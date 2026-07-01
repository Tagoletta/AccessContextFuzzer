package burp.core;

import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.payload.HeaderPayloadBuilder;
import burp.payload.PathPayloadBuilder;
import burp.payload.SelectionPayloadBuilder;
import burp.util.HttpUtils;

import javax.swing.*;
import java.awt.*;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.regex.Pattern;

public class ScanEngine {

    private final ExtensionContext ctx;
    private volatile List<Object[]> compiledCustomRules = new ArrayList<>();

    public ScanEngine(ExtensionContext ctx) {
        this.ctx = ctx;
    }

    // -------------------------------------------------------------------------
    // Scan configuration snapshot (must be created on the EDT)
    // -------------------------------------------------------------------------

    public static final class ScanConfig {
        public final String detectRules;
        public final int wafThreshold;
        public final boolean parallel;
        public final int parallelThreads;

        public ScanConfig(ExtensionContext ctx) {
            this.detectRules     = ctx.txtDetectRules.getText();
            this.wafThreshold    = (int) ctx.spinWafThreshold.getValue();
            this.parallel        = ctx.chkParallelMode.isSelected();
            this.parallelThreads = (int) ctx.spinParallelThreads.getValue();
        }
    }

    // -------------------------------------------------------------------------
    // Rule compilation
    // -------------------------------------------------------------------------

    private List<Object[]> buildCompiledRules(String rulesText) {
        List<Object[]> result = new ArrayList<>();
        if (rulesText == null || rulesText.isBlank()) return result;
        for (String line : rulesText.split("\n")) {
            line = line.trim();
            if (line.isEmpty() || line.startsWith("#")) continue;
            int eq = line.lastIndexOf('=');
            if (eq < 1) continue;
            String regex = line.substring(0, eq).trim();
            String label = line.substring(eq + 1).trim();
            if (label.isEmpty()) continue;
            try {
                result.add(new Object[]{Pattern.compile(regex, Pattern.CASE_INSENSITIVE | Pattern.DOTALL), label});
            } catch (Exception e) {
                ctx.api.logging().logToError("[ACF] Invalid custom rule regex '" + regex + "': " + e.getMessage());
            }
        }
        return result;
    }

    // -------------------------------------------------------------------------
    // Core fuzzing
    // -------------------------------------------------------------------------

    public FuzzResult executeSingle(HttpRequest request) {
        try {
            long t = System.nanoTime();
            HttpRequestResponse rr = ctx.api.http().sendRequest(request);
            long ms = (System.nanoTime() - t) / 1_000_000;
            return new FuzzResult(rr, ms);
        } catch (Exception e) {
            ctx.api.logging().logToError("[ACF] Request error: " + e.getMessage());
            return new FuzzResult(null, 0);
        }
    }

    private static String safeUrl(HttpRequest req) {
        try { return req.url(); } catch (Exception e) {
            try { return req.path(); } catch (Exception e2) { return "(unknown)"; }
        }
    }

    /** Carries the (possibly upgraded) result plus whether a MISS→HIT was confirmed. */
    private static final class WcdCheck {
        final FuzzResult fr;
        final boolean confirmed;
        WcdCheck(FuzzResult fr, boolean confirmed) { this.fr = fr; this.confirmed = confirmed; }
    }

    /**
     * WCD cache verification. When a response is a cacheable 200 MISS, resend the
     * SAME request a few times within the cache window to see whether X-Cache flips
     * to HIT. On confirmation, returns the HIT result (so the row shows the cached
     * response) and confirmed=true; otherwise returns the original result unchanged.
     */
    private WcdCheck verifyWcdMissToHit(FuzzResult fr, HttpRequest req) throws InterruptedException {
        if (fr == null || fr.rr == null) return new WcdCheck(fr, false);
        String xcV = HttpUtils.getHeaderValue(fr.rr, "X-Cache").toUpperCase(java.util.Locale.ROOT);
        String ccV = HttpUtils.getHeaderValue(fr.rr, "Cache-Control").toLowerCase(java.util.Locale.ROOT);
        boolean isMissAndCacheable = HttpUtils.statusOf(fr.rr) == 200
                && !ccV.contains("private") && !ccV.contains("no-store")
                && (ccV.contains("max-age") || ccV.contains("s-maxage"))
                && (xcV.isEmpty() || !xcV.contains("HIT"));
        if (!isMissAndCacheable) return new WcdCheck(fr, false);
        ctx.api.logging().logToOutput("[ACF-WCD] Cacheable MISS → verifying: " + req.path());
        for (int attempt = 1; attempt <= 4; attempt++) {
            Thread.sleep(250);
            FuzzResult fr2 = executeSingle(req);
            if (fr2 != null && fr2.rr != null) {
                String xc2 = HttpUtils.getHeaderValue(fr2.rr, "X-Cache").toUpperCase(java.util.Locale.ROOT);
                String age2 = HttpUtils.getHeaderValue(fr2.rr, "Age");
                ctx.api.logging().logToOutput("[ACF-WCD] attempt=" + attempt + " X-Cache=" + xc2
                        + (age2.isEmpty() ? "" : " Age=" + age2) + " path=" + req.path());
                if (xc2.contains("HIT")) {
                    ctx.api.logging().logToOutput("[ACF-WCD] ✅ CONFIRMED miss→hit: " + req.path());
                    return new WcdCheck(fr2, true);
                }
            }
        }
        ctx.api.logging().logToOutput("[ACF-WCD] not confirmed (stayed MISS): " + req.path());
        return new WcdCheck(fr, false);
    }

    public void startFuzzing(HttpRequestResponse baseRr, FuzzerEngine engine,
                              List<Variant> variants, int delayMs, ScanConfig config) {
        engine.lastRequest = baseRr;
        engine.isRunning.set(true);
        SwingUtilities.invokeLater(() -> {
            engine.btnStop.setEnabled(true);
            engine.btnRerun.setEnabled(false);
            engine.model.setRowCount(0);
            engine.progressBar.setValue(0);
            engine.progressBar.setForeground(new Color(76, 175, 80));
            if (engine.lblStatus != null) engine.lblStatus.setText("Scanning…");
            if (engine.filterActive.get()) {
                try {
                    javax.swing.table.TableRowSorter<?> sorter =
                            (javax.swing.table.TableRowSorter<?>) engine.table.getRowSorter();
                    sorter.setRowFilter(null);
                    engine.filterActive.set(false);
                    engine.btnFilter.setText("🔍 Show Only Interesting");
                    engine.btnFilter.setBackground(new Color(255, 193, 7));
                } catch (Exception ignored) {}
            }
        });

        // All UI values come from the pre-built ScanConfig (read on EDT by caller)
        compiledCustomRules = buildCompiledRules(config.detectRules);

        int processedCount = 0, interestingCount = 0, bypassCount = 0, finalBaseStatus = -1;
        int wcdCachedCount = 0, wcdPrivateCount = 0, wcdNoStoreCount = 0;
        int wcdVaryCookieCount = 0, wcdPotentialCount = 0, wcdConfirmedCount = 0;
        List<String> wcdPotentialVariants = new ArrayList<>();
        List<String> wcdConfirmedVariants = new ArrayList<>();

        try {
            HttpRequest baseReq = baseRr.request();
            engine.requestHistory.clear();

            HttpRequestResponse baseline = ctx.api.http().sendRequest(baseReq);
            int baseStatus    = HttpUtils.statusOf(baseline);
            int baseLen       = HttpUtils.bodyLen(baseline);
            String baseBodyStr = HttpUtils.bodyStr(baseline);
            int baseWords     = HttpUtils.wordCount(baseBodyStr);
            int baseLines     = HttpUtils.lineCount(baseBodyStr);
            String baseTitle  = HttpUtils.getTitle(baseBodyStr);
            String baseHash   = HttpUtils.bodyHash(baseBodyStr);
            engine.baselineStatus = baseStatus;
            finalBaseStatus = baseStatus;

            final String cacheBase = HttpUtils.computeCacheStatus(baseline);
            SwingUtilities.invokeLater(() -> engine.model.addRow(new Object[]{
                    0, "BASELINE", baseStatus, cacheBase, baseWords, baseLines, baseLen, baseTitle, 0, "Original"}));
            engine.requestHistory.put(0, baseline);

            int total = variants.size();
            SwingUtilities.invokeLater(() -> {
                engine.progressBar.setMaximum(total);
                engine.progressBar.setString("0 / " + total);
            });

            int wafThreshold    = config.wafThreshold;
            boolean isParallel  = config.parallel;
            int parallelThreads = isParallel ? Math.max(2, config.parallelThreads) : 1;
            ExecutorService batchPool = isParallel ? Executors.newFixedThreadPool(parallelThreads) : null;

            try {
                if (isParallel) {
                    List<Future<FuzzResult>> futures = new ArrayList<>(variants.size());
                    for (Variant v : variants) {
                        if (!engine.isRunning.get()) break;
                        final Variant fv = v;
                        futures.add(batchPool.submit(() -> executeSingle(fv.request)));
                    }

                    int consecutiveResets = 0;
                    long totalRttMs = 0; int rttCount = 0;

                    for (int i = 0; i < futures.size() && engine.isRunning.get(); i++) {
                        FuzzResult fr;
                        try { fr = futures.get(i).get(60, TimeUnit.SECONDS); }
                        catch (TimeoutException te) { futures.get(i).cancel(true); fr = new FuzzResult(null, 60000); }

                        // WCD cache verification: cacheable MISS → resend to confirm HIT
                        WcdCheck wcd = verifyWcdMissToHit(fr, variants.get(i).request);
                        fr = wcd.fr;
                        boolean wcdConfirmed = wcd.confirmed;
                        HttpRequestResponse rr = fr != null ? fr.rr : null;
                        long rttMs = fr != null ? fr.rttMs : 0;
                        engine.requestHistory.put(i + 1, rr);
                        if (rr != null) ctx.api.siteMap().add(rr);

                        String bodyStr = HttpUtils.bodyStr(rr);
                        int st    = HttpUtils.statusOf(rr);
                        int len   = HttpUtils.bodyLen(rr);
                        int words = HttpUtils.wordCount(bodyStr);
                        int lines = HttpUtils.lineCount(bodyStr);
                        String title = HttpUtils.getTitle(bodyStr);

                        totalRttMs += rttMs; rttCount++;
                        long avgMs = totalRttMs / rttCount;
                        int remaining = total - (i + 1);
                        long etaSec = remaining > 0 ? (remaining * avgMs) / 1000 : 0;
                        String etaStr = etaSec >= 60
                                ? String.format("~%d:%02d remaining", etaSec / 60, etaSec % 60)
                                : String.format("~%ds remaining", etaSec);

                        if (st == -1) consecutiveResets++; else consecutiveResets = 0;

                        String notes = computeNotes(rr, bodyStr, st, len, words, baseStatus, baseLen, baseWords, baseHash);
                        if (st == 429 || st == 503) notes = "RATE_LIMITED(" + st + ") " + notes;
                        if (wcdConfirmed) notes = "🎯 WCD CONFIRMED (MISS→HIT) " + notes;
                        final String finalNotes  = notes.trim();
                        final String finalCache  = HttpUtils.computeCacheStatus(rr);
                        final String varName     = variants.get(i).name;
                        final int rowNo          = i + 1;
                        final String finalEta    = etaStr;
                        final int finalRtt       = (int) rttMs;

                        String rrCC = HttpUtils.getHeaderValue(rr, "Cache-Control").toLowerCase(java.util.Locale.ROOT);
                        String rrXC = HttpUtils.getHeaderValue(rr, "X-Cache").toUpperCase(java.util.Locale.ROOT);
                        String rrVary = HttpUtils.getHeaderValue(rr, "Vary").toLowerCase(java.util.Locale.ROOT);
                        boolean rrHit = rrXC.contains("HIT");
                        if (rrHit) wcdCachedCount++;
                        if (rrCC.contains("private"))  wcdPrivateCount++;
                        if (rrCC.contains("no-store")) wcdNoStoreCount++;
                        if (rrHit && rrVary.contains("cookie")) wcdVaryCookieCount++;
                        if (rrHit && !rrCC.contains("private") && !rrCC.contains("no-store") && !rrVary.contains("cookie")) {
                            wcdPotentialCount++;
                            wcdPotentialVariants.add(varName);
                        }
                        if (wcdConfirmed) {
                            wcdConfirmedCount++; wcdConfirmedVariants.add(varName);
                            addWcdFinding("Scan (auto)", safeUrl(variants.get(i).request), String.valueOf(st),
                                    "—", "HIT", "🎯 Cacheable MISS→HIT — run no-auth verify to confirm WCD", rr);
                        }

                        SwingUtilities.invokeLater(() -> {
                            engine.model.addRow(new Object[]{rowNo, varName, st, finalCache, words, lines, len, title, finalRtt, finalNotes});
                            engine.progressBar.setValue(rowNo);
                            engine.progressBar.setString(rowNo + " / " + total + " ⚡ parallel (" + finalEta + ")");
                        });

                        processedCount++;
                        if (isInterestingNote(finalNotes))           interestingCount++;
                        if (finalNotes.contains("POTENTIAL BYPASS") || wcdConfirmed) bypassCount++;

                        if (consecutiveResets >= wafThreshold) {
                            engine.isRunning.set(false);
                            final int rc = consecutiveResets;
                            SwingUtilities.invokeLater(() -> showWafDialog(engine, rc));
                            break;
                        }
                    }
                } else {
                    int idx = 1, consecutiveResets = 0, currentDelay = delayMs;
                    long totalRttMs = 0; int rttCount = 0;

                    for (Variant v : variants) {
                        if (!engine.isRunning.get()) break;
                        Thread.sleep(currentDelay);
                        if (!engine.isRunning.get()) break;

                        final int rowNo = idx++;
                        FuzzResult fr = executeSingle(v.request);
                        // WCD cache verification: cacheable MISS → resend to confirm HIT
                        WcdCheck wcd = verifyWcdMissToHit(fr, v.request);
                        fr = wcd.fr;
                        boolean wcdConfirmed = wcd.confirmed;
                        HttpRequestResponse rr = fr.rr;
                        engine.requestHistory.put(rowNo, rr);
                        if (rr != null) ctx.api.siteMap().add(rr);

                        String bodyStr = HttpUtils.bodyStr(rr);
                        int st    = HttpUtils.statusOf(rr);
                        int len   = HttpUtils.bodyLen(rr);
                        int words = HttpUtils.wordCount(bodyStr);
                        int lines = HttpUtils.lineCount(bodyStr);
                        String title = HttpUtils.getTitle(bodyStr);

                        totalRttMs += fr.rttMs + currentDelay; rttCount++;
                        long avgMs = totalRttMs / rttCount;
                        int remaining = total - rowNo;
                        long etaSec = remaining > 0 ? (remaining * avgMs) / 1000 : 0;
                        String etaStr = etaSec >= 60
                                ? String.format("~%d:%02d remaining", etaSec / 60, etaSec % 60)
                                : String.format("~%ds remaining", etaSec);

                        if (st == -1) consecutiveResets++; else consecutiveResets = 0;

                        if (st == 429 || st == 503) {
                            currentDelay = Math.min(currentDelay < 100 ? 500 : currentDelay * 2, 30000);
                            final int displayDelay = currentDelay;
                            SwingUtilities.invokeLater(() ->
                                    engine.progressBar.setString("Rate limited! Delay → " + displayDelay + "ms"));
                            Thread.sleep(currentDelay);
                        }

                        String notes = computeNotes(rr, bodyStr, st, len, words, baseStatus, baseLen, baseWords, baseHash);
                        if (st == 429 || st == 503) notes = "RATE_LIMITED(" + st + ") " + notes;
                        if (wcdConfirmed) notes = "🎯 WCD CONFIRMED (MISS→HIT) " + notes;
                        final String finalNotes  = notes.trim();
                        final String finalCache  = HttpUtils.computeCacheStatus(rr);
                        final String finalVName  = v.name;
                        final String finalEta    = etaStr;
                        final int finalRtt       = (int) fr.rttMs;

                        String rrCC = HttpUtils.getHeaderValue(rr, "Cache-Control").toLowerCase(java.util.Locale.ROOT);
                        String rrXC = HttpUtils.getHeaderValue(rr, "X-Cache").toUpperCase(java.util.Locale.ROOT);
                        String rrVary = HttpUtils.getHeaderValue(rr, "Vary").toLowerCase(java.util.Locale.ROOT);
                        boolean rrHit = rrXC.contains("HIT");
                        if (rrHit) wcdCachedCount++;
                        if (rrCC.contains("private"))  wcdPrivateCount++;
                        if (rrCC.contains("no-store")) wcdNoStoreCount++;
                        if (rrHit && rrVary.contains("cookie")) wcdVaryCookieCount++;
                        if (rrHit && !rrCC.contains("private") && !rrCC.contains("no-store") && !rrVary.contains("cookie")) {
                            wcdPotentialCount++;
                            wcdPotentialVariants.add(finalVName);
                        }
                        if (wcdConfirmed) {
                            wcdConfirmedCount++; wcdConfirmedVariants.add(finalVName);
                            addWcdFinding("Scan (auto)", safeUrl(v.request), String.valueOf(st),
                                    "—", "HIT", "🎯 Cacheable MISS→HIT — run no-auth verify to confirm WCD", rr);
                        }

                        SwingUtilities.invokeLater(() -> {
                            engine.model.addRow(new Object[]{rowNo, finalVName, st, finalCache, words, lines, len, title, finalRtt, finalNotes});
                            engine.progressBar.setValue(rowNo);
                            engine.progressBar.setString(rowNo + " / " + total + " (" + finalEta + ")");
                        });

                        processedCount++;
                        if (isInterestingNote(finalNotes))           interestingCount++;
                        if (finalNotes.contains("POTENTIAL BYPASS") || wcdConfirmed) bypassCount++;

                        if (consecutiveResets >= wafThreshold) {
                            engine.isRunning.set(false);
                            final int rc = consecutiveResets;
                            SwingUtilities.invokeLater(() -> showWafDialog(engine, rc));
                            break;
                        }

                        if (rowNo % 50 == 0 && engine.isRunning.get()) {
                            try {
                                HttpRequestResponse sessionCheck = ctx.api.http().sendRequest(baseReq);
                                int sessionStatus = HttpUtils.statusOf(sessionCheck);
                                if (sessionStatus != baseStatus && sessionStatus != -1) {
                                    final int oldSt = baseStatus, newSt = sessionStatus;
                                    SwingUtilities.invokeLater(() -> {
                                        engine.model.addRow(new Object[]{rowNo, "SESSION CHECK",
                                                newSt, "?", 0, 0, 0, "", 0,
                                                "⚠️ SESSION_DRIFT (" + oldSt + " → " + newSt + ")"});
                                        engine.progressBar.setString("Session drift detected!");
                                        engine.progressBar.setForeground(new Color(255, 165, 0));
                                    });
                                    final int[] choiceBox = {JOptionPane.YES_OPTION};
                                    try {
                                        SwingUtilities.invokeAndWait(() ->
                                            choiceBox[0] = JOptionPane.showConfirmDialog(null,
                                                "Session Drift Detected!\n\nBaseline was " + oldSt + " but now returns " + newSt + ".\n"
                                                + "Your session may have expired or been invalidated.\n\nContinue scanning?",
                                                "Session Health Warning", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE));
                                    } catch (Exception ignored) {}
                                    if (choiceBox[0] != JOptionPane.YES_OPTION) { engine.isRunning.set(false); break; }
                                }
                            } catch (Exception ex) {
                                ctx.api.logging().logToError("[ACF] Session check error: " + ex.getMessage());
                            }
                        }
                    }
                }
            } finally {
                if (batchPool != null) batchPool.shutdownNow();
            }

            final int pc = processedCount, ic = interestingCount, bc = bypassCount, wc = wcdConfirmedCount;
            SwingUtilities.invokeLater(() -> {
                engine.progressBar.setString("Done — " + pc + " sent");
                engine.lblStatus.setText(String.format(
                        "✅ Done — %d sent | %d findings | %d 🎯 bypass | %d 🎯 WCD cacheable | Re-run available",
                        pc, ic, bc, wc));
            });

            String targetUrl;
            try { targetUrl = baseRr.request().url().replaceAll("\\?.*", ""); } catch (Exception e) { targetUrl = "Unknown"; }
            appendScanHistory(engine.engineType, targetUrl, processedCount, interestingCount, bypassCount, finalBaseStatus);

            if ("Path".equals(engine.engineType) && (wcdCachedCount > 0 || wcdPotentialCount > 0 || wcdConfirmedCount > 0)) {
                final int wcc = wcdCachedCount, wpc = wcdPrivateCount, wnc = wcdNoStoreCount;
                final int wvc = wcdVaryCookieCount, wpcc = wcdPotentialCount, wconf = wcdConfirmedCount;
                final List<String> wpv = new ArrayList<>(wcdPotentialVariants);
                final List<String> wcv = new ArrayList<>(wcdConfirmedVariants);
                final String tu = targetUrl;
                SwingUtilities.invokeLater(() -> showWcdSummary(wcc, wpc, wnc, wvc, wpcc, wpv, wconf, wcv, tu));
            }

            // flashTab must run on EDT — it creates a Swing Timer; index reads must be on EDT too
            SwingUtilities.invokeLater(() -> {
                int idx = ctx.mainTabs.indexOfComponent(engine.mainPanel);
                if (idx >= 0) flashTab(idx, ctx.mainTabs.getTitleAt(idx));
            });

        } catch (Exception ex) {
            ctx.api.logging().logToError("[ACF] Fuzzing error in " + engine.engineType + ": " + ex.getMessage());
        } finally {
            engine.isRunning.set(false);
            SwingUtilities.invokeLater(() -> {
                engine.btnStop.setEnabled(false);
                engine.btnRerun.setEnabled(true);
            });
        }
    }

    // -------------------------------------------------------------------------
    // Notes & analysis
    // -------------------------------------------------------------------------

    public String computeNotes(HttpRequestResponse rr, String bodyStr, int st, int len, int words,
                                int baseStatus, int baseLen, int baseWords, String baseHash) {
        StringBuilder notes = new StringBuilder();

        if (st != baseStatus) {
            if (st >= 200 && st < 300
                    && (baseStatus == 401 || baseStatus == 403 || baseStatus == 404 || baseStatus == 405))
                notes.append("🎯 POTENTIAL BYPASS ");
            else if ((st == 301 || st == 302 || st == 307 || st == 308)
                    && (baseStatus == 401 || baseStatus == 403))
                notes.append("🔀 REDIRECT BYPASS? ");
            else if (baseStatus == 404 && st > 0 && st != 404)
                notes.append("🔍 PATH_CONFUSION ");
            else
                notes.append("STATUS_CHANGE ");
        }

        String currentHash = HttpUtils.bodyHash(bodyStr);
        boolean bodyDiffers = !currentHash.isEmpty() && !baseHash.isEmpty() && !currentHash.equals(baseHash);
        if (bodyDiffers && st == baseStatus) {
            if (st >= 200 && st < 300) notes.append("⚠️ BODY_BYPASS? ");
            else                        notes.append("BODY_DIFF ");
        }

        if (words != baseWords)           notes.append("WORD_DELTA ");
        if (Math.abs(len - baseLen) > 50) notes.append("LEN_DELTA ");

        String xCache        = HttpUtils.getHeaderValue(rr, "X-Cache");
        String cacheControl  = HttpUtils.getHeaderValue(rr, "Cache-Control");
        String vary          = HttpUtils.getHeaderValue(rr, "Vary");
        String age           = HttpUtils.getHeaderValue(rr, "Age");

        boolean isCacheHit   = xCache.toUpperCase(java.util.Locale.ROOT).contains("HIT");
        boolean isPrivate    = cacheControl.toLowerCase(java.util.Locale.ROOT).contains("private");
        boolean isNoStore    = cacheControl.toLowerCase(java.util.Locale.ROOT).contains("no-store");
        boolean cookieInVary = vary.toLowerCase(java.util.Locale.ROOT).contains("cookie");

        if (isCacheHit && !isPrivate && !isNoStore && !cookieInVary) notes.append("🎯 CACHE_HIT_CACHEABLE ");
        if (isCacheHit && cookieInVary)  notes.append("HIT_VARY_COOKIE ");
        if (!xCache.isEmpty() && !isCacheHit) notes.append("X-Cache:").append(xCache).append(" ");
        if (isPrivate)  notes.append("CC:PRIVATE ");
        if (isNoStore)  notes.append("CC:NO-STORE ");
        if (cacheControl.contains("s-maxage")) notes.append("CC:S-MAXAGE ");
        if (cacheControl.contains("max-age") && !isPrivate && !isNoStore) notes.append("CC:MAX-AGE ");
        if (!age.isEmpty()) notes.append("Age:").append(age).append(" ");

        HttpUtils.detectSensitiveData(bodyStr, notes);
        applyCustomRules(bodyStr, notes);

        return notes.toString().trim();
    }

    /**
     * A note is "interesting" only when it flags a real finding — not baseline
     * noise like STATUS_CHANGE / WORD_DELTA / LEN_DELTA / X-Cache:miss / CC:* .
     */
    public static boolean isInterestingNote(String notes) {
        if (notes == null || notes.isEmpty()) return false;
        return notes.contains("POTENTIAL BYPASS")
            || notes.contains("REDIRECT BYPASS")
            || notes.contains("PATH_CONFUSION")
            || notes.contains("BODY_BYPASS")
            || notes.contains("WCD CONFIRMED")
            || notes.contains("CACHE_HIT_CACHEABLE")
            || notes.contains("HIT_VARY_COOKIE")
            || notes.contains("SENSITIVE_DATA")
            || notes.contains("CUSTOM:");
    }

    /** Append a row to the WCD Findings tab (EDT-safe) and store the proving response. */
    public void addWcdFinding(String source, String url, String authStatus, String noAuthStatus,
                              String xCache, String verdict, HttpRequestResponse proof) {
        int id = ctx.wcdFindingsSeq.incrementAndGet();
        if (proof != null) ctx.wcdFindingsHistory.put(id, proof);
        String ts = LocalDateTime.now().format(ExtensionContext.TS_FMT);
        SwingUtilities.invokeLater(() -> {
            if (ctx.wcdFindingsModel != null)
                ctx.wcdFindingsModel.addRow(new Object[]{id, source, url, authStatus, noAuthStatus, xCache, verdict, ts});
        });
    }

    private void applyCustomRules(String body, StringBuilder notes) {
        if (compiledCustomRules.isEmpty() || body == null || body.isEmpty()) return;
        for (Object[] rule : compiledCustomRules) {
            if (((Pattern) rule[0]).matcher(body).find())
                notes.append("CUSTOM:").append(rule[1]).append(" ");
        }
    }

    // -------------------------------------------------------------------------
    // WCD verification
    // -------------------------------------------------------------------------

    /**
     * True WCD confirmation. Works on whichever message is open (the request half
     * of the open request/response is used). Two phases:
     *   1) Warm — replay WITH the current auth so the sensitive response is stored
     *      in the cache (resend until X-Cache: HIT to be sure it is cacheable).
     *   2) Replay — resend WITHOUT cookies/auth. If it is served from cache (HIT)
     *      and returns the same authenticated/sensitive body, it is a confirmed WCD.
     * The outcome is always recorded in the WCD Findings tab.
     */
    public void verifyWcdNoAuth(HttpRequestResponse originalRr) {
        ctx.taskExecutor.submit(() -> {
            try {
                final HttpRequest authReq = originalRr.request();
                final String url = safeUrl(authReq);

                // ── Phase 1: warm the cache with auth ───────────────────────────
                HttpRequestResponse warm = ctx.api.http().sendRequest(authReq);
                int authStatus = HttpUtils.statusOf(warm);
                String authBody = HttpUtils.bodyStr(warm);
                String authHash = HttpUtils.bodyHash(authBody);
                String cc   = HttpUtils.getHeaderValue(warm, "Cache-Control");
                String warmXc = HttpUtils.getHeaderValue(warm, "X-Cache").toUpperCase(java.util.Locale.ROOT);
                boolean isPrivate = cc.toLowerCase(java.util.Locale.ROOT).contains("private");
                boolean isNoStore = cc.toLowerCase(java.util.Locale.ROOT).contains("no-store");
                ctx.api.logging().logToOutput("[ACF-WCD-VERIFY] warm(auth) status=" + authStatus
                        + " X-Cache=" + (warmXc.isEmpty() ? "(none)" : warmXc) + " url=" + url);
                for (int i = 0; i < 3 && !warmXc.contains("HIT") && !isPrivate && !isNoStore; i++) {
                    Thread.sleep(250);
                    HttpRequestResponse w2 = ctx.api.http().sendRequest(authReq);
                    warmXc = HttpUtils.getHeaderValue(w2, "X-Cache").toUpperCase(java.util.Locale.ROOT);
                    if (warmXc.contains("HIT")) { warm = w2; authBody = HttpUtils.bodyStr(w2); authHash = HttpUtils.bodyHash(authBody); }
                }

                // ── Phase 2: replay without auth ────────────────────────────────
                HttpRequest noAuthReq = authReq
                        .withRemovedHeader("Cookie")
                        .withRemovedHeader("Authorization")
                        .withRemovedHeader("X-Auth-Token")
                        .withRemovedHeader("X-API-Key");
                HttpRequestResponse res = ctx.api.http().sendRequest(noAuthReq);
                int st        = HttpUtils.statusOf(res);
                String xCache = HttpUtils.getHeaderValue(res, "X-Cache");
                String vary   = HttpUtils.getHeaderValue(res, "Vary");
                String noAuthBody = HttpUtils.bodyStr(res);
                String noAuthHash = HttpUtils.bodyHash(noAuthBody);
                boolean isHit      = xCache.toUpperCase(java.util.Locale.ROOT).contains("HIT");
                boolean varyCookie = vary.toLowerCase(java.util.Locale.ROOT).contains("cookie");
                boolean sameAsAuth = !authHash.isEmpty() && authHash.equals(noAuthHash);
                StringBuilder sens = new StringBuilder();
                HttpUtils.detectSensitiveData(noAuthBody, sens);
                boolean leaksSensitive = sens.length() > 0 || sameAsAuth;
                ctx.api.logging().logToOutput("[ACF-WCD-VERIFY] no-auth status=" + st
                        + " X-Cache=" + (xCache.isEmpty() ? "(none)" : xCache)
                        + " sameBodyAsAuth=" + sameAsAuth + " sensitive=" + (sens.length() > 0) + " url=" + url);

                // ── Verdict ─────────────────────────────────────────────────────
                String shortVerdict, longVerdict; int msgType;
                if (isPrivate) {
                    shortVerdict = "🚫 Cache-Control: private";
                    longVerdict  = "🚫 Cache-Control: private — WCD not possible, browser cache only.";
                    msgType = JOptionPane.INFORMATION_MESSAGE;
                } else if (isNoStore) {
                    shortVerdict = "🚫 Cache-Control: no-store";
                    longVerdict  = "🚫 Cache-Control: no-store — WCD not possible, no caching.";
                    msgType = JOptionPane.INFORMATION_MESSAGE;
                } else if (isHit && leaksSensitive && !varyCookie) {
                    shortVerdict = "✅ CONFIRMED WCD";
                    longVerdict  = "✅ CONFIRMED WCD\nThe no-auth request was served from cache (X-Cache: HIT) and returned "
                            + (sameAsAuth ? "the SAME body as the authenticated response" : "sensitive data")
                            + ".\nAn unauthenticated attacker can retrieve this cached authenticated content.";
                    msgType = JOptionPane.WARNING_MESSAGE;
                } else if (isHit && varyCookie) {
                    shortVerdict = "⚠️ HIT but Vary: Cookie";
                    longVerdict  = "⚠️ Cache HIT but Vary: Cookie is set\nThe cache keys on the cookie (per-user). WCD risk is low.";
                    msgType = JOptionPane.INFORMATION_MESSAGE;
                } else if (isHit) {
                    shortVerdict = "⚠️ HIT but content differs";
                    longVerdict  = "⚠️ Served from cache (HIT) but the no-auth body differs from the authenticated one "
                            + "(likely a public/login page). Not a confirmed leak.";
                    msgType = JOptionPane.INFORMATION_MESSAGE;
                } else {
                    shortVerdict = "❌ Not cached without auth";
                    longVerdict  = "❌ The no-auth replay was NOT served from cache (status " + st + ", X-Cache: "
                            + (xCache.isEmpty() ? "none" : xCache) + ").\nThis URL is not exploitable via WCD as tested.";
                    msgType = JOptionPane.INFORMATION_MESSAGE;
                }

                addWcdFinding("Manual verify", url, String.valueOf(authStatus), String.valueOf(st),
                        xCache.isEmpty() ? "(none)" : xCache, shortVerdict, res);

                StringBuilder msg = new StringBuilder();
                msg.append("URL: ").append(url).append("\n");
                msg.append("Warm (with auth) status: ").append(authStatus)
                        .append("  X-Cache: ").append(warmXc.isEmpty() ? "(none)" : warmXc).append("\n");
                msg.append("Replay (no auth) status: ").append(st)
                        .append("  X-Cache: ").append(xCache.isEmpty() ? "(none)" : xCache).append("\n");
                msg.append("Cache-Control: ").append(cc.isEmpty() ? "(none)" : cc).append("\n");
                msg.append("Vary: ").append(vary.isEmpty() ? "(none)" : vary).append("\n");
                msg.append("No-auth body == auth body: ").append(sameAsAuth ? "yes" : "no");
                if (sens.length() > 0) msg.append("   Sensitive: ").append(sens.toString().trim());
                msg.append("\n\nResult: ").append(longVerdict);
                msg.append("\n\n→ Added to the 'WCD Findings' tab (double-click the row to view the no-auth response).");
                final String finalMsg = msg.toString();
                final int finalType = msgType;
                SwingUtilities.invokeLater(() ->
                        JOptionPane.showMessageDialog(ctx.mainTabs, finalMsg, "WCD Verification", finalType));
            } catch (Exception ex) {
                ctx.api.logging().logToError("[ACF] WCD verify error: " + ex.getMessage());
            }
        });
    }

    private void showWcdSummary(int cached, int priv, int noStore, int varyCookie,
                                int potential, List<String> variants,
                                int confirmed, List<String> confirmedVariants, String targetUrl) {
        if (cached == 0 && potential == 0 && confirmed == 0) return;
        StringBuilder msg = new StringBuilder();
        msg.append("WCD SCAN SUMMARY\n");
        msg.append("Target: ").append(targetUrl).append("\n");
        msg.append("─".repeat(48)).append("\n");
        if (confirmed > 0) {
            msg.append("🎯 Cacheable MISS→HIT (added to WCD Findings tab):\n");
            for (String v : confirmedVariants) msg.append("  🎯 ").append(v).append("\n");
            msg.append("─".repeat(48)).append("\n");
        }
        msg.append(String.format("Cached Responses (X-Cache: HIT):     %d%n", cached));
        msg.append(String.format("Confirmed MISS→HIT (resend):          %d%n", confirmed));
        msg.append(String.format("Cache-Control: private:               %d  ← WCD not possible%n", priv));
        msg.append(String.format("Cache-Control: no-store:              %d  ← WCD not possible%n", noStore));
        msg.append(String.format("Vary: Cookie set:                     %d  ← WCD risk low%n", varyCookie));
        msg.append(String.format("Potential WCD (HIT, no Vary:Cookie):  %d%n", potential));
        msg.append("\nNext step: right-click the cacheable request → 'Verify WCD (warm + no-auth replay)'\n"
                + "to confirm an unauthenticated attacker gets the cached content. See the 'WCD Findings' tab.");
        int msgType = (confirmed > 0 || potential > 0) ? JOptionPane.WARNING_MESSAGE : JOptionPane.INFORMATION_MESSAGE;
        JOptionPane.showMessageDialog(ctx.mainTabs, msg.toString(), "WCD Scan Summary", msgType);
    }

    // -------------------------------------------------------------------------
    // Engine actions
    // -------------------------------------------------------------------------

    public void stopEngine(FuzzerEngine engine) {
        engine.isRunning.set(false);
        engine.progressBar.setString("Aborted!");
        engine.btnRerun.setEnabled(true);
    }

    public void rerunFuzzing(FuzzerEngine engine) {
        if (engine.isRunning.get()) return;
        if (engine.lastRequest == null) {
            JOptionPane.showMessageDialog(null, "No previous request found. Right-click a request first.",
                    "Re-run Error", JOptionPane.WARNING_MESSAGE);
            return;
        }
        HttpRequestResponse rr = engine.lastRequest;
        List<Variant> variants;
        int delay = (int) ctx.spinDelay.getValue();
        switch (engine.engineType) {
            case "Header":
                variants = new HeaderPayloadBuilder(ctx).build(rr.request());
                break;
            case "Path":
                variants = new PathPayloadBuilder(ctx).build(rr.request());
                break;
            case "Selection":
                if (engine.lastSelectionRange == null) {
                    JOptionPane.showMessageDialog(null, "No selection range stored. Select text and fuzz first.",
                            "Re-run Error", JOptionPane.WARNING_MESSAGE);
                    return;
                }
                variants = new SelectionPayloadBuilder(ctx).build(rr.request(),
                        engine.lastSelectionRange[0], engine.lastSelectionRange[1]);
                break;
            default: return;
        }
        // rerunFuzzing is called from EDT (button listener) — safe to read UI here
        ScanConfig cfg = new ScanConfig(ctx);
        ctx.taskExecutor.submit(() -> startFuzzing(rr, engine, variants, delay, cfg));
    }

    public void showPayloadPreview(FuzzerEngine engine) {
        List<Variant> variants;
        try {
            switch (engine.engineType) {
                case "Header":
                    if (engine.lastRequest == null) { showPreviewNoRequest(); return; }
                    variants = new HeaderPayloadBuilder(ctx).build(engine.lastRequest.request());
                    break;
                case "Path":
                    if (engine.lastRequest == null) { showPreviewNoRequest(); return; }
                    variants = new PathPayloadBuilder(ctx).build(engine.lastRequest.request());
                    break;
                case "Selection":
                    if (engine.lastRequest == null || engine.lastSelectionRange == null) {
                        showPreviewNoRequest(); return;
                    }
                    variants = new SelectionPayloadBuilder(ctx).build(engine.lastRequest.request(),
                            engine.lastSelectionRange[0], engine.lastSelectionRange[1]);
                    break;
                default: return;
            }
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(null, "Could not generate preview: " + ex.getMessage(),
                    "Preview Error", JOptionPane.WARNING_MESSAGE);
            return;
        }

        java.util.Map<String, Integer> counts = new java.util.LinkedHashMap<>();
        StringBuilder details = new StringBuilder();
        for (Variant v : variants) {
            String cat = v.name.contains(":") ? v.name.substring(0, v.name.indexOf(':')) : v.name;
            counts.merge(cat, 1, Integer::sum);
            details.append(v.name).append('\n');
        }
        StringBuilder sb = new StringBuilder();
        sb.append("Engine     : ").append(engine.engineType).append('\n');
        sb.append("Total      : ").append(variants.size()).append(" payloads\n\n");
        sb.append("--- Category Summary ---\n");
        counts.forEach((cat, cnt) -> sb.append(String.format("  %-24s %d\n", cat, cnt)));
        sb.append("\n--- Full Payload List ---\n");
        sb.append(details);

        JTextArea ta = new JTextArea(sb.toString());
        ta.setEditable(false);
        ta.setFont(new java.awt.Font("Monospaced", java.awt.Font.PLAIN, 11));
        ta.setCaretPosition(0);
        Frame burpFrame = (Frame) SwingUtilities.getAncestorOfClass(Frame.class, ctx.mainTabs);
        JDialog dialog = new JDialog(burpFrame,
                "Payload Preview — " + engine.engineType + " (" + variants.size() + " total)", false);
        dialog.setSize(640, 720);
        dialog.setLocationRelativeTo(burpFrame);
        dialog.add(new JScrollPane(ta));
        dialog.setVisible(true);
    }

    private void showPreviewNoRequest() {
        JOptionPane.showMessageDialog(null,
                "No target request available yet.\nRight-click a request and run a scan first.",
                "Payload Preview", JOptionPane.INFORMATION_MESSAGE);
    }

    // -------------------------------------------------------------------------
    // OPSEC / IP check
    // -------------------------------------------------------------------------

    public void checkExternalIp(JLabel targetLabel) {
        targetLabel.setText(" Status: Checking...");
        targetLabel.setForeground(java.awt.Color.BLUE);
        ctx.taskExecutor.submit(() -> {
            try {
                HttpService service = HttpService.httpService("api.ipify.org", 443, true);
                HttpRequest req = HttpRequest.httpRequest(service,
                        "GET / HTTP/1.1\r\nHost: api.ipify.org\r\nConnection: close\r\nAccept: */*\r\nUser-Agent: AccessContextFuzzer/" + ExtensionContext.VERSION + "\r\n\r\n");
                HttpRequestResponse res = ctx.api.http().sendRequest(req);
                if (res.response() != null && res.response().statusCode() == 200) {
                    String ip = res.response().bodyToString().trim();
                    SwingUtilities.invokeLater(() -> {
                        targetLabel.setText(" Current IP: " + ip + " (Verified)");
                        targetLabel.setForeground(new java.awt.Color(0, 153, 0));
                    });
                } else {
                    SwingUtilities.invokeLater(() -> {
                        targetLabel.setText(" Status: Failed.");
                        targetLabel.setForeground(java.awt.Color.RED);
                    });
                }
            } catch (Exception ex) {
                ctx.api.logging().logToError("[ACF] IP check error: " + ex.getMessage());
                SwingUtilities.invokeLater(() -> {
                    targetLabel.setText(" Status: Error!");
                    targetLabel.setForeground(java.awt.Color.RED);
                });
            }
        });
    }

    public boolean confirmOpsec(JLabel ipLabel) {
        if (ipLabel.getText().contains("Not checked")) {
            int r = JOptionPane.showConfirmDialog(null,
                    "Your external IP hasn't been verified!\nContinue without OPSEC check?",
                    "OPSEC Warning", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            return r == JOptionPane.YES_OPTION;
        }
        return true;
    }

    // -------------------------------------------------------------------------
    // Scan history
    // -------------------------------------------------------------------------

    public void appendScanHistory(String engineType, String targetUrl,
                                   int total, int interesting, int bypasses, int baseStatus) {
        String ts = LocalDateTime.now().format(ExtensionContext.TS_FMT);
        SwingUtilities.invokeLater(() -> {
            int rowNum = ctx.historyModel.getRowCount() + 1;
            ctx.historyModel.addRow(new Object[]{rowNum, engineType, targetUrl, ts, total, interesting, bypasses, baseStatus});
        });
    }

    // -------------------------------------------------------------------------
    // UI helpers
    // -------------------------------------------------------------------------

    public void flashTab(int tabIndex, String originalTitle) {
        int[] count = {0};
        Timer timer = new Timer(400, null);
        timer.addActionListener(e -> {
            if (count[0] >= 6) {
                ctx.mainTabs.setTitleAt(tabIndex, originalTitle);
                ctx.mainTabs.setForegroundAt(tabIndex, null);
                ((Timer) e.getSource()).stop();
                return;
            }
            if (count[0] % 2 == 0) {
                ctx.mainTabs.setTitleAt(tabIndex, "⚡ " + originalTitle);
                ctx.mainTabs.setForegroundAt(tabIndex, new java.awt.Color(255, 120, 0));
            } else {
                ctx.mainTabs.setTitleAt(tabIndex, originalTitle);
                ctx.mainTabs.setForegroundAt(tabIndex, null);
            }
            count[0]++;
        });
        timer.start();
    }

    public void focusSuiteTab() {
        SwingUtilities.invokeLater(() -> {
            java.awt.Container parent = ctx.mainTabs.getParent();
            while (parent != null) {
                if (parent instanceof JTabbedPane) {
                    JTabbedPane burpTabs = (JTabbedPane) parent;
                    for (int i = 0; i < burpTabs.getTabCount(); i++) {
                        if (burpTabs.getComponentAt(i) == ctx.mainTabs ||
                                SwingUtilities.isDescendingFrom(ctx.mainTabs, burpTabs.getComponentAt(i))) {
                            burpTabs.setSelectedIndex(i);
                            return;
                        }
                    }
                }
                parent = parent.getParent();
            }
        });
    }

    private void showWafDialog(FuzzerEngine engine, int resetCount) {
        engine.progressBar.setString("WAF BLOCKED! Scan stopped.");
        engine.progressBar.setForeground(new java.awt.Color(255, 60, 60));
        JOptionPane.showMessageDialog(null,
                "WAF Blocking Detected!\n\n"
                + resetCount + " consecutive connection resets (status -1) detected.\n"
                + "The target's WAF/firewall is likely blocking your requests.\n\n"
                + "Suggestions:\n"
                + "  • Increase the delay (or switch to sequential mode)\n"
                + "  • Use a different IP / proxy\n"
                + "  • Reduce the number of enabled payload categories\n"
                + "  • Raise WAF Block Threshold in ⚙ Settings",
                "WAF Blocking Detected", JOptionPane.WARNING_MESSAGE);
    }
}
