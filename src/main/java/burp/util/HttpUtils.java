package burp.util;

import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.StringTokenizer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class HttpUtils {

    private HttpUtils() {}

    // Volatile tokens that change on every response and would otherwise make an
    // identical page look "changed" in the body diff. Stripped before hashing.
    private static final Pattern VT_JWT   = Pattern.compile("eyJ[A-Za-z0-9_-]+\\.eyJ[A-Za-z0-9_-]+(?:\\.[A-Za-z0-9_-]+)?");
    private static final Pattern VT_UUID  = Pattern.compile("\\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\\b");
    private static final Pattern VT_HEX   = Pattern.compile("\\b[0-9a-fA-F]{32,}\\b");
    private static final Pattern VT_TS    = Pattern.compile("\\d{4}-\\d{2}-\\d{2}[T ]\\d{2}:\\d{2}:\\d{2}(?:\\.\\d+)?(?:Z|[+-]\\d{2}:?\\d{2})?");
    private static final Pattern VT_JSON  = Pattern.compile(
            "(\"(?:_?csrf(?:_?token)?|csrftoken|authenticity_token|_token|nonce|requestverificationtoken)\"\\s*:\\s*\")[^\"]*(\")",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern VT_INPUT = Pattern.compile(
            "(name=\"(?:__RequestVerificationToken|_?csrf[^\"]*|authenticity_token)\"[^>]*\\bvalue=\")[^\"]*(\")",
            Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

    /**
     * Replace per-request volatile tokens (JWTs, UUIDs, long hex digests, ISO
     * timestamps, CSRF/nonce fields) with fixed placeholders so that two
     * semantically identical responses hash the same. Used only for the body
     * diff — it never changes what is shown to the user.
     */
    public static String normalizeForHash(String body) {
        if (body == null || body.isEmpty()) return "";
        String s = body;
        s = VT_JWT.matcher(s).replaceAll("#JWT#");
        s = VT_UUID.matcher(s).replaceAll("#UUID#");
        s = VT_HEX.matcher(s).replaceAll("#HEX#");
        s = VT_TS.matcher(s).replaceAll("#TS#");
        s = VT_JSON.matcher(s).replaceAll("$1#TOK#$2");
        s = VT_INPUT.matcher(s).replaceAll("$1#TOK#$2");
        return s;
    }

    private static final ThreadLocal<MessageDigest> MD5_TL = ThreadLocal.withInitial(() -> {
        try { return MessageDigest.getInstance("MD5"); } catch (Exception e) { throw new RuntimeException(e); }
    });

    private static final Pattern PATTERN_JWT = Pattern.compile(
            "eyJ[A-Za-z0-9-_=]+\\.eyJ[A-Za-z0-9-_=]+");
    private static final Pattern PATTERN_CSRF = Pattern.compile(
            "\"(?:csrf|_token|authenticity_token|csrftoken)\"\\s*:\\s*\"([^\"]{8,})\"", Pattern.CASE_INSENSITIVE);
    private static final Pattern PATTERN_EMAIL_FIELD = Pattern.compile(
            "\"(?:email|username)\"\\s*:\\s*\"[a-zA-Z0-9._%+@\\-]{5,}\"", Pattern.CASE_INSENSITIVE);
    private static final Pattern PATTERN_BEARER = Pattern.compile(
            "Bearer\\s+[A-Za-z0-9\\-._~+/]{20,}=*", Pattern.CASE_INSENSITIVE);
    private static final Pattern PATTERN_SECRET = Pattern.compile(
            "\"(?:api_?key|access_token|secret|client_secret)\"\\s*:\\s*\"([^\"]{8,})\"", Pattern.CASE_INSENSITIVE);
    private static final Pattern PATTERN_TITLE =
            Pattern.compile("<title>(.*?)</title>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL);

    // ── Body extraction ───────────────────────────────────────────────────────

    /** Extract response body as String once; pass this to the String-based helpers below. */
    public static String bodyStr(HttpRequestResponse rr) {
        try {
            if (rr == null || rr.response() == null) return "";
            String s = rr.response().bodyToString();
            return s != null ? s : "";
        } catch (Throwable t) { return ""; }
    }

    public static int statusOf(HttpRequestResponse rr) {
        try { return rr.response().statusCode(); } catch (Throwable t) { return -1; }
    }

    public static int bodyLen(HttpRequestResponse rr) {
        try { return rr.response().body() == null ? 0 : rr.response().body().length(); } catch (Throwable t) { return 0; }
    }

    // ── String-based analysis (preferred: call with pre-fetched bodyStr) ──────

    public static String bodyHash(String body) {
        try {
            if (body == null || body.isEmpty()) return "";
            String normalized = normalizeForHash(body);
            MessageDigest md = MD5_TL.get();
            md.reset();
            byte[] digest = md.digest(normalized.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(32);
            for (byte b : digest) sb.append(String.format("%02x", b & 0xff));
            return sb.toString();
        } catch (Throwable t) { return ""; }
    }

    public static String bodyHash(HttpRequestResponse rr) { return bodyHash(bodyStr(rr)); }

    public static String getTitle(String body) {
        if (body == null || body.isEmpty()) return "";
        try {
            Matcher m = PATTERN_TITLE.matcher(body);
            if (m.find()) return m.group(1).trim().replaceAll("\\s+", " ");
        } catch (Throwable t) {}
        return "";
    }

    public static String getTitle(HttpRequestResponse rr) { return getTitle(bodyStr(rr)); }

    public static int wordCount(String body) {
        if (body == null || body.isEmpty()) return 0;
        return new StringTokenizer(body).countTokens();
    }

    public static int wordCount(HttpRequestResponse rr) { return wordCount(bodyStr(rr)); }

    public static int lineCount(String body) {
        if (body == null || body.isEmpty()) return 0;
        int count = 1, len = body.length();
        for (int i = 0; i < len; i++) {
            char c = body.charAt(i);
            if (c == '\n') count++;
            else if (c == '\r') { count++; if (i + 1 < len && body.charAt(i + 1) == '\n') i++; }
        }
        return count;
    }

    public static int lineCount(HttpRequestResponse rr) { return lineCount(bodyStr(rr)); }

    public static void detectSensitiveData(String body, StringBuilder notes) {
        if (body == null || body.isEmpty()) return;
        try {
            if (PATTERN_JWT.matcher(body).find())         notes.append("SENSITIVE_DATA:JWT ");
            if (PATTERN_CSRF.matcher(body).find())        notes.append("SENSITIVE_DATA:CSRF_TOKEN ");
            if (PATTERN_EMAIL_FIELD.matcher(body).find()) notes.append("SENSITIVE_DATA:EMAIL ");
            if (PATTERN_BEARER.matcher(body).find())      notes.append("SENSITIVE_DATA:BEARER ");
            if (PATTERN_SECRET.matcher(body).find())      notes.append("SENSITIVE_DATA:SECRET ");
        } catch (Exception ignored) {}
    }

    public static void detectSensitiveData(HttpRequestResponse rr, StringBuilder notes) {
        try {
            if (rr == null || rr.response() == null) return;
            detectSensitiveData(bodyStr(rr), notes);
        } catch (Exception ignored) {}
    }

    // ── Header extraction ─────────────────────────────────────────────────────

    public static String getHeaderValue(HttpRequestResponse rr, String headerName) {
        try {
            if (rr == null || rr.response() == null) return "";
            String val = rr.response().headerValue(headerName);
            return val != null ? val : "";
        } catch (Throwable t) {
            return "";
        }
    }

    /** All response headers as a lower-cased name → value map (repeated headers joined with ", "). */
    public static Map<String, String> headerMap(HttpRequestResponse rr) {
        Map<String, String> m = new HashMap<>();
        try {
            if (rr == null || rr.response() == null) return m;
            for (HttpHeader h : rr.response().headers()) {
                if (h == null || h.name() == null) continue;
                String k = h.name().toLowerCase(Locale.ROOT);
                String v = h.value() == null ? "" : h.value();
                m.merge(k, v, (a, b) -> a + ", " + b);
            }
        } catch (Throwable t) { /* ignore */ }
        return m;
    }

    /** Vendor-agnostic cache analysis (Cloudflare, Vercel, Fastly, Akamai, Nginx, RFC 9211…). */
    public static CacheAnalyzer.Result cacheInfo(HttpRequestResponse rr) {
        return CacheAnalyzer.analyze(headerMap(rr));
    }

    public static String computeCacheStatus(HttpRequestResponse rr) {
        try { return cacheInfo(rr).label; } catch (Throwable t) { return "?"; }
    }
}
