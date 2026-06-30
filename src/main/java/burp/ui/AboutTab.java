package burp.ui;

import burp.core.ExtensionContext;
import burp.util.ThemeColors;

import javax.swing.*;
import javax.swing.event.HyperlinkEvent;
import java.awt.*;
import java.awt.Desktop;
import java.awt.event.HierarchyEvent;

public class AboutTab {

    private AboutTab() {}

    public static JPanel build(ExtensionContext ctx) {
        JPanel panel = new JPanel(new BorderLayout());

        JEditorPane editor = new JEditorPane("text/html", buildHtml(ExtensionContext.VERSION));
        editor.setEditable(false);
        editor.putClientProperty(JEditorPane.HONOR_DISPLAY_PROPERTIES, Boolean.TRUE);
        editor.setFont(new Font("SansSerif", Font.PLAIN, 13));
        editor.setOpaque(false);

        // Open links in the system browser
        editor.addHyperlinkListener(e -> {
            if (e.getEventType() == HyperlinkEvent.EventType.ACTIVATED && e.getURL() != null) {
                try { Desktop.getDesktop().browse(e.getURL().toURI()); } catch (Exception ignored) {}
            }
        });

        // Rebuild HTML whenever the tab becomes visible so theme changes are picked up
        editor.addHierarchyListener(e -> {
            if ((e.getChangeFlags() & HierarchyEvent.SHOWING_CHANGED) != 0 && editor.isShowing()) {
                editor.setText(buildHtml(ExtensionContext.VERSION));
                editor.setCaretPosition(0);
            }
        });

        JScrollPane scroll = new JScrollPane(editor);
        scroll.setBorder(BorderFactory.createEmptyBorder());
        scroll.getVerticalScrollBar().setUnitIncrement(16);
        panel.add(scroll, BorderLayout.CENTER);

        SwingUtilities.invokeLater(() -> editor.setCaretPosition(0));
        return panel;
    }

    private static String buildHtml(String version) {
        String css =
            "body{font-family:Segoe UI,Arial,sans-serif;font-size:13px;line-height:1.65;" +
                "margin:24px 36px;background:" + ThemeColors.htmlBg() + ";color:" + ThemeColors.htmlFg() + "}" +
            "h1{color:" + ThemeColors.htmlH1() + ";margin-bottom:2px}" +
            "h2{color:" + ThemeColors.htmlH2() + ";margin-top:20px;margin-bottom:6px}" +
            "h3{color:" + ThemeColors.htmlH3() + ";margin-bottom:4px}" +
            "a{color:" + ThemeColors.htmlLink() + "}" +
            "hr{border:none;border-top:1px solid " + ThemeColors.htmlBorder() + ";margin:12px 0 18px}" +
            "code{background:" + ThemeColors.htmlCode() + ";padding:1px 4px;border-radius:3px;font-size:12px}" +
            "table{border-collapse:collapse;width:100%;margin-bottom:10px}" +
            "th{text-align:left;padding:7px 12px;border:1px solid " + ThemeColors.htmlBorder() +
                ";background:" + ThemeColors.htmlRowHdr() + "}" +
            "td{padding:6px 12px;border:1px solid " + ThemeColors.htmlBorder() + "}" +
            "tr.alt td{background:" + ThemeColors.htmlRowAlt() + "}" +
            "ul,ol{padding-left:22px}" +
            "li{margin-bottom:4px}" +
            ".dim{color:" + ThemeColors.htmlDim() + ";font-size:11px}";

        return "<!DOCTYPE html><html><head><style>" + css + "</style></head><body>" +

            "<h1>Access Context Fuzzer " +
                "<span style='font-size:13px;font-weight:normal;color:" + ThemeColors.htmlDim() + "'>v" + version + "</span>" +
            "</h1>" +
            "<p class='dim' style='margin-top:0'>Developed by <a href='https://tagmachan.com'>Tagoletta</a>" +
                " &nbsp;·&nbsp; MIT License</p>" +
            "<hr/>" +

            "<h2>What is this?</h2>" +
            "<p>A Burp Suite extension for systematically testing <b>access control bypass</b>, " +
            "<b>path normalization</b>, and <b>Web Cache Deception (WCD)</b> vulnerabilities. " +
            "Instead of manually crafting dozens of header and path variations, the extension " +
            "generates and tests hundreds of variants automatically — then highlights exactly which " +
            "ones behave differently from the baseline.</p>" +
            "<p>It runs entirely inside Burp. No external proxy, no side-channel, no extra setup. " +
            "Right-click a request → pick an engine → watch the results.</p>" +

            "<h2>Quick Start</h2>" +
            "<ol>" +
            "<li>Browse to your target in Burp's built-in browser</li>" +
            "<li>Find a request in <b>Proxy → HTTP History</b></li>" +
            "<li><b>Right-click</b> the request → choose an <i>Access Context</i> action</li>" +
            "<li>The matching tab opens and the scan starts automatically</li>" +
            "<li>Click <b>🔍 Show Only Interesting</b> to filter out baseline-matching rows</li>" +
            "<li><b>Double-click</b> any row to open Burp's native request/response viewer</li>" +
            "<li><b>Right-click</b> a result row → <i>Compare with Baseline</i> for a side-by-side diff</li>" +
            "</ol>" +

            "<h2>The Three Engines</h2>" +

            "<h3>🔐 Header Bypass</h3>" +
            "<p>Injects IP spoofing and host manipulation headers to test whether access control " +
            "decisions rely on easily-spoofed headers like <code>X-Forwarded-For</code>, " +
            "<code>X-Real-IP</code>, <code>X-Original-URL</code>, or <code>X-Forwarded-Host</code>. " +
            "Covers 40+ built-in variants (WebDAV verbs, HTTP/2 pseudo-headers, content-type overrides) " +
            "plus custom headers and IPs loaded from a wordlist file.</p>" +

            "<h3>🔀 Path / GET Bypass</h3>" +
            "<p>Manipulates the URL path using encoding tricks, normalization techniques, and Web Cache " +
            "Deception payloads. Tests how the origin server and CDN interpret the same URL differently. " +
            "Includes a <b>CDN Profile</b> selector (Cloudflare, Akamai, Fastly, CloudFront, Nginx, " +
            "Varnish) that filters delimiter payloads to the set most relevant to your target — and a " +
            "<b>Fat GET</b> option that sends a request body with a GET, which some CDNs ignore " +
            "while origins process differently.</p>" +

            "<h3>🎯 Selection Fuzz</h3>" +
            "<p>Select any portion of a request in Burp's message editor, then right-click → " +
            "<i>Fuzz Selection</i>. Fuzzes only the selected text with URL encoding, double encoding, " +
            "IIS Unicode, UTF-8 fullwidth, and custom payloads — without modifying the rest of the request.</p>" +

            "<h2>Web Cache Deception (WCD)</h2>" +
            "<p>The Path engine includes a dedicated 4-phase WCD pipeline. Enable the relevant " +
            "checkboxes in the <i>Built-in Payloads</i> panel:</p>" +
            "<table>" +
            "<tr><th style='width:32px'>#</th><th>Checkbox</th><th>What it finds</th></tr>" +
            "<tr><td><b>1</b></td><td>Delimiter Fuzzing</td>" +
                "<td>Which characters the origin treats as path delimiters (<code>?</code> <code>#</code> <code>%23</code> <code>;</code>…)</td></tr>" +
            "<tr class='alt'><td><b>2</b></td><td>Delimiter + Extension</td>" +
                "<td>Whether adding a static extension after a delimiter (<code>.js</code>, <code>.css</code>, 19 types) triggers CDN caching</td></tr>" +
            "<tr><td><b>3</b></td><td>Normalization Discrepancy</td>" +
                "<td>Whether the CDN normalizes encoded dot-segments (<code>..%2f</code>) that the origin rejects</td></tr>" +
            "<tr class='alt'><td><b>4</b></td><td>Cache Deception Combos</td>" +
                "<td>Combined exploit payloads — the cache sees a static resource path, the origin serves the authenticated endpoint</td></tr>" +
            "</table>" +
            "<p>After a Path scan finishes, a <b>WCD Summary</b> popup shows HIT / PRIVATE / Vary:Cookie counts " +
            "and lists which variants look exploitable. Use <b>Verify WCD (No-Auth)</b> from the right-click " +
            "context menu to replay a cached URL without credentials and confirm the finding.</p>" +

            "<h2>Tips</h2>" +
            "<ul>" +
            "<li>The <b>Cache</b> column shows <code>HIT ✅</code> / <code>MISS</code> / <code>PRIVATE 🚫</code> " +
                "at a glance — no need to read Notes for cache status</li>" +
            "<li><b>Pink rows</b> = sensitive data detected in the response (JWT, CSRF token, Bearer token, API key)</li>" +
            "<li>Set a <b>CDN Profile</b> before a WCD scan to filter irrelevant delimiter payloads</li>" +
            "<li>Enable <b>Parallel Mode</b> in Settings for fast scans on non-rate-limited targets</li>" +
            "<li>Click <b>👁 Preview Payloads</b> to audit the full variant list before hitting a rate-sensitive endpoint</li>" +
            "<li>Settings persist across Burp restarts — configure once, done</li>" +
            "<li>All scanned requests appear in <b>Burp's Site Map</b> automatically</li>" +
            "</ul>" +

            "<hr/>" +
            "<p class='dim'>" +
                "v" + version + " &nbsp;·&nbsp; " +
                "<a href='https://tagmachan.com'>tagmachan.com</a> &nbsp;·&nbsp; " +
                "<a href='https://github.com/Tagoletta/AccessContextFuzzer'>GitHub</a> &nbsp;·&nbsp; " +
                "<a href='https://tagmachan.com/web-cache-deception-and-poisoning.tagox'>WCD Guide</a>" +
            "</p>" +
            "</body></html>";
    }
}
