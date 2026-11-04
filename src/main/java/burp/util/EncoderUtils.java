package burp.util;

import burp.api.montoya.http.message.requests.HttpRequest;

import java.nio.charset.StandardCharsets;
import java.util.Locale;

public class EncoderUtils {

    private EncoderUtils() {}

    /**
     * True only for an HTTP/2 (or later) request. HTTP/2 pseudo-headers
     * ({@code :authority}, {@code :path}) are invalid as ordinary header lines
     * on an HTTP/1.1 request, so those variants must be skipped there.
     */
    public static boolean isHttp2(String httpVersion) {
        if (httpVersion == null) return false;
        String v = httpVersion.replace(" ", "").toUpperCase(Locale.ROOT);
        return v.contains("HTTP/2") || v.contains("HTTP/3") || v.equals("2") || v.equals("3");
    }

    /**
     * Percent-encode every character except the structural ones ('/', '.', '?').
     * Characters outside US-ASCII are encoded as their UTF-8 byte sequence
     * (e.g. 'ğ' → %C4%9F), not as a raw code point — the previous
     * {@code %02x} of {@code (int) c} produced invalid output (e.g. %11f) for
     * any character above U+00FF.
     */
    public static String urlEncode(String v) {
        if (v == null) return "";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < v.length(); i++) {
            char c = v.charAt(i);
            if (c == '/' || c == '.' || c == '?') { sb.append(c); continue; }
            if (c < 0x80) {
                sb.append(String.format("%%%02X", (int) c));
            } else {
                // Encode this (possibly multi-char, for surrogate pairs) code point as UTF-8 bytes.
                int cp = v.codePointAt(i);
                if (Character.charCount(cp) == 2) i++;
                for (byte b : new String(Character.toChars(cp)).getBytes(StandardCharsets.UTF_8))
                    sb.append(String.format("%%%02X", b & 0xFF));
            }
        }
        return sb.toString();
    }

    /**
     * IIS %u Unicode encoding. ASCII bytes use %uXXXX with the code point; the
     * structural characters are preserved. Non-ASCII uses the real code point
     * value (correct %u notation) instead of the old truncated {@code %u00%02x}.
     */
    public static String iisUnicodeEncode(String v) {
        if (v == null) return "";
        StringBuilder sb = new StringBuilder();
        int i = 0;
        while (i < v.length()) {
            char c = v.charAt(i);
            if (c == '/' || c == '.' || c == '?') { sb.append(c); i++; continue; }
            int cp = v.codePointAt(i);
            if (cp <= 0xFFFF) sb.append(String.format("%%u%04x", cp));
            else              sb.append(String.format("%%u%04x", (int) c)); // surrogate unit
            i += Character.charCount(cp);
        }
        return sb.toString();
    }

    public static String flipCase(String s) {
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            if (Character.isLowerCase(c)) sb.append(Character.toUpperCase(c));
            else if (Character.isUpperCase(c)) sb.append(Character.toLowerCase(c));
            else sb.append(c);
        }
        return sb.toString();
    }

    public static String stripLeadingSlash(String s) {
        return s.startsWith("/") ? s.substring(1) : s;
    }

    public static String injectDotDotSemicolon(String p) {
        int l = p.lastIndexOf('/');
        return (l <= 0 || l == p.length() - 1) ? p + "..;/" : p.substring(0, l) + "/..;" + p.substring(l);
    }

    public static HttpRequest addOrReplaceHeader(HttpRequest b, String n, String v) {
        return b.withRemovedHeader(n).withAddedHeader(n, v);
    }

    public static String escapeHtml(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
