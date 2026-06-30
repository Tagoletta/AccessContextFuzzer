package burp.util;

import burp.api.montoya.http.message.requests.HttpRequest;

public class EncoderUtils {

    private EncoderUtils() {}

    public static String urlEncode(String v) {
        StringBuilder sb = new StringBuilder();
        for (char c : v.toCharArray()) {
            if (c == '/' || c == '.' || c == '?') sb.append(c);
            else sb.append(String.format("%%%02x", (int) c));
        }
        return sb.toString();
    }

    public static String iisUnicodeEncode(String v) {
        StringBuilder sb = new StringBuilder();
        for (char c : v.toCharArray()) {
            if (c == '/' || c == '.' || c == '?') sb.append(c);
            else sb.append(String.format("%%u00%02x", (int) c));
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
