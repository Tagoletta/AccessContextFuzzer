package burp.util;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.security.MessageDigest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class HttpUtils {

    private HttpUtils() {}

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

    public static int statusOf(HttpRequestResponse rr) {
        try { return rr.response().statusCode(); } catch (Throwable t) { return -1; }
    }

    public static int bodyLen(HttpRequestResponse rr) {
        try { return rr.response().body() == null ? 0 : rr.response().body().length(); } catch (Throwable t) { return 0; }
    }

    public static String bodyHash(HttpRequestResponse rr) {
        try {
            byte[] body = rr.response().body().getBytes();
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(body);
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) sb.append(String.format("%02x", b & 0xff));
            return sb.toString();
        } catch (Throwable t) {
            return "";
        }
    }

    public static String getTitle(HttpRequestResponse rr) {
        try {
            String b = rr.response().bodyToString();
            if (b == null) return "";
            Matcher m = Pattern.compile("<title>(.*?)</title>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL).matcher(b);
            if (m.find()) return m.group(1).trim().replaceAll("\\s+", " ");
        } catch (Throwable t) {}
        return "";
    }

    public static String getHeaderValue(HttpRequestResponse rr, String headerName) {
        try {
            if (rr == null || rr.response() == null) return "";
            String val = rr.response().headerValue(headerName);
            return val != null ? val : "";
        } catch (Throwable t) {
            return "";
        }
    }

    public static String computeCacheStatus(HttpRequestResponse rr) {
        try {
            String xCache = getHeaderValue(rr, "X-Cache");
            String cc     = getHeaderValue(rr, "Cache-Control").toLowerCase();
            String vary   = getHeaderValue(rr, "Vary").toLowerCase();
            if (cc.contains("no-store")) return "NO-STORE 🚫";
            if (cc.contains("private"))  return "PRIVATE 🚫";
            if (xCache.toUpperCase().contains("HIT"))
                return vary.contains("cookie") ? "HIT/Vary:Cookie" : "HIT ✅";
            if (xCache.toUpperCase().contains("MISS")) return "MISS";
            if (!xCache.isEmpty()) return xCache;
            if (cc.contains("s-maxage")) return "CDN-CACHE?";
            return "?";
        } catch (Throwable t) { return "?"; }
    }

    public static int wordCount(HttpRequestResponse rr) {
        try {
            String b = rr.response().bodyToString();
            return (b == null || b.trim().isEmpty()) ? 0 : b.trim().split("\\s+").length;
        } catch (Throwable t) { return 0; }
    }

    public static int lineCount(HttpRequestResponse rr) {
        try {
            String b = rr.response().bodyToString();
            return (b == null || b.isEmpty()) ? 0 : b.split("\r\n|\r|\n").length;
        } catch (Throwable t) { return 0; }
    }

    public static void detectSensitiveData(HttpRequestResponse rr, StringBuilder notes) {
        try {
            if (rr == null || rr.response() == null) return;
            String body = rr.response().bodyToString();
            if (body == null || body.isEmpty()) return;
            if (PATTERN_JWT.matcher(body).find())         notes.append("SENSITIVE_DATA:JWT ");
            if (PATTERN_CSRF.matcher(body).find())        notes.append("SENSITIVE_DATA:CSRF_TOKEN ");
            if (PATTERN_EMAIL_FIELD.matcher(body).find()) notes.append("SENSITIVE_DATA:EMAIL ");
            if (PATTERN_BEARER.matcher(body).find())      notes.append("SENSITIVE_DATA:BEARER ");
            if (PATTERN_SECRET.matcher(body).find())      notes.append("SENSITIVE_DATA:SECRET ");
        } catch (Exception ignored) {}
    }
}
