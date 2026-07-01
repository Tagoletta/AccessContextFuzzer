package burp.util;

import burp.api.montoya.http.message.HttpRequestResponse;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.StringTokenizer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class HttpUtils {

    private HttpUtils() {}

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
            MessageDigest md = MD5_TL.get();
            md.reset();
            byte[] digest = md.digest(body.getBytes(StandardCharsets.UTF_8));
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
}
