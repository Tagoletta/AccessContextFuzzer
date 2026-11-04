package burp.util;

import java.util.Locale;
import java.util.Map;

/**
 * Vendor-agnostic cache-state analysis.
 *
 * <p>The previous implementation keyed every HIT/MISS decision on the single
 * {@code X-Cache} header, which the two most common CDNs do not send:
 * Cloudflare uses {@code cf-cache-status}, Vercel uses {@code x-vercel-cache},
 * and the modern standard (RFC 9211) is {@code Cache-Status}. As a result the
 * WCD MISS→HIT confirmation silently never fired behind those CDNs.
 *
 * <p>This class is intentionally pure (operates on a lower-cased header map) so
 * it can be unit-tested without a live Burp/Montoya response.
 */
public final class CacheAnalyzer {

    private CacheAnalyzer() {}

    /** Headers whose value directly reports cache HIT/MISS, across vendors. */
    private static final String[] STATUS_HEADERS = {
            "x-cache",            // Fastly / Akamai / CloudFront / Varnish
            "cf-cache-status",    // Cloudflare
            "x-vercel-cache",     // Vercel
            "cache-status",       // RFC 9211 (standard)
            "x-cache-status",     // Nginx proxy_cache
            "x-proxy-cache",      // Nginx (alt)
            "x-nextjs-cache",     // Next.js
            "x-drupal-cache",     // Drupal
            "cache",              // Netlify ("cache": "HIT")
    };

    public static final class Result {
        public final boolean hit;
        public final boolean miss;
        public final boolean isPrivate;
        public final boolean noStore;
        public final boolean cookieInVary;
        public final boolean cacheableByCc;   // max-age / s-maxage present and not private/no-store
        public final String  label;           // for the Cache column

        Result(boolean hit, boolean miss, boolean isPrivate, boolean noStore,
               boolean cookieInVary, boolean cacheableByCc, String label) {
            this.hit = hit; this.miss = miss; this.isPrivate = isPrivate; this.noStore = noStore;
            this.cookieInVary = cookieInVary; this.cacheableByCc = cacheableByCc; this.label = label;
        }
    }

    /**
     * True if {@code value} reports the response was served from cache, for any
     * known vendor syntax: {@code HIT}, {@code TCP_HIT}, {@code Hit from cloudfront},
     * Cloudflare {@code STALE}/{@code REVALIDATED}/{@code UPDATING}, RFC 9211
     * {@code Cache-Status: name; hit}. An RFC 9211 {@code fwd=} segment means the
     * request was forwarded to the origin, i.e. not served purely from cache.
     */
    public static boolean valueIsHit(String value) {
        if (value == null) return false;
        String v = value.toLowerCase(Locale.ROOT);
        if (v.contains("fwd=")) return false;          // RFC 9211 forward to origin
        return v.contains("hit")
            || v.contains("stale")
            || v.contains("revalidated")
            || v.contains("updating");
    }

    /** True if {@code value} explicitly reports a cache miss / non-cache serve. */
    public static boolean valueIsMiss(String value) {
        if (value == null) return false;
        String v = value.toLowerCase(Locale.ROOT);
        if (v.contains("fwd=")) return true;           // RFC 9211 forward to origin
        return v.contains("miss") || v.contains("expired")
            || v.contains("dynamic") || v.contains("bypass");
    }

    /**
     * @param lc a map of lower-cased header name → value (values already joined
     *           if the header appeared more than once)
     */
    public static Result analyze(Map<String, String> lc) {
        String cc   = lc.getOrDefault("cache-control", "").toLowerCase(Locale.ROOT);
        String vary = lc.getOrDefault("vary", "").toLowerCase(Locale.ROOT);

        boolean isPrivate = cc.contains("private");
        boolean noStore   = cc.contains("no-store");
        boolean hasMaxAge = cc.contains("max-age") || cc.contains("s-maxage");
        boolean cookieInVary = vary.contains("cookie");

        boolean hit = false, miss = false;
        String rawStatus = "";
        for (String h : STATUS_HEADERS) {
            String val = lc.get(h);
            if (val == null || val.isEmpty()) continue;
            if (rawStatus.isEmpty()) rawStatus = val;
            if (valueIsHit(val))  hit = true;
            if (valueIsMiss(val)) miss = true;
        }
        // A genuine hit header wins over a miss header from another hop.
        if (hit) miss = false;

        boolean cacheableByCc = hasMaxAge && !isPrivate && !noStore;

        String label;
        if (noStore)              label = "NO-STORE 🚫";
        else if (isPrivate)       label = "PRIVATE 🚫";
        else if (hit)             label = cookieInVary ? "HIT/Vary:Cookie" : "HIT ✅";
        else if (miss)            label = "MISS";
        else if (!rawStatus.isEmpty()) label = rawStatus;
        else if (cacheableByCc)   label = "CDN-CACHE?";
        else                      label = "?";

        return new Result(hit, miss, isPrivate, noStore, cookieInVary, cacheableByCc, label);
    }
}
