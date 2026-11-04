package burp.util;

import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class CacheAnalyzerTest {

    private static Map<String, String> h(String... kv) {
        Map<String, String> m = new HashMap<>();
        for (int i = 0; i + 1 < kv.length; i += 2) m.put(kv[i].toLowerCase(), kv[i + 1]);
        return m;
    }

    @Test
    void cloudflareHitIsDetected() {
        // Cloudflare sends NO X-Cache — the old code missed this entirely.
        CacheAnalyzer.Result r = CacheAnalyzer.analyze(h(
                "cf-cache-status", "HIT", "cache-control", "public, max-age=60"));
        assertTrue(r.hit);
        assertTrue(r.cacheableByCc);
        assertEquals("HIT ✅", r.label);
    }

    @Test
    void vercelHitIsDetected() {
        CacheAnalyzer.Result r = CacheAnalyzer.analyze(h("x-vercel-cache", "HIT"));
        assertTrue(r.hit);
    }

    @Test
    void rfc9211HitAndMiss() {
        assertTrue(CacheAnalyzer.analyze(h("cache-status", "ExampleCache; hit")).hit);
        CacheAnalyzer.Result miss = CacheAnalyzer.analyze(h("cache-status", "ExampleCache; fwd=uri-miss"));
        assertFalse(miss.hit);
        assertTrue(miss.miss);
    }

    @Test
    void fastlyXCacheStillWorks() {
        assertTrue(CacheAnalyzer.analyze(h("x-cache", "HIT")).hit);
        assertTrue(CacheAnalyzer.analyze(h("x-cache", "TCP_HIT from edge")).hit);
        assertTrue(CacheAnalyzer.analyze(h("x-cache", "Hit from cloudfront")).hit);
    }

    @Test
    void missDoesNotFalselyReportHit() {
        CacheAnalyzer.Result r = CacheAnalyzer.analyze(h("x-cache", "MISS"));
        assertFalse(r.hit);
        assertTrue(r.miss);
        assertEquals("MISS", r.label);
    }

    @Test
    void cloudflareDynamicIsNotHit() {
        CacheAnalyzer.Result r = CacheAnalyzer.analyze(h("cf-cache-status", "DYNAMIC"));
        assertFalse(r.hit);
        assertTrue(r.miss);
    }

    @Test
    void privateAndNoStoreWin() {
        assertEquals("PRIVATE 🚫", CacheAnalyzer.analyze(h("cache-control", "private, max-age=0")).label);
        assertEquals("NO-STORE 🚫", CacheAnalyzer.analyze(h("cache-control", "no-store")).label);
        assertFalse(CacheAnalyzer.analyze(h("cache-control", "private")).cacheableByCc);
    }

    @Test
    void localeSafeMaxAgeUppercase() {
        // A Turkish-locale server could send "Max-Age" — must still be cacheable.
        CacheAnalyzer.Result r = CacheAnalyzer.analyze(h(
                "cf-cache-status", "MISS", "cache-control", "public, Max-Age=120"));
        assertTrue(r.cacheableByCc);
    }

    @Test
    void varyCookieLabel() {
        CacheAnalyzer.Result r = CacheAnalyzer.analyze(h(
                "x-cache", "HIT", "vary", "Cookie"));
        assertTrue(r.hit);
        assertTrue(r.cookieInVary);
        assertEquals("HIT/Vary:Cookie", r.label);
    }

    @Test
    void multiHopHitWinsOverMiss() {
        CacheAnalyzer.Result r = CacheAnalyzer.analyze(h("x-cache", "MISS, HIT"));
        assertTrue(r.hit);
        assertFalse(r.miss);
    }
}
