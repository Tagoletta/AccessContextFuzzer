package burp.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class HttpUtilsTest {

    @Test
    void identicalBodiesHashEqual() {
        String a = "<html><body>hello</body></html>";
        assertEquals(HttpUtils.bodyHash(a), HttpUtils.bodyHash(a));
    }

    @Test
    void volatileTokensNormalizedAway() {
        // Same page, different CSRF token + timestamp => must hash the same now.
        String p1 = "{\"csrf_token\":\"abc123def456aaaa\",\"ts\":\"2026-01-01T10:00:00Z\",\"user\":\"ali\"}";
        String p2 = "{\"csrf_token\":\"zzz999www888bbbb\",\"ts\":\"2026-11-04T07:00:00Z\",\"user\":\"ali\"}";
        assertEquals(HttpUtils.bodyHash(p1), HttpUtils.bodyHash(p2));
    }

    @Test
    void uuidAndJwtNormalized() {
        String a = "id=550e8400-e29b-41d4-a716-446655440000 token=eyJhbGci.eyJzdWIiOiIxIn0.sig user=x";
        String b = "id=11111111-2222-4333-8444-555555555555 token=eyJ0eXAi.eyJuYW1lIjoieSJ9.zzz user=x";
        assertEquals(HttpUtils.bodyHash(a), HttpUtils.bodyHash(b));
    }

    @Test
    void genuinelyDifferentBodiesDiffer() {
        assertNotEquals(HttpUtils.bodyHash("secret admin panel"),
                        HttpUtils.bodyHash("public login page"));
    }

    @Test
    void wordAndLineCount() {
        assertEquals(3, HttpUtils.wordCount("one two three"));
        assertEquals(0, HttpUtils.wordCount(""));
        assertEquals(3, HttpUtils.lineCount("a\nb\nc"));
        assertEquals(2, HttpUtils.lineCount("a\r\nb"));
    }

    @Test
    void titleExtraction() {
        assertEquals("Hello", HttpUtils.getTitle("<html><head><TITLE>Hello</TITLE></head></html>"));
        assertEquals("", HttpUtils.getTitle("<html>no title</html>"));
    }
}
