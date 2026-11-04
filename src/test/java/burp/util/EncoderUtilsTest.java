package burp.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class EncoderUtilsTest {

    @Test
    void urlEncodeKeepsOnlyStructuralChars() {
        // By design this is an aggressive "encode everything except / . ?" bypass
        // helper — letters are percent-encoded too (uppercase hex).
        assertEquals("/%61%64%6D%69%6E/.", EncoderUtils.urlEncode("/admin/."));
    }

    @Test
    void urlEncodeAsciiIsUppercaseHex() {
        // space (0x20) and 'A' (0x41) -> %20 %41
        assertEquals("%20%41", EncoderUtils.urlEncode(" A"));
    }

    @Test
    void urlEncodeNonAsciiUsesUtf8Bytes() {
        // Turkish 'ğ' is U+011F -> UTF-8 C4 9F. The old code produced the invalid "%11f".
        assertEquals("%C4%9F", EncoderUtils.urlEncode("ğ"));
        // 'ü' U+00FC -> UTF-8 C3 BC (NOT %fc)
        assertEquals("%C3%BC", EncoderUtils.urlEncode("ü"));
    }

    @Test
    void urlEncodeNeverEmitsOddLengthEscapes() {
        String out = EncoderUtils.urlEncode("şçöğüİ/abc");
        // Every '%' must be followed by exactly two hex digits.
        assertTrue(out.matches("(?:[^%]|%[0-9A-Fa-f]{2})*"), "invalid percent-encoding: " + out);
    }

    @Test
    void urlEncodeHandlesAstralCodePoint() {
        // U+1F600 (😀) -> UTF-8 F0 9F 98 80
        assertEquals("%F0%9F%98%80", EncoderUtils.urlEncode("😀"));
    }

    @Test
    void iisUnicodeEncodeUsesRealCodePoint() {
        // 'ğ' U+011F -> %u011f  (old code truncated to %u001f)
        assertEquals("%u011f", EncoderUtils.iisUnicodeEncode("ğ"));
        assertEquals("/", EncoderUtils.iisUnicodeEncode("/"));
    }

    @Test
    void isHttp2Detection() {
        assertTrue(EncoderUtils.isHttp2("HTTP/2"));
        assertTrue(EncoderUtils.isHttp2("HTTP/2.0"));
        assertTrue(EncoderUtils.isHttp2("HTTP/3"));
        assertFalse(EncoderUtils.isHttp2("HTTP/1.1"));
        assertFalse(EncoderUtils.isHttp2("HTTP/1.0"));
        assertFalse(EncoderUtils.isHttp2(null));
    }
}
