package burp.core;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class OracleTest {

    @Test
    void catchAll2xxDetection() {
        assertTrue(new ScanEngine.Oracle(true, 200, 100, "h").catchAllIs2xx());
        assertTrue(new ScanEngine.Oracle(true, 204, 0, "").catchAllIs2xx());
        assertFalse(new ScanEngine.Oracle(true, 404, 100, "h").catchAllIs2xx());
        assertFalse(new ScanEngine.Oracle(true, 403, 100, "h").catchAllIs2xx());
    }

    @Test
    void disabledOracleIsStableAndNoCatchAll() {
        ScanEngine.Oracle o = ScanEngine.Oracle.disabled();
        assertTrue(o.baselineStable);
        assertEquals(-1, o.catchAllStatus);
        assertFalse(o.catchAllIs2xx());
        assertEquals("", o.catchAllHash);
    }

    @Test
    void nullHashNormalizedToEmpty() {
        assertEquals("", new ScanEngine.Oracle(false, 404, -1, null).catchAllHash);
    }
}
