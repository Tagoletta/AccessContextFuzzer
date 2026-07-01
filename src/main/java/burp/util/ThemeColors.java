package burp.util;

import javax.swing.*;
import java.awt.*;

public final class ThemeColors {

    private ThemeColors() {}

    // ── Theme detection (cached; refreshed on L&F change) ────────────────────

    private static volatile boolean cachedDark = computeIsDark();

    static {
        UIManager.addPropertyChangeListener("lookAndFeel", evt -> cachedDark = computeIsDark());
    }

    private static boolean computeIsDark() {
        Color bg = UIManager.getColor("Panel.background");
        return bg != null && (0.299 * bg.getRed() + 0.587 * bg.getGreen() + 0.114 * bg.getBlue()) < 128;
    }

    public static boolean isDark() { return cachedDark; }

    // ── Table row highlight colors ────────────────────────────────────────────

    public static Color rowSensitive()   { return isDark() ? new Color(130, 35, 75)  : new Color(255, 140, 200); }
    public static Color rowCacheHit()    { return isDark() ? new Color(155, 85, 10)  : new Color(255, 165, 50);  }
    public static Color rowBypass()      { return isDark() ? new Color(145, 115, 10) : new Color(255, 215, 100); }
    public static Color rowRedirect()    { return isDark() ? new Color(20, 65, 135)  : new Color(180, 220, 255); }
    public static Color rowBodyBypass()  { return isDark() ? new Color(155, 95, 10)  : new Color(255, 200, 100); }
    public static Color rowCustom()      { return isDark() ? new Color(85, 45, 145)  : new Color(220, 200, 255); }
    public static Color rowSuccess()     { return isDark() ? new Color(20, 95, 40)   : new Color(200, 255, 200); }
    public static Color rowRedirect3xx() { return isDark() ? new Color(20, 55, 115)  : new Color(200, 220, 255); }
    public static Color rowRateLimit()   { return isDark() ? new Color(115, 105, 10) : new Color(255, 255, 180); }
    public static Color rowError()       { return isDark() ? new Color(135, 25, 25)  : new Color(255, 200, 200); }
    public static Color rowReset()       { return isDark() ? new Color(65, 65, 65)   : new Color(200, 200, 200); }
    public static Color rowForeground()  { return isDark() ? new Color(235, 235, 235) : Color.BLACK; }

    // ── Button colors ─────────────────────────────────────────────────────────

    public static Color btnStop()        { return isDark() ? new Color(190, 65, 65)  : new Color(255, 102, 102); }
    public static Color btnRerun()       { return isDark() ? new Color(55, 125, 200) : new Color(102, 178, 255); }
    public static Color btnFilterOff()   { return isDark() ? new Color(170, 130, 10) : new Color(255, 193, 7);   }
    public static Color btnFilterOn()    { return isDark() ? new Color(35, 135, 50)  : new Color(76, 175, 80);   }
    public static Color btnWhiteFg()     { return Color.WHITE; }
    public static Color btnFilterOffFg() { return isDark() ? Color.WHITE : Color.BLACK; }

    // ── Semantic text colors ──────────────────────────────────────────────────

    public static Color warningText() { return isDark() ? new Color(215, 150, 45) : new Color(180, 100, 0); }

    public static Color dimText() {
        Color fg = coalesce(UIManager.getColor("Label.foreground"), Color.DARK_GRAY);
        Color bg = coalesce(UIManager.getColor("Panel.background"), Color.WHITE);
        return blend(bg, fg, 0.45f);
    }

    // ── HTML color strings (for JEditorPane / diff HTML) ─────────────────────

    public static String htmlBg()      { return hex(coalesce(UIManager.getColor("Panel.background"), Color.WHITE)); }
    public static String htmlFg()      { return hex(coalesce(UIManager.getColor("Label.foreground"), Color.BLACK)); }
    public static String htmlBorder()  { return hex(coalesce(UIManager.getColor("Separator.foreground"), new Color(200, 200, 200))); }
    public static String htmlRowHdr() {
        Color bg = coalesce(UIManager.getColor("Panel.background"), Color.WHITE);
        return hex(isDark() ? shift(bg, +30) : shift(bg, -18));
    }
    public static String htmlRowAlt() {
        Color alt = UIManager.getColor("Table.alternateRowColor");
        if (alt != null) return hex(alt);
        Color bg = coalesce(UIManager.getColor("Panel.background"), Color.WHITE);
        return hex(isDark() ? shift(bg, +20) : shift(bg, -10));
    }
    public static String htmlCode() {
        Color bg = coalesce(UIManager.getColor("Panel.background"), Color.WHITE);
        return hex(isDark() ? shift(bg, +28) : shift(bg, -12));
    }
    public static String htmlDim() {
        return hex(blend(coalesce(UIManager.getColor("Panel.background"), Color.WHITE),
                         coalesce(UIManager.getColor("Label.foreground"), Color.BLACK), 0.45f));
    }
    public static String htmlH1()   { return isDark() ? "#7ec8e3" : "#1a3a4a"; }
    public static String htmlH2()   { return isDark() ? "#5bb3cf" : "#2c5364"; }
    public static String htmlH3()   { return isDark() ? "#4da3bf" : "#3a6678"; }
    public static String htmlLink() { return isDark() ? "#6ab0d0" : "#1a6a8a"; }

    // Diff viewer
    public static String diffChanged() { return isDark() ? "#6b2020" : "#ffebee"; }
    public static String diffAdded()   { return isDark() ? "#1a5020" : "#e8f5e9"; }
    public static String diffRemoved() { return isDark() ? "#6b4a10" : "#fff3e0"; }
    public static String diffHeader()  { return isDark() ? "#333333" : "#dddddd"; }
    public static String diffBorder()  { return isDark() ? "#555555" : "#999999"; }
    public static String diffRowSep()  { return isDark() ? "#444444" : "#eeeeee"; }

    // ── Internal helpers ──────────────────────────────────────────────────────

    private static Color coalesce(Color c, Color fallback) { return c != null ? c : fallback; }

    private static Color blend(Color a, Color b, float t) {
        return new Color(clamp((int)(a.getRed()   + t * (b.getRed()   - a.getRed()))),
                         clamp((int)(a.getGreen() + t * (b.getGreen() - a.getGreen()))),
                         clamp((int)(a.getBlue()  + t * (b.getBlue()  - a.getBlue()))));
    }

    private static Color shift(Color c, int d) {
        return new Color(clamp(c.getRed()+d), clamp(c.getGreen()+d), clamp(c.getBlue()+d));
    }

    public static String hex(Color c) {
        return String.format("#%02x%02x%02x", c.getRed(), c.getGreen(), c.getBlue());
    }

    private static int clamp(int v) { return Math.max(0, Math.min(255, v)); }
}
