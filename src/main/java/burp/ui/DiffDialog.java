package burp.ui;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.core.ExtensionContext;
import burp.util.HttpUtils;
import burp.util.ThemeColors;

import javax.swing.*;
import java.awt.*;

public class DiffDialog {

    private DiffDialog() {}

    public static void show(ExtensionContext ctx, HttpRequestResponse baseline,
                             HttpRequestResponse variant, String variantName) {
        Frame burpFrame = (Frame) SwingUtilities.getAncestorOfClass(Frame.class, ctx.mainTabs);
        JDialog dialog = new JDialog(burpFrame, "Diff: BASELINE vs " + variantName, false);
        dialog.setSize(1400, 800);
        dialog.setLocationRelativeTo(burpFrame);

        int baseSt  = HttpUtils.statusOf(baseline);
        int varSt   = HttpUtils.statusOf(variant);
        int baseLen = HttpUtils.bodyLen(baseline);
        int varLen  = HttpUtils.bodyLen(variant);

        String cChanged = ThemeColors.diffChanged();
        String cAdded   = ThemeColors.diffAdded();
        String cRemoved = ThemeColors.diffRemoved();

        JPanel infoPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        infoPanel.setBorder(BorderFactory.createEmptyBorder(4, 6, 4, 6));
        JLabel infoLabel = new JLabel(String.format(
                "<html><b>BASELINE:</b> %d (%d bytes)&nbsp;&nbsp;|&nbsp;&nbsp;<b>VARIANT:</b> %d (%d bytes)" +
                "&nbsp;&nbsp;&nbsp;" +
                "<span style='background:%s'>&nbsp;&nbsp;</span> Changed&nbsp;" +
                "<span style='background:%s'>&nbsp;&nbsp;</span> Added&nbsp;" +
                "<span style='background:%s'>&nbsp;&nbsp;</span> Removed</html>",
                baseSt, baseLen, varSt, varLen, cChanged, cAdded, cRemoved));
        infoPanel.add(infoLabel);

        String baseBody = "", varBody = "";
        try { if (baseline.response() != null) baseBody = baseline.response().bodyToString(); } catch (Exception ignored) {}
        try { if (variant.response()  != null) varBody  = variant.response().bodyToString();  } catch (Exception ignored) {}

        JEditorPane diffPane = new JEditorPane("text/html", buildDiffHtml(baseBody, varBody));
        diffPane.setEditable(false);
        diffPane.setCaretPosition(0);

        dialog.setLayout(new BorderLayout());
        dialog.add(infoPanel, BorderLayout.NORTH);
        dialog.add(new JScrollPane(diffPane), BorderLayout.CENTER);
        dialog.setVisible(true);
    }

    private static String buildDiffHtml(String baseBody, String varBody) {
        String bg      = ThemeColors.htmlBg();
        String fg      = ThemeColors.htmlFg();
        String hdr     = ThemeColors.diffHeader();
        String border  = ThemeColors.diffBorder();
        String rowSep  = ThemeColors.diffRowSep();
        String changed = ThemeColors.diffChanged();
        String added   = ThemeColors.diffAdded();
        String removed = ThemeColors.diffRemoved();

        String[] baseLines = baseBody.split("\r?\n", -1);
        String[] varLines  = varBody.split("\r?\n", -1);
        int maxLen = Math.min(Math.max(baseLines.length, varLines.length), 1000);

        StringBuilder html = new StringBuilder(
                "<html><body style='font-family:monospace;font-size:11px;margin:0;padding:0;" +
                "background:" + bg + ";color:" + fg + "'>" +
                "<table style='width:100%;border-collapse:collapse;table-layout:fixed'>" +
                "<colgroup><col style='width:50%'/><col style='width:50%'/></colgroup>" +
                "<tr style='background:" + hdr + "'>" +
                "<th style='padding:3px 6px;text-align:left;border-right:2px solid " + border + "'>BASELINE</th>" +
                "<th style='padding:3px 6px;text-align:left'>VARIANT</th></tr>");

        for (int i = 0; i < maxLen; i++) {
            String bl = i < baseLines.length ? escapeHtml(baseLines[i]) : "";
            String vl = i < varLines.length  ? escapeHtml(varLines[i])  : "";
            boolean same = bl.equals(vl);
            if (same) {
                html.append("<tr>" +
                    "<td style='padding:1px 4px;white-space:pre;border-right:2px solid " + rowSep + "'>")
                    .append(bl).append("</td>" +
                    "<td style='padding:1px 4px;white-space:pre'>").append(vl).append("</td></tr>");
            } else {
                String blBg = bl.isEmpty() ? removed : changed;
                String vlBg = vl.isEmpty() ? removed : added;
                html.append("<tr>")
                    .append("<td style='padding:1px 4px;white-space:pre;border-right:2px solid " + rowSep +
                            ";background:" + blBg + "'>")
                    .append(bl.isEmpty() ? "<i style='color:#888'>&lt;empty&gt;</i>" : bl).append("</td>")
                    .append("<td style='padding:1px 4px;white-space:pre;background:" + vlBg + "'>")
                    .append(vl.isEmpty() ? "<i style='color:#888'>&lt;empty&gt;</i>" : vl).append("</td></tr>");
            }
        }
        if (Math.max(baseLines.length, varLines.length) > 1000)
            html.append("<tr><td colspan='2' style='padding:6px;font-style:italic'>" +
                    "[ Truncated — first 1000 lines shown ]</td></tr>");
        html.append("</table></body></html>");
        return html.toString();
    }

    public static String escapeHtml(String s) {
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }
}
