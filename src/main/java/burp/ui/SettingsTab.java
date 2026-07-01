package burp.ui;

import burp.core.ExtensionContext;
import burp.core.ScanEngine;

import burp.util.ThemeColors;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;

public class SettingsTab {

    private SettingsTab() {}

    public static JPanel build(ExtensionContext ctx, ScanEngine scanEngine) {
        JPanel panel = new JPanel(new BorderLayout(0, 8));
        panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // OPSEC & Network — shared across all engines, persisted below
        ctx.lblCurrentIp = new JLabel(" Status: Not checked.");
        ctx.spinDelay = new JSpinner(new SpinnerNumberModel(20, 0, 60000, 10));
        JPanel opsecWrap = new JPanel(new BorderLayout());
        opsecWrap.add(ResultsPanel.buildOpsecPanel(ctx, ctx.lblCurrentIp, ctx.spinDelay, scanEngine), BorderLayout.WEST);

        JPanel topWrap = new JPanel(new BorderLayout(0, 8));

        JPanel topPanel = new JPanel(new GridLayout(1, 2, 8, 0));
        topPanel.setPreferredSize(new Dimension(800, 180));
        topPanel.setMaximumSize(new Dimension(Integer.MAX_VALUE, 180));

        // Global Scan Settings
        JPanel globalPanel = new JPanel();
        globalPanel.setLayout(new BoxLayout(globalPanel, BoxLayout.Y_AXIS));
        globalPanel.setBorder(BorderFactory.createTitledBorder("Global Scan Settings"));

        JPanel wafRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        wafRow.add(new JLabel("WAF Block Threshold:"));
        ctx.spinWafThreshold = new JSpinner(new SpinnerNumberModel(5, 1, 50, 1));
        ctx.spinWafThreshold.setPreferredSize(new Dimension(55, 25));
        wafRow.add(ctx.spinWafThreshold);
        wafRow.add(new JLabel("consecutive resets → auto-stop"));
        globalPanel.add(wafRow);

        JPanel parallelRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        ctx.chkParallelMode = new JCheckBox("Parallel Mode");
        ctx.chkParallelMode.setToolTipText("Send multiple requests simultaneously. Delay and session drift check are disabled.");
        ctx.spinParallelThreads = new JSpinner(new SpinnerNumberModel(4, 2, 20, 1));
        ctx.spinParallelThreads.setPreferredSize(new Dimension(55, 25));
        JLabel lblParallelWarn = new JLabel("⚠ Disables delay & drift check");
        lblParallelWarn.setFont(new Font("SansSerif", Font.ITALIC, 11));
        lblParallelWarn.setForeground(ThemeColors.warningText());
        parallelRow.add(ctx.chkParallelMode);
        parallelRow.add(new JLabel("  Threads:"));
        parallelRow.add(ctx.spinParallelThreads);
        parallelRow.add(lblParallelWarn);
        globalPanel.add(parallelRow);

        JPanel saveRow = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton btnSave = new JButton("💾 Save Settings Now");
        btnSave.addActionListener(e -> {
            save(ctx);
            JOptionPane.showMessageDialog(null, "Settings saved.", "Saved", JOptionPane.INFORMATION_MESSAGE);
        });
        saveRow.add(btnSave);
        saveRow.add(new JLabel("  Settings also auto-save on extension unload."));
        globalPanel.add(saveRow);
        topPanel.add(globalPanel);

        // Custom Detection Rules
        JPanel rulesPanel = new JPanel(new BorderLayout(0, 3));
        rulesPanel.setBorder(BorderFactory.createTitledBorder("Custom Detection Rules"));
        JLabel rulesHint = new JLabel("Format: regex=LABEL   (one per line, # = comment)");
        rulesHint.setFont(new Font("SansSerif", Font.ITALIC, 11));
        rulesHint.setForeground(ThemeColors.dimText());
        rulesHint.setBorder(BorderFactory.createEmptyBorder(2, 3, 2, 3));
        ctx.txtDetectRules = new JTextArea(5, 20);
        ctx.txtDetectRules.setFont(new Font("Monospaced", Font.PLAIN, 11));
        ctx.txtDetectRules.setText("# Examples:\n# admin.*panel=ADMIN_PANEL\n# Bearer\\s+[A-Za-z0-9]+\\.=JWT_TOKEN");
        rulesPanel.add(rulesHint, BorderLayout.NORTH);
        rulesPanel.add(new JScrollPane(ctx.txtDetectRules), BorderLayout.CENTER);
        topPanel.add(rulesPanel);

        topWrap.add(opsecWrap, BorderLayout.NORTH);
        topWrap.add(topPanel, BorderLayout.CENTER);
        panel.add(topWrap, BorderLayout.NORTH);

        // Scan History
        JPanel historyPanel = new JPanel(new BorderLayout(0, 3));
        historyPanel.setBorder(BorderFactory.createTitledBorder("Scan History (current session)"));

        ctx.historyModel = new DefaultTableModel(
                new Object[]{"#", "Type", "Target URL", "Timestamp", "Payloads", "Interesting", "Bypasses", "Baseline"}, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
            @Override public Class<?> getColumnClass(int c) {
                return (c == 0 || c == 4 || c == 5 || c == 6 || c == 7) ? Integer.class : String.class;
            }
        };
        JTable historyTable = new JTable(ctx.historyModel);
        historyTable.setAutoCreateRowSorter(true);
        historyTable.setFillsViewportHeight(true);
        historyTable.getColumnModel().getColumn(2).setPreferredWidth(300);

        JPanel histCtrl = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton btnClearHistory = new JButton("Clear History");
        btnClearHistory.addActionListener(e -> ctx.historyModel.setRowCount(0));
        histCtrl.add(btnClearHistory);
        histCtrl.add(new JLabel("  History is in-memory and cleared on Burp restart."));

        historyPanel.add(histCtrl, BorderLayout.NORTH);
        historyPanel.add(new JScrollPane(historyTable), BorderLayout.CENTER);
        panel.add(historyPanel, BorderLayout.CENTER);

        return panel;
    }

    public static void load(ExtensionContext ctx) {
        try {
            burp.api.montoya.persistence.Preferences prefs = ctx.api.persistence().preferences();

            Integer dl = prefs.getInteger("acf.delay");
            if (dl == null) dl = prefs.getInteger("acf.path.delay");   // migrate legacy per-engine key
            if (dl != null) ctx.spinDelay.setValue(dl);

            Boolean v;
            v = prefs.getBoolean("acf.hdr.ip");         if (v != null) ctx.chkHeaderIP.setSelected(v);
            v = prefs.getBoolean("acf.hdr.method");     if (v != null) ctx.chkHeaderMethod.setSelected(v);
            v = prefs.getBoolean("acf.hdr.rewrite");    if (v != null) ctx.chkHeaderRewrite.setSelected(v);

            v = prefs.getBoolean("acf.path.rewrite");   if (v != null) ctx.chkPathRewrite.setSelected(v);
            v = prefs.getBoolean("acf.path.norm");      if (v != null) ctx.chkPathNorm.setSelected(v);
            v = prefs.getBoolean("acf.path.adv");       if (v != null) ctx.chkPathAdvanced.setSelected(v);
            v = prefs.getBoolean("acf.path.delim");     if (v != null) ctx.chkPathDelimiter.setSelected(v);
            v = prefs.getBoolean("acf.path.delimext");  if (v != null) ctx.chkPathDelimExt.setSelected(v);
            v = prefs.getBoolean("acf.path.normdisc");  if (v != null) ctx.chkPathNormDisc.setSelected(v);
            v = prefs.getBoolean("acf.path.cachecombo"); if (v != null) ctx.chkPathCacheCombo.setSelected(v);
            v = prefs.getBoolean("acf.path.fatget");    if (v != null) ctx.chkPathFatGet.setSelected(v);

            v = prefs.getBoolean("acf.sel.url");        if (v != null) ctx.chkSelUrl.setSelected(v);
            v = prefs.getBoolean("acf.sel.doubleurl");  if (v != null) ctx.chkSelDoubleUrl.setSelected(v);
            v = prefs.getBoolean("acf.sel.iis");        if (v != null) ctx.chkSelIis.setSelected(v);
            v = prefs.getBoolean("acf.sel.utf");        if (v != null) ctx.chkSelUtf.setSelected(v);

            String s;
            s = prefs.getString("acf.delim.suffix"); if (s != null) ctx.txtDelimSuffix.setText(s);
            s = prefs.getString("acf.cache.prefix"); if (s != null) ctx.txtCachePrefix.setText(s);
            s = prefs.getString("acf.hdr.ips");      if (s != null) ctx.txtHeaderIPs.setText(s);
            s = prefs.getString("acf.hdr.headers");  if (s != null) ctx.txtHeaderHeaders.setText(s);
            s = prefs.getString("acf.path.paths");   if (s != null) ctx.txtPathPaths.setText(s);
            s = prefs.getString("acf.sel.custom");   if (s != null) ctx.txtSelCustom.setText(s);
            s = prefs.getString("acf.detect.rules"); if (s != null) ctx.txtDetectRules.setText(s);

            Integer wt = prefs.getInteger("acf.waf.threshold");    if (wt != null) ctx.spinWafThreshold.setValue(wt);
            Integer pt = prefs.getInteger("acf.parallel.threads"); if (pt != null) ctx.spinParallelThreads.setValue(pt);
            v = prefs.getBoolean("acf.parallel"); if (v != null) ctx.chkParallelMode.setSelected(v);

            Integer ci = prefs.getInteger("acf.cdnprofile");
            if (ci != null && ci >= 0 && ci < ctx.cmbCdnProfile.getItemCount()) ctx.cmbCdnProfile.setSelectedIndex(ci);

        } catch (Exception ex) {
            ctx.api.logging().logToError("[ACF] Settings load error: " + ex.getMessage());
        }
    }

    public static void save(ExtensionContext ctx) {
        try {
            burp.api.montoya.persistence.Preferences prefs = ctx.api.persistence().preferences();

            prefs.setInteger("acf.delay", (int) ctx.spinDelay.getValue());

            prefs.setBoolean("acf.hdr.ip",      ctx.chkHeaderIP.isSelected());
            prefs.setBoolean("acf.hdr.method",  ctx.chkHeaderMethod.isSelected());
            prefs.setBoolean("acf.hdr.rewrite", ctx.chkHeaderRewrite.isSelected());

            prefs.setBoolean("acf.path.rewrite",    ctx.chkPathRewrite.isSelected());
            prefs.setBoolean("acf.path.norm",        ctx.chkPathNorm.isSelected());
            prefs.setBoolean("acf.path.adv",         ctx.chkPathAdvanced.isSelected());
            prefs.setBoolean("acf.path.delim",       ctx.chkPathDelimiter.isSelected());
            prefs.setBoolean("acf.path.delimext",    ctx.chkPathDelimExt.isSelected());
            prefs.setBoolean("acf.path.normdisc",    ctx.chkPathNormDisc.isSelected());
            prefs.setBoolean("acf.path.cachecombo",  ctx.chkPathCacheCombo.isSelected());
            prefs.setBoolean("acf.path.fatget",      ctx.chkPathFatGet.isSelected());

            prefs.setBoolean("acf.sel.url",       ctx.chkSelUrl.isSelected());
            prefs.setBoolean("acf.sel.doubleurl", ctx.chkSelDoubleUrl.isSelected());
            prefs.setBoolean("acf.sel.iis",       ctx.chkSelIis.isSelected());
            prefs.setBoolean("acf.sel.utf",       ctx.chkSelUtf.isSelected());

            prefs.setString("acf.delim.suffix", ctx.txtDelimSuffix.getText());
            prefs.setString("acf.cache.prefix", ctx.txtCachePrefix.getText());
            prefs.setString("acf.hdr.ips",      ctx.txtHeaderIPs.getText());
            prefs.setString("acf.hdr.headers",  ctx.txtHeaderHeaders.getText());
            prefs.setString("acf.path.paths",   ctx.txtPathPaths.getText());
            prefs.setString("acf.sel.custom",   ctx.txtSelCustom.getText());
            prefs.setString("acf.detect.rules", ctx.txtDetectRules.getText());

            prefs.setInteger("acf.waf.threshold",    (int) ctx.spinWafThreshold.getValue());
            prefs.setBoolean("acf.parallel",          ctx.chkParallelMode.isSelected());
            prefs.setInteger("acf.parallel.threads",  (int) ctx.spinParallelThreads.getValue());
            prefs.setInteger("acf.cdnprofile",        ctx.cmbCdnProfile.getSelectedIndex());

        } catch (Exception ex) {
            ctx.api.logging().logToError("[ACF] Settings save error: " + ex.getMessage());
        }
    }
}
