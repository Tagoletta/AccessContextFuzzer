package burp.ui;

import burp.core.ExtensionContext;
import burp.core.FuzzerEngine;
import burp.core.ScanEngine;

import javax.swing.*;
import java.awt.*;

public class PathEngineTab {

    private PathEngineTab() {}

    public static JPanel build(ExtensionContext ctx, ScanEngine scanEngine) {
        FuzzerEngine engine = new FuzzerEngine();
        engine.engineType = "Path";
        ctx.pathEngine = engine;

        engine.mainPanel = new JPanel(new BorderLayout());
        JPanel settingsPanel = new JPanel();
        settingsPanel.setLayout(new BoxLayout(settingsPanel, BoxLayout.Y_AXIS));
        settingsPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        ctx.lblCurrentIpPath = new JLabel(" Status: Not checked.");
        ctx.spinPathDelay = new JSpinner(new SpinnerNumberModel(20, 0, 60000, 10));
        settingsPanel.add(ResultsPanel.buildOpsecPanel(ctx, ctx.lblCurrentIpPath, ctx.spinPathDelay, scanEngine));

        JPanel togglePanel = new JPanel(new GridLayout(2, 4, 5, 5));
        togglePanel.setBorder(BorderFactory.createTitledBorder("Built-in Payloads"));
        ctx.chkPathRewrite = new JCheckBox("Rewrite Tricks", true);
        ctx.chkPathNorm = new JCheckBox("Path Normalization", true);
        ctx.chkPathAdvanced = new JCheckBox("Advanced Encoders", true);
        ctx.chkPathDelimiter = new JCheckBox("Delimiter Fuzzing", true);
        ctx.chkPathDelimExt = new JCheckBox("Delimiter + Extension", true);
        ctx.chkPathNormDisc = new JCheckBox("Normalization Discrepancy", true);
        ctx.chkPathCacheCombo = new JCheckBox("Cache Deception Combos", true);
        ctx.chkPathFatGet = new JCheckBox("Fat GET Test", false);
        ctx.chkPathFatGet.setToolTipText("Send GET with body — CDNs often cache the path and ignore the body (WCD vector)");
        togglePanel.add(ctx.chkPathRewrite);
        togglePanel.add(ctx.chkPathNorm);
        togglePanel.add(ctx.chkPathAdvanced);
        togglePanel.add(ctx.chkPathDelimiter);
        togglePanel.add(ctx.chkPathDelimExt);
        togglePanel.add(ctx.chkPathNormDisc);
        togglePanel.add(ctx.chkPathCacheCombo);
        togglePanel.add(ctx.chkPathFatGet);
        settingsPanel.add(togglePanel);

        JPanel presetPathPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        presetPathPanel.setBorder(BorderFactory.createTitledBorder("Scan Profiles"));
        JButton btnPathQuick = new JButton("⚡ Quick Scan");
        btnPathQuick.setToolTipText("Only Path Normalization + Rewrite");
        btnPathQuick.addActionListener(e -> {
            ctx.chkPathRewrite.setSelected(true);
            ctx.chkPathNorm.setSelected(true);
            ctx.chkPathAdvanced.setSelected(false);
            ctx.chkPathDelimiter.setSelected(false);
            ctx.chkPathDelimExt.setSelected(false);
            ctx.chkPathNormDisc.setSelected(false);
            ctx.chkPathCacheCombo.setSelected(false);
        });
        JButton btnPathWcd = new JButton("🎯 WCD Only");
        btnPathWcd.setToolTipText("Only Web Cache Deception payloads");
        btnPathWcd.addActionListener(e -> {
            ctx.chkPathRewrite.setSelected(false);
            ctx.chkPathNorm.setSelected(false);
            ctx.chkPathAdvanced.setSelected(false);
            ctx.chkPathDelimiter.setSelected(true);
            ctx.chkPathDelimExt.setSelected(true);
            ctx.chkPathNormDisc.setSelected(true);
            ctx.chkPathCacheCombo.setSelected(true);
        });
        JButton btnPathFull = new JButton("🔥 Full Scan");
        btnPathFull.setToolTipText("All payloads enabled");
        btnPathFull.addActionListener(e -> {
            ctx.chkPathRewrite.setSelected(true);
            ctx.chkPathNorm.setSelected(true);
            ctx.chkPathAdvanced.setSelected(true);
            ctx.chkPathDelimiter.setSelected(true);
            ctx.chkPathDelimExt.setSelected(true);
            ctx.chkPathNormDisc.setSelected(true);
            ctx.chkPathCacheCombo.setSelected(true);
        });
        presetPathPanel.add(btnPathQuick);
        presetPathPanel.add(btnPathWcd);
        presetPathPanel.add(btnPathFull);
        settingsPanel.add(presetPathPanel);

        JPanel wcdPanel = new JPanel(new GridLayout(3, 1, 5, 5));
        wcdPanel.setBorder(BorderFactory.createTitledBorder("Web Cache Deception Settings"));
        JPanel row1 = new JPanel(new FlowLayout(FlowLayout.LEFT));
        row1.add(new JLabel("Delimiter suffix: "));
        ctx.txtDelimSuffix = new JTextField("abc", 10);
        row1.add(ctx.txtDelimSuffix);
        row1.add(new JLabel("  (e.g. /path{DELIM}abc)"));
        wcdPanel.add(row1);
        JPanel row2 = new JPanel(new FlowLayout(FlowLayout.LEFT));
        row2.add(new JLabel("Cache directory prefix: "));
        ctx.txtCachePrefix = new JTextField("/resources", 15);
        row2.add(ctx.txtCachePrefix);
        row2.add(new JLabel("  (for normalization & combo attacks)"));
        wcdPanel.add(row2);
        JPanel row3 = new JPanel(new FlowLayout(FlowLayout.LEFT));
        row3.add(new JLabel("CDN Profile: "));
        ctx.cmbCdnProfile = new JComboBox<>(new String[]{"Auto", "Cloudflare", "Akamai", "Fastly", "CloudFront", "Nginx", "Varnish"});
        ctx.cmbCdnProfile.setToolTipText("Select CDN for profile-specific payload variants (Auto = generic delimiter set)");
        row3.add(ctx.cmbCdnProfile);
        row3.add(new JLabel("  Auto = generic set, specific = CDN-tuned payloads added"));
        wcdPanel.add(row3);
        settingsPanel.add(wcdPanel);

        ctx.txtPathPaths = new JTextArea(3, 30);
        settingsPanel.add(ResultsPanel.createTextAreaPanel("Custom Paths:", ctx.txtPathPaths));

        settingsPanel.setMinimumSize(new Dimension(600, 420));
        settingsPanel.setPreferredSize(new Dimension(600, 420));

        JPanel resultsPanel = ResultsPanel.build(ctx, engine, scanEngine, "Path");
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, settingsPanel, resultsPanel);
        splitPane.setDividerLocation(420);
        engine.mainPanel.add(splitPane, BorderLayout.CENTER);
        return engine.mainPanel;
    }
}
