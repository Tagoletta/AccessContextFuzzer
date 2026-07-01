package burp.ui;

import burp.core.ExtensionContext;
import burp.core.FuzzerEngine;
import burp.core.ScanEngine;

import javax.swing.*;
import java.awt.*;

public class HeaderEngineTab {

    private HeaderEngineTab() {}

    public static JPanel build(ExtensionContext ctx, ScanEngine scanEngine) {
        FuzzerEngine engine = new FuzzerEngine();
        engine.engineType = "Header";
        ctx.headerEngine = engine;

        engine.mainPanel = new JPanel(new BorderLayout());
        JPanel settingsPanel = new JPanel();
        settingsPanel.setLayout(new BoxLayout(settingsPanel, BoxLayout.Y_AXIS));
        settingsPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JPanel togglePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        togglePanel.setBorder(BorderFactory.createTitledBorder("Built-in Payloads"));
        ctx.chkHeaderIP = new JCheckBox("Enable IP/Host Spoofing", true);
        ctx.chkHeaderMethod = new JCheckBox("Enable Method Override", true);
        ctx.chkHeaderRewrite = new JCheckBox("Enable URL Rewrite Override", true);
        togglePanel.add(ctx.chkHeaderIP);
        togglePanel.add(ctx.chkHeaderMethod);
        togglePanel.add(ctx.chkHeaderRewrite);
        settingsPanel.add(togglePanel);

        JPanel presetPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        presetPanel.setBorder(BorderFactory.createTitledBorder("Scan Profiles"));
        JButton btnHdrQuick = new JButton("⚡ Quick Scan");
        btnHdrQuick.setToolTipText("Only IP/Host Spoofing");
        btnHdrQuick.addActionListener(e -> {
            ctx.chkHeaderIP.setSelected(true);
            ctx.chkHeaderMethod.setSelected(false);
            ctx.chkHeaderRewrite.setSelected(false);
        });
        JButton btnHdrFull = new JButton("🔥 Full Scan");
        btnHdrFull.setToolTipText("All payloads enabled");
        btnHdrFull.addActionListener(e -> {
            ctx.chkHeaderIP.setSelected(true);
            ctx.chkHeaderMethod.setSelected(true);
            ctx.chkHeaderRewrite.setSelected(true);
        });
        presetPanel.add(btnHdrQuick);
        presetPanel.add(btnHdrFull);
        settingsPanel.add(presetPanel);

        JPanel customPanel = new JPanel(new GridLayout(1, 2, 10, 0));
        ctx.txtHeaderIPs = new JTextArea(4, 20);
        ctx.txtHeaderHeaders = new JTextArea(4, 20);
        customPanel.add(ResultsPanel.createTextAreaPanel("Custom IPs:", ctx.txtHeaderIPs));
        customPanel.add(ResultsPanel.createTextAreaPanel("Custom Headers:", ctx.txtHeaderHeaders));
        settingsPanel.add(customPanel);

        settingsPanel.setMinimumSize(new Dimension(600, 320));
        settingsPanel.setPreferredSize(new Dimension(600, 320));

        JPanel resultsPanel = ResultsPanel.build(ctx, engine, scanEngine, "Header");
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, settingsPanel, resultsPanel);
        splitPane.setDividerLocation(320);
        engine.mainPanel.add(splitPane, BorderLayout.CENTER);
        return engine.mainPanel;
    }
}
