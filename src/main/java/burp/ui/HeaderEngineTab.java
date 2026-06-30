package burp.ui;

import burp.core.ExtensionContext;
import burp.core.FuzzerEngine;
import burp.core.ScanEngine;

import burp.util.ThemeColors;

import javax.swing.*;
import java.awt.*;
import java.nio.file.Files;
import java.nio.charset.StandardCharsets;

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

        ctx.lblCurrentIpHeader = new JLabel(" Status: Not checked.");
        ctx.spinHeaderDelay = new JSpinner(new SpinnerNumberModel(20, 0, 60000, 10));
        settingsPanel.add(buildOpsecPanel(ctx, ctx.lblCurrentIpHeader, ctx.spinHeaderDelay, scanEngine));

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
        customPanel.add(createTextAreaPanel("Custom IPs:", ctx.txtHeaderIPs));
        customPanel.add(createTextAreaPanel("Custom Headers:", ctx.txtHeaderHeaders));
        settingsPanel.add(customPanel);

        settingsPanel.setMinimumSize(new Dimension(600, 320));
        settingsPanel.setPreferredSize(new Dimension(600, 320));

        JPanel resultsPanel = ResultsPanel.build(ctx, engine, scanEngine, "Header");
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, settingsPanel, resultsPanel);
        splitPane.setDividerLocation(320);
        engine.mainPanel.add(splitPane, BorderLayout.CENTER);
        return engine.mainPanel;
    }

    private static JPanel buildOpsecPanel(ExtensionContext ctx, JLabel ipLabel, JSpinner delaySpinner, ScanEngine scanEngine) {
        JPanel panel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        panel.setBorder(BorderFactory.createTitledBorder("OPSEC & Network"));
        JButton btnCheckIp = new JButton("Check External IP");
        ipLabel.setFont(new Font("Monospaced", Font.BOLD, 12));
        btnCheckIp.addActionListener(e -> scanEngine.checkExternalIp(ipLabel));
        panel.add(btnCheckIp);
        panel.add(ipLabel);
        panel.add(new JLabel("  |  Delay (ms): "));
        panel.add(delaySpinner);
        return panel;
    }

    private static JPanel createTextAreaPanel(String title, JTextArea textArea) {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder(title));
        panel.add(new JScrollPane(textArea), BorderLayout.CENTER);
        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        JButton btnLoad = new JButton("📂 Load File");
        JButton btnClear = new JButton("✕ Clear");
        JLabel lblInfo = new JLabel();
        lblInfo.setFont(new Font("SansSerif", Font.ITALIC, 11));
        lblInfo.setForeground(ThemeColors.dimText());
        btnLoad.addActionListener(e -> {
            JFileChooser fc = new JFileChooser();
            fc.setDialogTitle("Select wordlist / payload file");
            fc.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("Text files", "txt", "lst", "csv", "list"));
            if (fc.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
                try {
                    java.util.List<String> lines = Files.readAllLines(fc.getSelectedFile().toPath(), StandardCharsets.UTF_8);
                    String existing = textArea.getText().trim();
                    if (!existing.isEmpty())
                        textArea.setText(existing + "\n" + String.join("\n", lines));
                    else
                        textArea.setText(String.join("\n", lines));
                    lblInfo.setText(lines.size() + " lines loaded from " + fc.getSelectedFile().getName());
                } catch (Exception ex) {
                    lblInfo.setText("Error: " + ex.getMessage());
                }
            }
        });
        btnClear.addActionListener(e -> { textArea.setText(""); lblInfo.setText("Cleared."); });
        btnPanel.add(btnLoad);
        btnPanel.add(btnClear);
        btnPanel.add(lblInfo);
        panel.add(btnPanel, BorderLayout.SOUTH);
        return panel;
    }
}
