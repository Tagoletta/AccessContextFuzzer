package burp.ui;

import burp.core.ExtensionContext;
import burp.core.FuzzerEngine;
import burp.core.ScanEngine;

import burp.util.ThemeColors;

import javax.swing.*;
import java.awt.*;
import java.nio.file.Files;
import java.nio.charset.StandardCharsets;

public class SelectionEngineTab {

    private SelectionEngineTab() {}

    public static JPanel build(ExtensionContext ctx, ScanEngine scanEngine) {
        FuzzerEngine engine = new FuzzerEngine();
        engine.engineType = "Selection";
        ctx.selectionEngine = engine;

        engine.mainPanel = new JPanel(new BorderLayout());
        JPanel settingsPanel = new JPanel();
        settingsPanel.setLayout(new BoxLayout(settingsPanel, BoxLayout.Y_AXIS));
        settingsPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        ctx.lblCurrentIpSel = new JLabel(" Status: Not checked.");
        ctx.spinSelDelay = new JSpinner(new SpinnerNumberModel(20, 0, 60000, 10));
        settingsPanel.add(buildOpsecPanel(ctx.lblCurrentIpSel, ctx.spinSelDelay, scanEngine));

        JPanel togglePanel = new JPanel(new GridLayout(2, 2, 5, 5));
        togglePanel.setBorder(BorderFactory.createTitledBorder("Selected Text Encoders"));
        ctx.chkSelUrl = new JCheckBox("URL Encode", true);
        ctx.chkSelDoubleUrl = new JCheckBox("Double URL Encode", true);
        ctx.chkSelIis = new JCheckBox("IIS Unicode Encode", true);
        ctx.chkSelUtf = new JCheckBox("UTF-8 Fullwidth Slash", true);
        togglePanel.add(ctx.chkSelUrl);
        togglePanel.add(ctx.chkSelDoubleUrl);
        togglePanel.add(ctx.chkSelIis);
        togglePanel.add(ctx.chkSelUtf);
        settingsPanel.add(togglePanel);

        ctx.txtSelCustom = new JTextArea(4, 30);
        settingsPanel.add(createTextAreaPanel("Custom Payloads for Selection:", ctx.txtSelCustom));

        settingsPanel.setMinimumSize(new Dimension(600, 300));
        settingsPanel.setPreferredSize(new Dimension(600, 300));

        JPanel resultsPanel = ResultsPanel.build(ctx, engine, scanEngine, "Selection");
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, settingsPanel, resultsPanel);
        splitPane.setDividerLocation(300);
        engine.mainPanel.add(splitPane, BorderLayout.CENTER);
        return engine.mainPanel;
    }

    private static JPanel buildOpsecPanel(JLabel ipLabel, JSpinner delaySpinner, ScanEngine scanEngine) {
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
