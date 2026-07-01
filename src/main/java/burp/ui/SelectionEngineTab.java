package burp.ui;

import burp.core.ExtensionContext;
import burp.core.FuzzerEngine;
import burp.core.ScanEngine;

import javax.swing.*;
import java.awt.*;

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
        settingsPanel.add(ResultsPanel.createTextAreaPanel("Custom Payloads for Selection:", ctx.txtSelCustom));

        settingsPanel.setMinimumSize(new Dimension(600, 300));
        settingsPanel.setPreferredSize(new Dimension(600, 300));

        JPanel resultsPanel = ResultsPanel.build(ctx, engine, scanEngine, "Selection");
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, settingsPanel, resultsPanel);
        splitPane.setDividerLocation(300);
        engine.mainPanel.add(splitPane, BorderLayout.CENTER);
        return engine.mainPanel;
    }
}
