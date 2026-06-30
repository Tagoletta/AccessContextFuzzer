package burp.core;

import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.ExecutorService;

public class ExtensionContext {

    public static final String VERSION = "2.3.0";
    public static final DateTimeFormatter TS_FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm");

    public final MontoyaApi api;
    public final JTabbedPane mainTabs;
    public final ExecutorService taskExecutor;

    // Engines
    public FuzzerEngine headerEngine, pathEngine, selectionEngine;

    // Header controls
    public JSpinner spinHeaderDelay;
    public JCheckBox chkHeaderIP, chkHeaderMethod, chkHeaderRewrite;
    public JTextArea txtHeaderIPs, txtHeaderHeaders;

    // Path controls
    public JSpinner spinPathDelay;
    public JCheckBox chkPathRewrite, chkPathNorm, chkPathAdvanced;
    public JCheckBox chkPathDelimiter, chkPathDelimExt, chkPathNormDisc, chkPathCacheCombo, chkPathFatGet;
    public JTextField txtDelimSuffix, txtCachePrefix;
    public JTextArea txtPathPaths;
    public JComboBox<String> cmbCdnProfile;

    // Selection controls
    public JSpinner spinSelDelay;
    public JCheckBox chkSelUrl, chkSelDoubleUrl, chkSelIis, chkSelUtf;
    public JTextArea txtSelCustom;

    // OPSEC labels
    public JLabel lblCurrentIpHeader, lblCurrentIpPath, lblCurrentIpSel;

    // Global settings
    public JSpinner spinWafThreshold, spinParallelThreads;
    public JCheckBox chkParallelMode;
    public JTextArea txtDetectRules;

    // History model
    public DefaultTableModel historyModel;

    public ExtensionContext(MontoyaApi api, JTabbedPane mainTabs, ExecutorService taskExecutor) {
        this.api = api;
        this.mainTabs = mainTabs;
        this.taskExecutor = taskExecutor;
    }
}
