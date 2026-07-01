package burp.core;

import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.ExecutorService;

public class ExtensionContext {

    public static final String VERSION = "2.4.0";
    public static final DateTimeFormatter TS_FMT = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm");

    public final MontoyaApi api;
    public final JTabbedPane mainTabs;
    public final ExecutorService taskExecutor;

    // Engines
    public FuzzerEngine headerEngine, pathEngine, selectionEngine;

    // OPSEC & Network (shared, lives in Settings)
    public JSpinner spinDelay;
    public JLabel lblCurrentIp;

    // Header controls
    public JCheckBox chkHeaderIP, chkHeaderMethod, chkHeaderRewrite;
    public JTextArea txtHeaderIPs, txtHeaderHeaders;

    // Path controls
    public JCheckBox chkPathRewrite, chkPathNorm, chkPathAdvanced;
    public JCheckBox chkPathDelimiter, chkPathDelimExt, chkPathNormDisc, chkPathCacheCombo, chkPathFatGet;
    public JTextField txtDelimSuffix, txtCachePrefix;
    public JTextArea txtPathPaths;
    public JComboBox<String> cmbCdnProfile;

    // Selection controls
    public JCheckBox chkSelUrl, chkSelDoubleUrl, chkSelIis, chkSelUtf;
    public JTextArea txtSelCustom;

    // Global settings
    public JSpinner spinWafThreshold, spinParallelThreads;
    public JCheckBox chkParallelMode;
    public JTextArea txtDetectRules;

    // History model
    public DefaultTableModel historyModel;

    // WCD Findings tab
    public DefaultTableModel wcdFindingsModel;
    public final java.util.Map<Integer, burp.api.montoya.http.message.HttpRequestResponse> wcdFindingsHistory
            = new java.util.concurrent.ConcurrentHashMap<>();
    public final java.util.concurrent.atomic.AtomicInteger wcdFindingsSeq = new java.util.concurrent.atomic.AtomicInteger(0);

    public ExtensionContext(MontoyaApi api, JTabbedPane mainTabs, ExecutorService taskExecutor) {
        this.api = api;
        this.mainTabs = mainTabs;
        this.taskExecutor = taskExecutor;
    }
}
