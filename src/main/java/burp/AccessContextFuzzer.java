package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.File;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class AccessContextFuzzer implements BurpExtension, ContextMenuItemsProvider {

    private MontoyaApi api;
    private JTabbedPane mainTabs;
    private FuzzerEngine headerEngine;
    private FuzzerEngine pathEngine;
    private FuzzerEngine selectionEngine;

    private JSpinner spinHeaderDelay;
    private JCheckBox chkHeaderIP;
    private JCheckBox chkHeaderMethod;
    private JCheckBox chkHeaderRewrite;
    private JTextArea txtHeaderIPs;
    private JTextArea txtHeaderHeaders;

    private JSpinner spinPathDelay;
    private JCheckBox chkPathRewrite;
    private JCheckBox chkPathNorm;
    private JCheckBox chkPathAdvanced;
    private JCheckBox chkPathDelimiter;
    private JCheckBox chkPathDelimExt;
    private JCheckBox chkPathNormDisc;
    private JCheckBox chkPathCacheCombo;
    private JTextField txtDelimSuffix;
    private JTextField txtCachePrefix;
    private JTextArea txtPathPaths;

    private JSpinner spinSelDelay;
    private JCheckBox chkSelUrl;
    private JCheckBox chkSelDoubleUrl;
    private JCheckBox chkSelIis;
    private JCheckBox chkSelUtf;
    private JTextArea txtSelCustom;

    private JLabel lblCurrentIpHeader;
    private JLabel lblCurrentIpPath;
    private JLabel lblCurrentIpSel;

    private class FuzzerEngine {
        JPanel mainPanel;
        DefaultTableModel model;
        JTable table;
        JProgressBar progressBar;
        JButton btnStop;
        JButton btnExport;
        JButton btnRerun;
        AtomicBoolean isRunning = new AtomicBoolean(false);
        Map<Integer, HttpRequestResponse> requestHistory = new ConcurrentHashMap<>();
        volatile HttpRequestResponse lastRequest;
        volatile int[] lastSelectionRange;
        String engineType;
    }

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Access Context Fuzzer");
        mainTabs = new JTabbedPane();
        headerEngine = buildHeaderEngine();
        pathEngine = buildPathEngine();
        selectionEngine = buildSelectionEngine();
        mainTabs.addTab("Header Bypass", headerEngine.mainPanel);
        mainTabs.addTab("Path / GET Bypass", pathEngine.mainPanel);
        mainTabs.addTab("Selection Fuzz", selectionEngine.mainPanel);
        api.userInterface().registerSuiteTab("Access Context", mainTabs);
        api.userInterface().registerContextMenuItemsProvider(this);
    }

    private FuzzerEngine buildHeaderEngine() {
        FuzzerEngine engine = new FuzzerEngine();
        engine.engineType = "Header";
        engine.mainPanel = new JPanel(new BorderLayout());
        JPanel settingsPanel = new JPanel();
        settingsPanel.setLayout(new BoxLayout(settingsPanel, BoxLayout.Y_AXIS));
        settingsPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        JPanel networkPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        networkPanel.setBorder(BorderFactory.createTitledBorder("OPSEC & Network"));
        JButton btnCheckIp = new JButton("Check External IP");
        lblCurrentIpHeader = new JLabel(" Status: Not checked.");
        lblCurrentIpHeader.setFont(new Font("Monospaced", Font.BOLD, 12));
        btnCheckIp.addActionListener(e -> checkExternalIp(lblCurrentIpHeader));
        networkPanel.add(btnCheckIp);
        networkPanel.add(lblCurrentIpHeader);
        networkPanel.add(new JLabel("  |  Delay (ms): "));
        spinHeaderDelay = new JSpinner(new SpinnerNumberModel(20, 0, 60000, 10));
        networkPanel.add(spinHeaderDelay);
        settingsPanel.add(networkPanel);
        JPanel togglePanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        togglePanel.setBorder(BorderFactory.createTitledBorder("Built-in Payloads"));
        chkHeaderIP = new JCheckBox("Enable IP/Host Spoofing", true);
        chkHeaderMethod = new JCheckBox("Enable Method Override", true);
        chkHeaderRewrite = new JCheckBox("Enable URL Rewrite Override", true);
        togglePanel.add(chkHeaderIP);
        togglePanel.add(chkHeaderMethod);
        togglePanel.add(chkHeaderRewrite);
        settingsPanel.add(togglePanel);
        JPanel customPanel = new JPanel(new GridLayout(1, 2, 10, 0));
        customPanel.add(createTextAreaPanel("Custom IPs:", txtHeaderIPs = new JTextArea(4, 20)));
        customPanel.add(createTextAreaPanel("Custom Headers:", txtHeaderHeaders = new JTextArea(4, 20)));
        settingsPanel.add(customPanel);
        JPanel resultsPanel = buildResultsPanel(engine, "Header");
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, settingsPanel, resultsPanel);
        splitPane.setDividerLocation(250);
        engine.mainPanel.add(splitPane, BorderLayout.CENTER);
        return engine;
    }

    private FuzzerEngine buildPathEngine() {
        FuzzerEngine engine = new FuzzerEngine();
        engine.engineType = "Path";
        engine.mainPanel = new JPanel(new BorderLayout());
        JPanel settingsPanel = new JPanel();
        settingsPanel.setLayout(new BoxLayout(settingsPanel, BoxLayout.Y_AXIS));
        settingsPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        JPanel networkPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        networkPanel.setBorder(BorderFactory.createTitledBorder("OPSEC & Network"));
        JButton btnCheckIp = new JButton("Check External IP");
        lblCurrentIpPath = new JLabel(" Status: Not checked.");
        lblCurrentIpPath.setFont(new Font("Monospaced", Font.BOLD, 12));
        btnCheckIp.addActionListener(e -> checkExternalIp(lblCurrentIpPath));
        networkPanel.add(btnCheckIp);
        networkPanel.add(lblCurrentIpPath);
        networkPanel.add(new JLabel("  |  Delay (ms): "));
        spinPathDelay = new JSpinner(new SpinnerNumberModel(20, 0, 60000, 10));
        networkPanel.add(spinPathDelay);
        settingsPanel.add(networkPanel);
        JPanel togglePanel = new JPanel(new GridLayout(2, 4, 5, 5));
        togglePanel.setBorder(BorderFactory.createTitledBorder("Built-in Payloads"));
        chkPathRewrite = new JCheckBox("Rewrite Tricks", true);
        chkPathNorm = new JCheckBox("Path Normalization", true);
        chkPathAdvanced = new JCheckBox("Advanced Encoders", true);
        chkPathDelimiter = new JCheckBox("Delimiter Fuzzing", true);
        chkPathDelimExt = new JCheckBox("Delimiter + Extension", true);
        chkPathNormDisc = new JCheckBox("Normalization Discrepancy", true);
        chkPathCacheCombo = new JCheckBox("Cache Deception Combos", true);
        togglePanel.add(chkPathRewrite);
        togglePanel.add(chkPathNorm);
        togglePanel.add(chkPathAdvanced);
        togglePanel.add(chkPathDelimiter);
        togglePanel.add(chkPathDelimExt);
        togglePanel.add(chkPathNormDisc);
        togglePanel.add(chkPathCacheCombo);
        settingsPanel.add(togglePanel);
        JPanel wcdPanel = new JPanel(new GridLayout(2, 1, 5, 5));
        wcdPanel.setBorder(BorderFactory.createTitledBorder("Web Cache Deception Settings"));
        JPanel row1 = new JPanel(new FlowLayout(FlowLayout.LEFT));
        row1.add(new JLabel("Delimiter suffix: "));
        txtDelimSuffix = new JTextField("abc", 10);
        row1.add(txtDelimSuffix);
        row1.add(new JLabel("  (e.g. /path{DELIM}abc)"));
        wcdPanel.add(row1);
        JPanel row2 = new JPanel(new FlowLayout(FlowLayout.LEFT));
        row2.add(new JLabel("Cache directory prefix: "));
        txtCachePrefix = new JTextField("/resources", 15);
        row2.add(txtCachePrefix);
        row2.add(new JLabel("  (for normalization & combo attacks)"));
        wcdPanel.add(row2);
        settingsPanel.add(wcdPanel);
        settingsPanel.add(createTextAreaPanel("Custom Paths:", txtPathPaths = new JTextArea(3, 30)));
        JPanel resultsPanel = buildResultsPanel(engine, "Path");
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, settingsPanel, resultsPanel);
        splitPane.setDividerLocation(310);
        engine.mainPanel.add(splitPane, BorderLayout.CENTER);
        return engine;
    }

    private FuzzerEngine buildSelectionEngine() {
        FuzzerEngine engine = new FuzzerEngine();
        engine.engineType = "Selection";
        engine.mainPanel = new JPanel(new BorderLayout());
        JPanel settingsPanel = new JPanel();
        settingsPanel.setLayout(new BoxLayout(settingsPanel, BoxLayout.Y_AXIS));
        settingsPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        JPanel networkPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        networkPanel.setBorder(BorderFactory.createTitledBorder("OPSEC & Network"));
        JButton btnCheckIp = new JButton("Check External IP");
        lblCurrentIpSel = new JLabel(" Status: Not checked.");
        lblCurrentIpSel.setFont(new Font("Monospaced", Font.BOLD, 12));
        btnCheckIp.addActionListener(e -> checkExternalIp(lblCurrentIpSel));
        networkPanel.add(btnCheckIp);
        networkPanel.add(lblCurrentIpSel);
        networkPanel.add(new JLabel("  |  Delay (ms): "));
        spinSelDelay = new JSpinner(new SpinnerNumberModel(20, 0, 60000, 10));
        networkPanel.add(spinSelDelay);
        settingsPanel.add(networkPanel);
        JPanel togglePanel = new JPanel(new GridLayout(2, 2, 5, 5));
        togglePanel.setBorder(BorderFactory.createTitledBorder("Selected Text Encoders"));
        chkSelUrl = new JCheckBox("URL Encode", true);
        chkSelDoubleUrl = new JCheckBox("Double URL Encode", true);
        chkSelIis = new JCheckBox("IIS Unicode Encode", true);
        chkSelUtf = new JCheckBox("UTF-8 Fullwidth Slash", true);
        togglePanel.add(chkSelUrl);
        togglePanel.add(chkSelDoubleUrl);
        togglePanel.add(chkSelIis);
        togglePanel.add(chkSelUtf);
        settingsPanel.add(togglePanel);
        settingsPanel.add(createTextAreaPanel("Custom Payloads for Selection:", txtSelCustom = new JTextArea(4, 30)));
        JPanel resultsPanel = buildResultsPanel(engine, "Selection");
        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, settingsPanel, resultsPanel);
        splitPane.setDividerLocation(260);
        engine.mainPanel.add(splitPane, BorderLayout.CENTER);
        return engine;
    }

    private JPanel buildResultsPanel(FuzzerEngine engine, String name) {
        JPanel resultsPanel = new JPanel(new BorderLayout());
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        engine.progressBar = new JProgressBar(0, 100);
        engine.progressBar.setStringPainted(true);
        engine.progressBar.setPreferredSize(new Dimension(300, 25));
        engine.btnStop = new JButton("Stop Fuzzing");
        engine.btnStop.setEnabled(false);
        engine.btnStop.setBackground(new Color(255, 102, 102));
        engine.btnStop.setForeground(Color.WHITE);
        engine.btnExport = new JButton("Export CSV");
        engine.btnRerun = new JButton("\u25B6 Re-run Fuzzing");
        engine.btnRerun.setEnabled(false);
        engine.btnRerun.setBackground(new Color(102, 178, 255));
        engine.btnRerun.setForeground(Color.WHITE);
        controlPanel.add(engine.progressBar);
        controlPanel.add(engine.btnStop);
        controlPanel.add(engine.btnRerun);
        controlPanel.add(engine.btnExport);
        resultsPanel.add(controlPanel, BorderLayout.NORTH);
        engine.model = new DefaultTableModel(
                new Object[] { "#", "Variant", "Status", "Words", "Lines", "Length", "Title", "RTT(ms)", "Notes" }, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }

            @Override
            public Class<?> getColumnClass(int columnIndex) {
                if (columnIndex == 0 || columnIndex == 2 || columnIndex == 3 || columnIndex == 4 || columnIndex == 5
                        || columnIndex == 7)
                    return Integer.class;
                return String.class;
            }
        };
        engine.table = new JTable(engine.model);
        engine.table.setAutoCreateRowSorter(true);
        engine.table.setRowSorter(new TableRowSorter<>(engine.model));
        applySmartRenderer(engine.table, engine.model);
        resultsPanel.add(new JScrollPane(engine.table), BorderLayout.CENTER);
        setupTableEvents(engine, name);
        engine.btnStop.addActionListener(e -> stopEngine(engine, name));
        engine.btnExport.addActionListener(e -> exportToCsv(engine.model, name));
        engine.btnRerun.addActionListener(e -> rerunFuzzing(engine));
        return resultsPanel;
    }

    private JPanel createTextAreaPanel(String title, JTextArea textArea) {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder(title));
        panel.add(new JScrollPane(textArea), BorderLayout.CENTER);
        JPanel btnPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        JButton btnLoad = new JButton("\uD83D\uDCC2 Load File");
        JButton btnClear = new JButton("\u2715 Clear");
        JLabel lblInfo = new JLabel();
        lblInfo.setFont(new Font("SansSerif", Font.ITALIC, 11));
        lblInfo.setForeground(Color.GRAY);
        btnLoad.addActionListener(e -> {
            JFileChooser fc = new JFileChooser();
            fc.setDialogTitle("Select wordlist / payload file");
            fc.setFileFilter(
                    new javax.swing.filechooser.FileNameExtensionFilter("Text files", "txt", "lst", "csv", "list"));
            if (fc.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
                try {
                    java.util.List<String> lines = Files.readAllLines(fc.getSelectedFile().toPath(),
                            StandardCharsets.UTF_8);
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
        btnClear.addActionListener(e -> {
            textArea.setText("");
            lblInfo.setText("Cleared.");
        });
        btnPanel.add(btnLoad);
        btnPanel.add(btnClear);
        btnPanel.add(lblInfo);
        panel.add(btnPanel, BorderLayout.SOUTH);
        return panel;
    }

    private void applySmartRenderer(JTable table, DefaultTableModel model) {
        table.setDefaultRenderer(Integer.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                    boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                if (!isSelected) {
                    try {
                        int modelRow = table.convertRowIndexToModel(row);
                        int status = (int) model.getValueAt(modelRow, 2);
                        if (status >= 200 && status < 300)
                            c.setBackground(new Color(200, 255, 200));
                        else if (status >= 500)
                            c.setBackground(new Color(255, 200, 200));
                        else
                            c.setBackground(Color.WHITE);
                    } catch (Exception ignored) {
                    }
                }
                return c;
            }
        });
        table.setDefaultRenderer(String.class, new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                    boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                if (!isSelected) {
                    try {
                        int modelRow = table.convertRowIndexToModel(row);
                        int status = (int) model.getValueAt(modelRow, 2);
                        if (status >= 200 && status < 300)
                            c.setBackground(new Color(200, 255, 200));
                        else if (status >= 500)
                            c.setBackground(new Color(255, 200, 200));
                        else
                            c.setBackground(Color.WHITE);
                    } catch (Exception ignored) {
                    }
                }
                return c;
            }
        });
    }

    private void setupTableEvents(FuzzerEngine engine, String tabName) {
        JPopupMenu popupMenu = new JPopupMenu();
        JMenuItem sendToRepeaterItem = new JMenuItem("Send to Repeater");
        popupMenu.add(sendToRepeaterItem);
        engine.table.setComponentPopupMenu(popupMenu);
        engine.table.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                int r = engine.table.rowAtPoint(e.getPoint());
                if (r >= 0 && r < engine.table.getRowCount())
                    engine.table.setRowSelectionInterval(r, r);
                else
                    engine.table.clearSelection();
            }

            @Override
            public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() == 2) {
                    int r = engine.table.rowAtPoint(e.getPoint());
                    if (r >= 0) {
                        int modelRow = engine.table.convertRowIndexToModel(r);
                        int reqId = (int) engine.model.getValueAt(modelRow, 0);
                        HttpRequestResponse rrData = engine.requestHistory.get(reqId);
                        if (rrData != null)
                            showRequestResponseDialog(rrData,
                                    tabName + ": " + engine.model.getValueAt(modelRow, 1));
                    }
                }
            }
        });
        sendToRepeaterItem.addActionListener(e -> {
            int selectedRow = engine.table.getSelectedRow();
            if (selectedRow != -1) {
                int modelRow = engine.table.convertRowIndexToModel(selectedRow);
                int reqId = (int) engine.model.getValueAt(modelRow, 0);
                HttpRequestResponse rrData = engine.requestHistory.get(reqId);
                if (rrData != null)
                    api.repeater().sendToRepeater(rrData.request(),
                            tabName + ": " + engine.model.getValueAt(modelRow, 1));
            }
        });
    }

    private void showRequestResponseDialog(HttpRequestResponse rr, String title) {
        Frame burpFrame = (Frame) SwingUtilities.getAncestorOfClass(Frame.class, mainTabs);
        JDialog dialog = new JDialog(burpFrame, title, false);
        dialog.setSize(1200, 750);
        dialog.setLocationRelativeTo(burpFrame);
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setResizeWeight(0.5);
        HttpRequestEditor reqEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        reqEditor.setRequest(rr.request());
        splitPane.setLeftComponent(reqEditor.uiComponent());
        JTabbedPane responseTabs = new JTabbedPane();
        HttpResponseEditor resEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
        if (rr.response() != null)
            resEditor.setResponse(rr.response());
        responseTabs.addTab("Editor", resEditor.uiComponent());
        JEditorPane renderPane = new JEditorPane();
        renderPane.setEditable(false);
        renderPane.setContentType("text/html");
        if (rr.response() != null) {
            try {
                String bodyStr = rr.response().bodyToString();
                String ct = rr.response().headerValue("Content-Type");
                if (ct != null && ct.contains("text/html")) {
                    renderPane.setText(bodyStr);
                } else {
                    renderPane.setText("<html><body><pre style='font-family:monospace;font-size:12px;'>"
                            + bodyStr.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                            + "</pre></body></html>");
                }
            } catch (Exception ex) {
                renderPane.setText("<html><body><i>Could not render response.</i></body></html>");
            }
        } else {
            renderPane.setText("<html><body><i>(No response)</i></body></html>");
        }
        renderPane.setCaretPosition(0);
        responseTabs.addTab("Render", new JScrollPane(renderPane));
        splitPane.setRightComponent(responseTabs);
        dialog.add(splitPane);
        dialog.setVisible(true);
    }

    private void stopEngine(FuzzerEngine engine, String name) {
        engine.isRunning.set(false);
        engine.progressBar.setString("Aborted!");
        engine.btnRerun.setEnabled(true);
    }

    private void rerunFuzzing(FuzzerEngine engine) {
        if (engine.isRunning.get())
            return;
        if (engine.lastRequest == null) {
            JOptionPane.showMessageDialog(null,
                    "No previous request found. Right-click a request first.",
                    "Re-run Error", JOptionPane.WARNING_MESSAGE);
            return;
        }
        HttpRequestResponse rr = engine.lastRequest;
        List<Variant> variants;
        int delay;
        switch (engine.engineType) {
            case "Header":
                variants = buildHeaderVariants(rr.request());
                delay = (int) spinHeaderDelay.getValue();
                break;
            case "Path":
                variants = buildPathVariants(rr.request());
                delay = (int) spinPathDelay.getValue();
                break;
            case "Selection":
                if (engine.lastSelectionRange == null) {
                    JOptionPane.showMessageDialog(null,
                            "No selection range stored. Select text and fuzz first.",
                            "Re-run Error", JOptionPane.WARNING_MESSAGE);
                    return;
                }
                variants = buildSelectionVariants(rr.request(),
                        engine.lastSelectionRange[0], engine.lastSelectionRange[1]);
                delay = (int) spinSelDelay.getValue();
                break;
            default:
                return;
        }
        new Thread(() -> startFuzzing(rr, engine, variants, delay)).start();
    }

    private void checkExternalIp(JLabel targetLabel) {
        targetLabel.setText(" Status: Checking...");
        targetLabel.setForeground(Color.BLUE);
        new Thread(() -> {
            try {
                HttpService service = HttpService.httpService("api.ipify.org", 443, true);
                HttpRequest req = HttpRequest.httpRequest(service,
                        "GET / HTTP/1.1\r\nHost: api.ipify.org\r\nConnection: close\r\nAccept: */*\r\nUser-Agent: AccessContext/3.0\r\n\r\n");
                HttpRequestResponse res = api.http().sendRequest(req);
                if (res.response() != null && res.response().statusCode() == 200) {
                    String ip = res.response().bodyToString().trim();
                    SwingUtilities.invokeLater(() -> {
                        targetLabel.setText(" Current IP: " + ip + " (Verified)");
                        targetLabel.setForeground(new Color(0, 153, 0));
                    });
                } else {
                    SwingUtilities.invokeLater(() -> {
                        targetLabel.setText(" Status: Failed.");
                        targetLabel.setForeground(Color.RED);
                    });
                }
            } catch (Exception ex) {
                SwingUtilities.invokeLater(() -> {
                    targetLabel.setText(" Status: Error!");
                    targetLabel.setForeground(Color.RED);
                });
            }
        }).start();
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<>();
        HttpRequestResponse targetReq = null;
        if (event.messageEditorRequestResponse().isPresent())
            targetReq = event.messageEditorRequestResponse().get().requestResponse();
        else if (event.selectedRequestResponses() != null && !event.selectedRequestResponses().isEmpty())
            targetReq = event.selectedRequestResponses().get(0);
        if (targetReq == null)
            return menuItems;
        final HttpRequestResponse finalReq = targetReq;

        JMenuItem runHeader = new JMenuItem("Access Context: Header Fuzz");
        runHeader.addActionListener(e -> {
            if (headerEngine.isRunning.get())
                return;
            if (!confirmOpsec(lblCurrentIpHeader))
                return;
            mainTabs.setSelectedIndex(0);
            focusSuiteTab();
            flashTab(0, "Header Bypass");
            new Thread(() -> startFuzzing(finalReq, headerEngine, buildHeaderVariants(finalReq.request()),
                    (int) spinHeaderDelay.getValue())).start();
        });
        menuItems.add(runHeader);
        JMenuItem runPath = new JMenuItem("Access Context: Path Fuzz");
        runPath.addActionListener(e -> {
            if (pathEngine.isRunning.get())
                return;
            if (!confirmOpsec(lblCurrentIpPath))
                return;
            mainTabs.setSelectedIndex(1);
            focusSuiteTab();
            flashTab(1, "Path / GET Bypass");
            new Thread(() -> startFuzzing(finalReq, pathEngine, buildPathVariants(finalReq.request()),
                    (int) spinPathDelay.getValue())).start();
        });
        menuItems.add(runPath);
        if (event.messageEditorRequestResponse().isPresent()
                && event.messageEditorRequestResponse().get().selectionOffsets().isPresent()) {
            Range range = event.messageEditorRequestResponse().get().selectionOffsets().get();
            int start = range.startIndexInclusive(), end = range.endIndexExclusive();
            if (start < end) {
                JMenuItem runSel = new JMenuItem("Access Context: Fuzz Selection");
                runSel.addActionListener(e -> {
                    if (selectionEngine.isRunning.get())
                        return;
                    if (!confirmOpsec(lblCurrentIpSel))
                        return;
                    mainTabs.setSelectedIndex(2);
                    focusSuiteTab();
                    flashTab(2, "Selection Fuzz");
                    new Thread(() -> {
                        selectionEngine.lastSelectionRange = new int[] { start, end };
                        startFuzzing(finalReq, selectionEngine,
                                buildSelectionVariants(finalReq.request(), start, end), (int) spinSelDelay.getValue());
                    }).start();
                });
                menuItems.add(runSel);
            }
        }
        return menuItems;
    }

    private boolean confirmOpsec(JLabel ipLabel) {
        if (ipLabel.getText().contains("Not checked")) {
            int r = JOptionPane.showConfirmDialog(null,
                    "Your external IP hasn't been verified!\nContinue without OPSEC check?",
                    "OPSEC Warning", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            return r == JOptionPane.YES_OPTION;
        }
        return true;
    }

    private void focusSuiteTab() {
        SwingUtilities.invokeLater(() -> {
            java.awt.Container parent = mainTabs.getParent();
            while (parent != null) {
                if (parent instanceof JTabbedPane) {
                    JTabbedPane burpTabs = (JTabbedPane) parent;
                    for (int i = 0; i < burpTabs.getTabCount(); i++) {
                        if (burpTabs.getComponentAt(i) == mainTabs ||
                                SwingUtilities.isDescendingFrom(mainTabs, burpTabs.getComponentAt(i))) {
                            burpTabs.setSelectedIndex(i);
                            return;
                        }
                    }
                }
                parent = parent.getParent();
            }
        });
    }

    private void flashTab(int tabIndex, String originalTitle) {
        new Thread(() -> {
            try {
                for (int i = 0; i < 6; i++) {
                    String label = (i % 2 == 0) ? "\u26A1 " + originalTitle : originalTitle;
                    int fi = i;
                    SwingUtilities.invokeLater(() -> {
                        mainTabs.setTitleAt(tabIndex, label);
                        if (fi % 2 == 0)
                            mainTabs.setForegroundAt(tabIndex, new Color(255, 120, 0));
                        else
                            mainTabs.setForegroundAt(tabIndex, null);
                    });
                    Thread.sleep(400);
                }
                SwingUtilities.invokeLater(() -> {
                    mainTabs.setTitleAt(tabIndex, originalTitle);
                    mainTabs.setForegroundAt(tabIndex, null);
                });
            } catch (InterruptedException ignored) {
            }
        }).start();
    }

    private void startFuzzing(HttpRequestResponse baseRr, FuzzerEngine engine, List<Variant> variants, int delayMs) {
        engine.lastRequest = baseRr;
        engine.isRunning.set(true);
        SwingUtilities.invokeLater(() -> {
            engine.btnStop.setEnabled(true);
            engine.btnRerun.setEnabled(false);
            engine.model.setRowCount(0);
            engine.progressBar.setValue(0);
        });
        try {
            HttpRequest baseReq = baseRr.request();
            engine.requestHistory.clear();
            HttpRequestResponse baseline = api.http().sendRequest(baseReq);
            int baseStatus = statusOf(baseline), baseLen = bodyLen(baseline), baseWords = wordCount(baseline),
                    baseLines = lineCount(baseline);
            String baseTitle = getTitle(baseline);
            SwingUtilities.invokeLater(() -> engine.model.addRow(new Object[] { 0, "BASELINE", baseStatus, baseWords,
                    baseLines, baseLen, baseTitle, 0, "Original" }));
            engine.requestHistory.put(0, baseline);
            int total = variants.size();
            SwingUtilities.invokeLater(() -> {
                engine.progressBar.setMaximum(total);
                engine.progressBar.setString("0 / " + total);
            });
            int idx = 1;
            for (Variant v : variants) {
                if (!engine.isRunning.get())
                    break;
                Thread.sleep(delayMs);
                if (!engine.isRunning.get())
                    break;
                final int rowNo = idx++;
                long t0 = System.nanoTime();
                HttpRequestResponse rr = api.http().sendRequest(v.request);
                api.siteMap().add(rr);
                long rttMs = Duration.ofNanos(System.nanoTime() - t0).toMillis();
                engine.requestHistory.put(rowNo, rr);
                int st = statusOf(rr), len = bodyLen(rr), words = wordCount(rr), lines = lineCount(rr);
                String title = getTitle(rr), notes = "";
                if (st != baseStatus)
                    notes += "STATUS_CHANGE ";
                if (words != baseWords)
                    notes += "WORD_DELTA ";
                if (Math.abs(len - baseLen) > 50)
                    notes += "LEN_DELTA ";
                String xCache = getHeaderValue(rr, "X-Cache");
                if (!xCache.isEmpty())
                    notes += "X-Cache:" + xCache + " ";
                String cacheControl = getHeaderValue(rr, "Cache-Control");
                if (!cacheControl.isEmpty())
                    notes += "CC:" + cacheControl + " ";
                String age = getHeaderValue(rr, "Age");
                if (!age.isEmpty())
                    notes += "Age:" + age + " ";
                final String finalNotes = notes.trim();
                SwingUtilities.invokeLater(() -> {
                    engine.model.addRow(
                            new Object[] { rowNo, v.name, st, words, lines, len, title, (int) rttMs, finalNotes });
                    engine.progressBar.setValue(rowNo);
                    engine.progressBar.setString(rowNo + " / " + total);
                });
            }
        } catch (Exception ignored) {
        } finally {
            engine.isRunning.set(false);
            SwingUtilities.invokeLater(() -> {
                engine.btnStop.setEnabled(false);
                engine.btnRerun.setEnabled(true);
                if (engine.progressBar.getValue() == engine.progressBar.getMaximum())
                    engine.progressBar.setString("Done! (Re-run available)");
            });
        }
    }

    private static class Variant {
        final String name;
        final HttpRequest request;

        Variant(String n, HttpRequest r) {
            this.name = n;
            this.request = r;
        }
    }

    private List<Variant> buildHeaderVariants(HttpRequest baseReq) {
        List<Variant> out = new ArrayList<>();
        if (chkHeaderIP.isSelected()) {
            String[] ipHeaders = { "X-Real-IP", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Server",
                    "X-Originating-IP", "X-Remote-IP", "X-Client-IP", "True-Client-IP", "CF-Connecting-IP",
                    "Fastly-Client-IP", "Akamai-Client-IP", "X-Cluster-Client-IP", "X-ProxyUser-IP", "X-Proxy-Addr",
                    "Forwarded", "X-Custom-IP-Authorization", "X-Host" };
            String[] ipValues = { "127.0.0.1", "localhost", "0.0.0.0", "::1", "192.168.0.1", "10.0.0.1" };
            for (String h : ipHeaders) {
                for (String val : ipValues) {
                    if (h.equals("Forwarded"))
                        out.add(new Variant("IP: " + h + "=" + val,
                                addOrReplaceHeader(baseReq, h, "for=" + val + ";proto=http")));
                    else
                        out.add(new Variant("IP: " + h + "=" + val, addOrReplaceHeader(baseReq, h, val)));
                }
            }
            out.add(new Variant("HOST: localhost", addOrReplaceHeader(baseReq, "Host", "localhost")));
            out.add(new Variant("HOST: 127.0.0.1", addOrReplaceHeader(baseReq, "Host", "127.0.0.1")));
        }
        if (chkHeaderMethod.isSelected()) {

            String[] directMethods = { "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "HEAD",
                    "PROPFIND", "DEBUG", "MOVE" };
            for (String m : directMethods)
                out.add(new Variant("METHOD: " + m, baseReq.withMethod(m)));

            String[] overrideHeaders = { "X-HTTP-Method-Override", "X-Original-Method", "X-Method-Override",
                    "X-HTTP-Method" };
            String[] methods = { "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "HEAD", "CONNECT",
                    "PROPFIND", "DEBUG", "MOVE" };
            for (String h : overrideHeaders)
                for (String m : methods)
                    out.add(new Variant("OVR: " + h + "=" + m, addOrReplaceHeader(baseReq, h, m)));
        }
        if (chkHeaderRewrite.isSelected()) {
            String path = baseReq.path();
            String pathOnly = path.contains("?") ? path.substring(0, path.indexOf('?')) : path;
            String query = path.contains("?") ? path.substring(path.indexOf('?')) : "";

            out.add(new Variant("REWRITE: X-Original-URL → " + pathOnly,
                    addOrReplaceHeader(baseReq.withPath("/" + query), "X-Original-URL", pathOnly)));
            out.add(new Variant("REWRITE: X-Rewrite-URL → " + pathOnly,
                    addOrReplaceHeader(baseReq.withPath("/" + query), "X-Rewrite-URL", pathOnly)));
            out.add(new Variant("REWRITE: X-Original-URL → " + path,
                    addOrReplaceHeader(baseReq.withPath("/"), "X-Original-URL", path)));
            out.add(new Variant("REWRITE: X-Rewrite-URL → " + path,
                    addOrReplaceHeader(baseReq.withPath("/"), "X-Rewrite-URL", path)));
            out.add(new Variant("REWRITE: X-Accel-Redirect → " + pathOnly,
                    addOrReplaceHeader(baseReq, "X-Accel-Redirect", pathOnly)));
        }
        for (String ip : txtHeaderIPs.getText().split("\n"))
            if (!ip.trim().isEmpty())
                out.add(new Variant("CUSTOM IP: " + ip.trim(),
                        addOrReplaceHeader(baseReq, "X-Forwarded-For", ip.trim())));
        for (String hdr : txtHeaderHeaders.getText().split("\n"))
            if (hdr.contains(":")) {
                String[] p = hdr.split(":", 2);
                out.add(new Variant("CUSTOM HDR: " + p[0].trim(),
                        addOrReplaceHeader(baseReq, p[0].trim(), p[1].trim())));
            }
        return out;
    }

    private List<Variant> buildPathVariants(HttpRequest baseReq) {
        List<Variant> out = new ArrayList<>();
        String path = baseReq.path();
        if (chkPathRewrite.isSelected()) {
            String pathOnly = path.contains("?") ? path.substring(0, path.indexOf('?')) : path;
            String query = path.contains("?") ? path.substring(path.indexOf('?')) : "";
            out.add(new Variant("REWRITE: X-Original-URL → " + pathOnly,
                    addOrReplaceHeader(baseReq.withPath("/" + query), "X-Original-URL", pathOnly)));
            out.add(new Variant("REWRITE: X-Rewrite-URL → " + pathOnly,
                    addOrReplaceHeader(baseReq.withPath("/" + query), "X-Rewrite-URL", pathOnly)));
            out.add(new Variant("REWRITE: X-Original-URL (full) → " + path,
                    addOrReplaceHeader(baseReq.withPath("/"), "X-Original-URL", path)));
            out.add(new Variant("REWRITE: X-Rewrite-URL (full) → " + path,
                    addOrReplaceHeader(baseReq.withPath("/"), "X-Rewrite-URL", path)));
            out.add(new Variant("REWRITE: X-Accel-Redirect → " + pathOnly,
                    addOrReplaceHeader(baseReq, "X-Accel-Redirect", pathOnly)));

            String[] probeMethods = { "TRACE", "OPTIONS", "POST", "PUT", "PATCH", "HEAD" };
            for (String m : probeMethods)
                out.add(new Variant("METHOD: " + m, baseReq.withMethod(m)));
        }
        if (chkPathNorm.isSelected()) {
            out.add(new Variant("PATH: Trailing slash", baseReq.withPath(path.endsWith("/") ? path : path + "/")));
            out.add(new Variant("PATH: Double slash prefix", baseReq.withPath("//" + path)));
            out.add(new Variant("PATH: /..;/ injection", baseReq.withPath(injectDotDotSemicolon(path))));
            out.add(new Variant("PATH: ; suffix", baseReq.withPath(path.endsWith(";") ? path : path + ";")));
            out.add(new Variant("PATH: .json suffix", baseReq.withPath(path + ".json")));
            out.add(new Variant("PATH: Case Flip", baseReq.withPath(flipCase(path))));
        }
        if (chkPathAdvanced.isSelected()) {
            out.add(new Variant("ENC: URL Encode", baseReq.withPath(urlEncode(path))));
            out.add(new Variant("ENC: Double URL", baseReq.withPath(urlEncode(urlEncode(path)))));
            out.add(new Variant("ENC: IIS Unicode", baseReq.withPath(iisUnicodeEncode(path))));
        }
        if (chkPathDelimiter.isSelected()) {
            String suffix = txtDelimSuffix.getText().trim();
            if (suffix.isEmpty())
                suffix = "abc";
            String[] rawDelimiters = { "?", "#", ";", "@", "!", "$", "&", "'", "(", ")", "*", "+", ",", "=",
                    "~", ".", "%", "|", "^", "`", "{{", "}}", "[", "]", "\\", ":", "\n", "\r", "\t", " " };
            for (String d : rawDelimiters) {
                String display = d.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t").replace(" ", "<SP>");
                out.add(new Variant("DELIM: '" + display + "'", baseReq.withPath(path + d + suffix)));
            }
            String[] encodedDelimiters = { "%23", "%3f", "%3F", "%3b", "%3B", "%2f", "%2F", "%5c", "%5C",
                    "%00", "%0a", "%0A", "%0d", "%0D", "%09", "%20", "%25", "%26", "%40", "%21",
                    "%24", "%27", "%28", "%29", "%2a", "%2A", "%2b", "%2B", "%2c", "%2C",
                    "%3d", "%3D", "%7e", "%7E", "%7c", "%7C", "%5e", "%5E", "%60",
                    "%7b", "%7B", "%7d", "%7D", "%5b", "%5B", "%5d", "%5D" };
            for (String d : encodedDelimiters)
                out.add(new Variant("DELIM-ENC: '" + d + "'", baseReq.withPath(path + d + suffix)));
        }
        if (chkPathDelimExt.isSelected()) {
            String suffix = txtDelimSuffix.getText().trim();
            if (suffix.isEmpty())
                suffix = "abc";
            String[] staticExts = { ".js", ".css", ".png", ".jpg", ".gif", ".svg", ".ico", ".woff", ".woff2" };
            String[] testDelims = { "?", "%23", "%3f", "%3F", ";", "%3b", "%3B" };
            for (String d : testDelims)
                for (String ext : staticExts)
                    out.add(new Variant("DELIM+EXT: '" + d + "' + " + ext,
                            baseReq.withPath(path + d + suffix + ext)));
        }
        if (chkPathNormDisc.isSelected()) {
            String cachePrefix = txtCachePrefix.getText().trim();
            if (cachePrefix.isEmpty())
                cachePrefix = "/resources";
            out.add(new Variant("NORM: /aaa/..%2f" + path, baseReq.withPath("/aaa/..%2f" + stripLeadingSlash(path))));
            out.add(new Variant("NORM: /aaa/..%5c" + path, baseReq.withPath("/aaa/..%5c" + stripLeadingSlash(path))));
            out.add(new Variant("NORM: /aaa/%2e%2e/" + path,
                    baseReq.withPath("/aaa/%2e%2e/" + stripLeadingSlash(path))));
            out.add(new Variant("NORM: /aaa/%2e%2e%2f" + path,
                    baseReq.withPath("/aaa/%2e%2e%2f" + stripLeadingSlash(path))));
            out.add(new Variant("NORM-CACHE: /aaa/..%2f" + cachePrefix,
                    baseReq.withPath("/aaa/..%2f" + stripLeadingSlash(cachePrefix) + "/test")));
            out.add(new Variant("NORM-CACHE: " + cachePrefix + "/..%2ftest",
                    baseReq.withPath(cachePrefix + "/..%2ftest")));
        }
        if (chkPathCacheCombo.isSelected()) {
            String cachePrefix = txtCachePrefix.getText().trim();
            if (cachePrefix.isEmpty())
                cachePrefix = "/resources";
            String[] comboDelims = { "?", "%23", "%3f", "%3F", ";", "%3b", "%3B", "%00" };
            String encodedTraversal = "%2f%2e%2e%2f";
            for (String d : comboDelims) {
                out.add(new Variant("WCD: '" + d + "' + traversal + " + cachePrefix,
                        baseReq.withPath(path + d + encodedTraversal + stripLeadingSlash(cachePrefix))));
                out.add(new Variant("WCD+CB: '" + d + "' + traversal + " + cachePrefix + "?cb",
                        baseReq.withPath(path + d + encodedTraversal + stripLeadingSlash(cachePrefix) + "?wcd")));
            }
        }
        for (String p : txtPathPaths.getText().split("\n"))
            if (!p.trim().isEmpty())
                out.add(new Variant("CUSTOM PATH: " + p.trim(), baseReq.withPath(p.trim())));
        return out;
    }

    private List<Variant> buildSelectionVariants(HttpRequest baseReq, int start, int end) {
        List<Variant> out = new ArrayList<>();
        ByteArray rawReq = baseReq.toByteArray();
        ByteArray before = rawReq.subArray(0, start);
        ByteArray after = rawReq.subArray(end, rawReq.length());
        String selected = rawReq.subArray(start, end).toString();
        if (chkSelUrl.isSelected())
            out.add(createSelVar(baseReq.httpService(), before, after, "SEL: URL Enc", urlEncode(selected)));
        if (chkSelDoubleUrl.isSelected())
            out.add(createSelVar(baseReq.httpService(), before, after, "SEL: Double Enc",
                    urlEncode(urlEncode(selected))));
        if (chkSelIis.isSelected())
            out.add(createSelVar(baseReq.httpService(), before, after, "SEL: IIS Unicode", iisUnicodeEncode(selected)));
        if (chkSelUtf.isSelected())
            out.add(createSelVar(baseReq.httpService(), before, after, "SEL: UTF-8 Fullwidth",
                    selected.replace("/", "/%ef%bc%8f")));
        for (String p : txtSelCustom.getText().split("\n"))
            if (!p.trim().isEmpty())
                out.add(createSelVar(baseReq.httpService(), before, after, "SEL: " + p.trim(), p.trim()));
        return out;
    }

    private Variant createSelVar(HttpService s, ByteArray b, ByteArray a, String n, String p) {
        return new Variant(n, HttpRequest.httpRequest(s, b.withAppended(ByteArray.byteArray(p)).withAppended(a)));
    }

    private HttpRequest addOrReplaceHeader(HttpRequest b, String n, String v) {
        return b.withRemovedHeader(n).withAddedHeader(n, v);
    }

    private static String getHeaderValue(HttpRequestResponse rr, String headerName) {
        try {
            if (rr.response() == null)
                return "";
            return rr.response().headerValue(headerName) != null ? rr.response().headerValue(headerName) : "";
        } catch (Throwable t) {
            return "";
        }
    }

    private static String stripLeadingSlash(String s) {
        return s.startsWith("/") ? s.substring(1) : s;
    }

    private static String injectDotDotSemicolon(String p) {
        int l = p.lastIndexOf('/');
        return (l <= 0 || l == p.length() - 1) ? p + "..;/" : p.substring(0, l) + "/..;" + p.substring(l);
    }

    private static String flipCase(String s) {
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) {
            if (Character.isLowerCase(c))
                sb.append(Character.toUpperCase(c));
            else if (Character.isUpperCase(c))
                sb.append(Character.toLowerCase(c));
            else
                sb.append(c);
        }
        return sb.toString();
    }

    private static String urlEncode(String v) {
        StringBuilder sb = new StringBuilder();
        for (char c : v.toCharArray()) {
            if (c == '/' || c == '.' || c == '?')
                sb.append(c);
            else
                sb.append(String.format("%%%02x", (int) c));
        }
        return sb.toString();
    }

    private static String iisUnicodeEncode(String v) {
        StringBuilder sb = new StringBuilder();
        for (char c : v.toCharArray()) {
            if (c == '/' || c == '.' || c == '?')
                sb.append(c);
            else
                sb.append(String.format("%%u00%02x", (int) c));
        }
        return sb.toString();
    }

    private int statusOf(HttpRequestResponse rr) {
        try {
            return rr.response().statusCode();
        } catch (Throwable t) {
            return -1;
        }
    }

    private int bodyLen(HttpRequestResponse rr) {
        try {
            return rr.response().body() == null ? 0 : rr.response().body().length();
        } catch (Throwable t) {
            return 0;
        }
    }

    private int wordCount(HttpRequestResponse rr) {
        try {
            String b = rr.response().bodyToString();
            return (b == null || b.trim().isEmpty()) ? 0 : b.trim().split("\\s+").length;
        } catch (Throwable t) {
            return 0;
        }
    }

    private int lineCount(HttpRequestResponse rr) {
        try {
            String b = rr.response().bodyToString();
            return (b == null || b.isEmpty()) ? 0 : b.split("\r\n|\r|\n").length;
        } catch (Throwable t) {
            return 0;
        }
    }

    private String getTitle(HttpRequestResponse rr) {
        try {
            String b = rr.response().bodyToString();
            if (b == null)
                return "";
            Matcher m = Pattern.compile("<title>(.*?)</title>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL).matcher(b);
            if (m.find())
                return m.group(1).trim().replaceAll("\\s+", " ");
        } catch (Throwable t) {
        }
        return "";
    }

    private void exportToCsv(DefaultTableModel m, String n) {
        if (m.getRowCount() == 0)
            return;
        JFileChooser f = new JFileChooser();
        if (f.showSaveDialog(null) == JFileChooser.APPROVE_OPTION) {
            File file = f.getSelectedFile();
            if (!file.getName().toLowerCase().endsWith(".csv"))
                file = new File(file.getParentFile(), file.getName() + ".csv");
            try (PrintWriter pw = new PrintWriter(file, "UTF-8")) {
                for (int i = 0; i < m.getColumnCount(); i++)
                    pw.print("\"" + m.getColumnName(i) + "\"" + (i == m.getColumnCount() - 1 ? "" : ","));
                pw.println();
                for (int r = 0; r < m.getRowCount(); r++) {
                    for (int c = 0; c < m.getColumnCount(); c++) {
                        Object v = m.getValueAt(r, c);
                        String s = (v == null) ? "" : v.toString().replace("\"", "\"\"");
                        pw.print("\"" + s + "\"" + (c == m.getColumnCount() - 1 ? "" : ","));
                    }
                    pw.println();
                }
            } catch (Exception ignored) {
            }
        }
    }
}