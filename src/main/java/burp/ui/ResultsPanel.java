package burp.ui;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import burp.core.ExtensionContext;
import burp.core.FuzzerEngine;
import burp.core.ScanEngine;
import burp.util.HttpUtils;
import burp.util.ThemeColors;

import javax.swing.*;
import javax.swing.RowFilter;
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
import java.util.List;

public class ResultsPanel {

    private ResultsPanel() {}

    public static JPanel build(ExtensionContext ctx, FuzzerEngine engine,
                                ScanEngine scanEngine, String name) {
        JPanel resultsPanel = new JPanel(new BorderLayout());
        JPanel controlPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        engine.progressBar = new JProgressBar(0, 100);
        engine.progressBar.setStringPainted(true);
        engine.progressBar.setPreferredSize(new Dimension(300, 25));

        engine.btnStop = new JButton("Stop Fuzzing");
        engine.btnStop.setEnabled(false);
        engine.btnStop.setBackground(ThemeColors.btnStop());
        engine.btnStop.setForeground(ThemeColors.btnWhiteFg());

        engine.btnExport = new JButton("Export CSV");

        engine.btnRerun = new JButton("▶ Re-run Fuzzing");
        engine.btnRerun.setEnabled(false);
        engine.btnRerun.setBackground(ThemeColors.btnRerun());
        engine.btnRerun.setForeground(ThemeColors.btnWhiteFg());

        engine.btnFilter = new JButton("🔍 Show Only Interesting");
        engine.btnFilter.setBackground(ThemeColors.btnFilterOff());
        engine.btnFilter.setForeground(ThemeColors.btnFilterOffFg());

        engine.btnPreview = new JButton("👁 Preview Payloads");
        engine.btnPreview.setToolTipText("Show all payload variants that would be sent (uses last request if available)");

        controlPanel.add(engine.progressBar);
        controlPanel.add(engine.btnStop);
        controlPanel.add(engine.btnRerun);
        controlPanel.add(engine.btnFilter);
        controlPanel.add(engine.btnPreview);
        controlPanel.add(engine.btnExport);
        resultsPanel.add(controlPanel, BorderLayout.NORTH);

        // Columns: #, Variant, Status, Cache, Words, Lines, Length, Title, RTT(ms), Notes
        engine.model = new DefaultTableModel(
                new Object[]{"#", "Variant", "Status", "Cache", "Words", "Lines", "Length", "Title", "RTT(ms)", "Notes"}, 0) {
            @Override public boolean isCellEditable(int row, int column) { return false; }
            @Override public Class<?> getColumnClass(int columnIndex) {
                if (columnIndex == 0 || columnIndex == 2 || columnIndex == 4 ||
                    columnIndex == 5 || columnIndex == 6 || columnIndex == 8)
                    return Integer.class;
                return String.class;
            }
        };
        engine.table = new JTable(engine.model);
        engine.table.setAutoCreateRowSorter(true);
        engine.table.setRowSorter(new TableRowSorter<>(engine.model));
        applySmartRenderer(engine.table, engine.model);
        engine.table.getColumnModel().getColumn(1).setPreferredWidth(220);
        engine.table.getColumnModel().getColumn(3).setPreferredWidth(130);
        engine.table.getColumnModel().getColumn(9).setPreferredWidth(320);
        resultsPanel.add(new JScrollPane(engine.table), BorderLayout.CENTER);

        setupTableEvents(ctx, engine, scanEngine, name);

        engine.btnStop.addActionListener(e -> scanEngine.stopEngine(engine));
        engine.btnExport.addActionListener(e -> exportToCsv(engine.model, name));
        engine.btnRerun.addActionListener(e -> scanEngine.rerunFuzzing(engine));
        engine.btnFilter.addActionListener(e -> toggleInterestingFilter(engine));
        engine.btnPreview.addActionListener(e -> scanEngine.showPayloadPreview(engine));

        return resultsPanel;
    }

    private static void setupTableEvents(ExtensionContext ctx, FuzzerEngine engine,
                                          ScanEngine scanEngine, String tabName) {
        JPopupMenu popupMenu = new JPopupMenu();
        JMenuItem sendToRepeaterItem  = new JMenuItem("Send to Repeater");
        JMenuItem sendAllSelectedItem = new JMenuItem("Send All Selected to Repeater");
        JMenuItem sendInterestingItem = new JMenuItem("Send All Interesting to Repeater");
        JMenuItem compareBaselineItem = new JMenuItem("Compare with Baseline");

        popupMenu.add(sendToRepeaterItem);
        popupMenu.add(sendAllSelectedItem);
        popupMenu.addSeparator();
        popupMenu.add(sendInterestingItem);
        popupMenu.addSeparator();
        popupMenu.add(compareBaselineItem);

        engine.table.setComponentPopupMenu(popupMenu);
        engine.table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
        engine.table.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                if (e.isPopupTrigger() || SwingUtilities.isRightMouseButton(e)) {
                    int r = engine.table.rowAtPoint(e.getPoint());
                    if (r >= 0 && !engine.table.isRowSelected(r))
                        engine.table.setRowSelectionInterval(r, r);
                } else if (!e.isControlDown() && !e.isShiftDown()) {
                    int r = engine.table.rowAtPoint(e.getPoint());
                    if (r >= 0 && r < engine.table.getRowCount())
                        engine.table.setRowSelectionInterval(r, r);
                    else
                        engine.table.clearSelection();
                }
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
                            showRequestResponseDialog(ctx,
                                    rrData, tabName + ": " + engine.model.getValueAt(modelRow, 1));
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
                    ctx.api.repeater().sendToRepeater(rrData.request(),
                            tabName + ": " + engine.model.getValueAt(modelRow, 1));
            }
        });

        sendAllSelectedItem.addActionListener(e -> {
            int[] selectedRows = engine.table.getSelectedRows();
            int sent = 0;
            for (int viewRow : selectedRows) {
                int modelRow = engine.table.convertRowIndexToModel(viewRow);
                int reqId = (int) engine.model.getValueAt(modelRow, 0);
                HttpRequestResponse rrData = engine.requestHistory.get(reqId);
                if (rrData != null) {
                    ctx.api.repeater().sendToRepeater(rrData.request(),
                            tabName + ": " + engine.model.getValueAt(modelRow, 1));
                    sent++;
                }
            }
            if (sent > 0)
                JOptionPane.showMessageDialog(null, sent + " request(s) sent to Repeater.",
                        "Sent to Repeater", JOptionPane.INFORMATION_MESSAGE);
        });

        sendInterestingItem.addActionListener(e -> {
            int sent = 0;
            for (int i = 0; i < engine.model.getRowCount(); i++) {
                String notes = (String) engine.model.getValueAt(i, 9);
                int reqId = (int) engine.model.getValueAt(i, 0);
                if (reqId == 0) continue;
                if (notes != null && !notes.isEmpty()) {
                    HttpRequestResponse rrData = engine.requestHistory.get(reqId);
                    if (rrData != null) {
                        ctx.api.repeater().sendToRepeater(rrData.request(),
                                tabName + ": " + engine.model.getValueAt(i, 1));
                        sent++;
                    }
                }
            }
            if (sent > 0)
                JOptionPane.showMessageDialog(null, sent + " interesting request(s) sent to Repeater.",
                        "Sent to Repeater", JOptionPane.INFORMATION_MESSAGE);
            else
                JOptionPane.showMessageDialog(null, "No interesting results found.",
                        "Sent to Repeater", JOptionPane.INFORMATION_MESSAGE);
        });

        compareBaselineItem.addActionListener(e -> {
            int selectedRow = engine.table.getSelectedRow();
            if (selectedRow == -1) return;
            int modelRow = engine.table.convertRowIndexToModel(selectedRow);
            int reqId = (int) engine.model.getValueAt(modelRow, 0);
            if (reqId == 0) {
                JOptionPane.showMessageDialog(null, "Cannot compare baseline with itself.",
                        "Compare", JOptionPane.INFORMATION_MESSAGE);
                return;
            }
            HttpRequestResponse baseline = engine.requestHistory.get(0);
            HttpRequestResponse variant  = engine.requestHistory.get(reqId);
            if (baseline == null || variant == null) {
                JOptionPane.showMessageDialog(null, "Request data not available.",
                        "Compare", JOptionPane.WARNING_MESSAGE);
                return;
            }
            String varName = (String) engine.model.getValueAt(modelRow, 1);
            DiffDialog.show(ctx, baseline, variant, varName);
        });
    }

    private static void showRequestResponseDialog(ExtensionContext ctx,
                                                   HttpRequestResponse rr, String title) {
        Frame burpFrame = (Frame) SwingUtilities.getAncestorOfClass(Frame.class, ctx.mainTabs);
        JDialog dialog = new JDialog(burpFrame, title, false);
        dialog.setSize(1200, 750);
        dialog.setLocationRelativeTo(burpFrame);
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setResizeWeight(0.5);
        HttpRequestEditor reqEditor = ctx.api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        reqEditor.setRequest(rr.request());
        splitPane.setLeftComponent(reqEditor.uiComponent());
        JTabbedPane responseTabs = new JTabbedPane();
        HttpResponseEditor resEditor = ctx.api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
        if (rr.response() != null) resEditor.setResponse(rr.response());
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
                            + DiffDialog.escapeHtml(bodyStr)
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

    public static void applySmartRenderer(JTable table, DefaultTableModel model) {
        DefaultTableCellRenderer smartRenderer = new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected,
                    boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                if (!isSelected) {
                    try {
                        int modelRow = table.convertRowIndexToModel(row);
                        int status = (int) model.getValueAt(modelRow, 2);
                        String notes = (String) model.getValueAt(modelRow, 9);
                        Color bg = getRowColor(status, notes);
                        if (bg != null) {
                            c.setBackground(bg);
                            c.setForeground(ThemeColors.rowForeground());
                        } else {
                            c.setBackground(table.getBackground());
                            c.setForeground(table.getForeground());
                        }
                    } catch (Exception ignored) {
                        c.setBackground(table.getBackground());
                        c.setForeground(table.getForeground());
                    }
                }
                return c;
            }
        };
        table.setDefaultRenderer(Integer.class, smartRenderer);
        table.setDefaultRenderer(String.class, smartRenderer);
    }

    public static Color getRowColor(int status, String notes) {
        if (status == -1)                                                    return ThemeColors.rowReset();
        if (notes != null && notes.contains("SENSITIVE_DATA:"))              return ThemeColors.rowSensitive();
        if (notes != null && notes.contains("🎯 CACHE_HIT_CACHEABLE"))      return ThemeColors.rowCacheHit();
        if (notes != null && notes.contains("🎯 POTENTIAL BYPASS"))         return ThemeColors.rowBypass();
        if (notes != null && notes.contains("🔀 REDIRECT BYPASS"))          return ThemeColors.rowRedirect();
        if (notes != null && notes.contains("⚠️ BODY_BYPASS"))              return ThemeColors.rowBodyBypass();
        if (notes != null && notes.contains("CUSTOM:"))                      return ThemeColors.rowCustom();
        if (status >= 200 && status < 300)                                   return ThemeColors.rowSuccess();
        if (status == 301 || status == 302 || status == 307 || status == 308) return ThemeColors.rowRedirect3xx();
        if (status == 429)                                                   return ThemeColors.rowRateLimit();
        if (status >= 500)                                                   return ThemeColors.rowError();
        return null;
    }

    public static void toggleInterestingFilter(FuzzerEngine engine) {
        TableRowSorter<?> sorter = (TableRowSorter<?>) engine.table.getRowSorter();
        if (engine.filterActive.get()) {
            sorter.setRowFilter(null);
            engine.filterActive.set(false);
            engine.btnFilter.setText("🔍 Show Only Interesting");
            engine.btnFilter.setBackground(ThemeColors.btnFilterOff());
            engine.btnFilter.setForeground(ThemeColors.btnFilterOffFg());
        } else {
            sorter.setRowFilter(new RowFilter<Object, Object>() {
                @Override
                public boolean include(Entry<?, ?> entry) {
                    String notes = entry.getStringValue(9);
                    int rowIdx = (int) entry.getValue(0);
                    return rowIdx == 0 || (notes != null && !notes.isEmpty());
                }
            });
            engine.filterActive.set(true);
            engine.btnFilter.setText("✖ Show All Results");
            engine.btnFilter.setBackground(ThemeColors.btnFilterOn());
            engine.btnFilter.setForeground(ThemeColors.btnWhiteFg());
        }
    }

    private static void exportToCsv(DefaultTableModel m, String n) {
        if (m.getRowCount() == 0) return;
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
                        String s = (v == null) ? "" : v.toString()
                                .replace("\"", "\"\"")
                                .replace("\r\n", " ").replace("\r", " ").replace("\n", " ");
                        pw.print("\"" + s + "\"" + (c == m.getColumnCount() - 1 ? "" : ","));
                    }
                    pw.println();
                }
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(null, "Export failed: " + ex.getMessage(),
                        "Export Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    public static JPanel buildOpsecPanel(ExtensionContext ctx, JLabel ipLabel,
                                          JSpinner delaySpinner, ScanEngine scanEngine) {
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

    public static JPanel createTextAreaPanel(String title, JTextArea textArea) {
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
            fc.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter(
                    "Text files", "txt", "lst", "csv", "list"));
            if (fc.showOpenDialog(null) == JFileChooser.APPROVE_OPTION) {
                try {
                    List<String> lines = Files.readAllLines(fc.getSelectedFile().toPath(), StandardCharsets.UTF_8);
                    String existing = textArea.getText().trim();
                    textArea.setText(existing.isEmpty() ? String.join("\n", lines)
                            : existing + "\n" + String.join("\n", lines));
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
