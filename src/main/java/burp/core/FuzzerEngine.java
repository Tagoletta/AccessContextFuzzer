package burp.core;

import burp.api.montoya.http.message.HttpRequestResponse;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

public class FuzzerEngine {
    public JPanel mainPanel;
    public DefaultTableModel model;
    public JTable table;
    public JProgressBar progressBar;
    public JButton btnStop;
    public JButton btnExport;
    public JButton btnRerun;
    public JButton btnFilter;
    public JButton btnPreview;
    public AtomicBoolean isRunning = new AtomicBoolean(false);
    public AtomicBoolean filterActive = new AtomicBoolean(false);
    public Map<Integer, HttpRequestResponse> requestHistory = new ConcurrentHashMap<>();
    public volatile HttpRequestResponse lastRequest;
    public volatile int[] lastSelectionRange;
    public volatile int baselineStatus = -999;
    public String engineType;
}
