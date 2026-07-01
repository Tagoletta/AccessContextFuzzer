package burp.ui;

import burp.api.montoya.http.message.HttpRequestResponse;
import burp.core.ExtensionContext;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

public class WcdFindingsTab {

    private WcdFindingsTab() {}

    public static JPanel build(ExtensionContext ctx) {
        JPanel panel = new JPanel(new BorderLayout());

        ctx.wcdFindingsModel = new DefaultTableModel(
                new Object[]{"#", "Source", "URL", "Auth", "No-Auth", "X-Cache", "Verdict", "Time"}, 0) {
            @Override public boolean isCellEditable(int r, int c) { return false; }
            @Override public Class<?> getColumnClass(int c) { return c == 0 ? Integer.class : String.class; }
        };
        JTable table = new JTable(ctx.wcdFindingsModel);
        table.setAutoCreateRowSorter(true);
        table.setFillsViewportHeight(true);
        table.getColumnModel().getColumn(2).setPreferredWidth(360);
        table.getColumnModel().getColumn(6).setPreferredWidth(220);

        table.addMouseListener(new MouseAdapter() {
            @Override public void mouseClicked(MouseEvent e) {
                if (e.getClickCount() != 2) return;
                int viewRow = table.rowAtPoint(e.getPoint());
                if (viewRow < 0) return;
                int modelRow = table.convertRowIndexToModel(viewRow);
                int id = (int) ctx.wcdFindingsModel.getValueAt(modelRow, 0);
                HttpRequestResponse rr = ctx.wcdFindingsHistory.get(id);
                if (rr != null)
                    ResultsPanel.showRequestResponseDialog(ctx, rr,
                            "WCD Finding: " + ctx.wcdFindingsModel.getValueAt(modelRow, 2));
                else
                    JOptionPane.showMessageDialog(null, "No stored response for this finding.",
                            "WCD Findings", JOptionPane.INFORMATION_MESSAGE);
            }
        });

        JPanel ctrl = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton btnClear = new JButton("Clear Findings");
        btnClear.addActionListener(e -> ctx.wcdFindingsModel.setRowCount(0));
        ctrl.add(btnClear);
        ctrl.add(new JLabel("  Double-click a row to view the stored request/response. In-memory; cleared on Burp restart."));

        panel.add(ctrl, BorderLayout.NORTH);
        panel.add(new JScrollPane(table), BorderLayout.CENTER);
        return panel;
    }
}
