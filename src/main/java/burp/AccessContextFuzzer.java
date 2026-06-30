package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import burp.core.ExtensionContext;
import burp.core.ScanEngine;
import burp.payload.HeaderPayloadBuilder;
import burp.payload.PathPayloadBuilder;
import burp.payload.SelectionPayloadBuilder;
import burp.ui.AboutTab;
import burp.ui.HeaderEngineTab;
import burp.ui.PathEngineTab;
import burp.ui.SelectionEngineTab;
import burp.ui.SettingsTab;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;

public class AccessContextFuzzer implements BurpExtension, ContextMenuItemsProvider {

    private ExtensionContext ctx;
    private ScanEngine scanEngine;

    @Override
    public void initialize(MontoyaApi api) {
        JTabbedPane mainTabs = new JTabbedPane();
        ctx = new ExtensionContext(api, mainTabs, Executors.newCachedThreadPool());
        scanEngine = new ScanEngine(ctx);

        api.extension().setName("Access Context Fuzzer");
        api.extension().registerUnloadingHandler(() -> {
            SettingsTab.save(ctx);
            ctx.taskExecutor.shutdownNow();
        });

        JPanel headerPanel    = HeaderEngineTab.build(ctx, scanEngine);
        JPanel pathPanel      = PathEngineTab.build(ctx, scanEngine);
        JPanel selectionPanel = SelectionEngineTab.build(ctx, scanEngine);
        JPanel settingsPanel  = SettingsTab.build(ctx);
        JPanel aboutPanel     = AboutTab.build(ctx);

        mainTabs.addTab("🔐 Header Bypass",        headerPanel);
        mainTabs.addTab("🔀 Path / GET Bypass",    pathPanel);
        mainTabs.addTab("🎯 Selection Fuzz",       selectionPanel);
        mainTabs.addTab("⚙ Settings & History",   settingsPanel);
        mainTabs.addTab("ℹ About",                aboutPanel);

        api.userInterface().registerSuiteTab("Access Context", mainTabs);
        api.userInterface().registerContextMenuItemsProvider(this);

        // Enable tooltip display inside popup/context menus
        ToolTipManager.sharedInstance().setEnabled(true);
        ToolTipManager.sharedInstance().setInitialDelay(300);
        ToolTipManager.sharedInstance().setDismissDelay(8000);

        SwingUtilities.invokeLater(() -> SettingsTab.load(ctx));
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<Component> menuItems = new ArrayList<>();
        HttpRequestResponse targetReq = null;
        if (event.messageEditorRequestResponse().isPresent())
            targetReq = event.messageEditorRequestResponse().get().requestResponse();
        else if (event.selectedRequestResponses() != null && !event.selectedRequestResponses().isEmpty())
            targetReq = event.selectedRequestResponses().get(0);
        if (targetReq == null) return menuItems;
        final HttpRequestResponse finalReq = targetReq;

        JMenuItem verifyWcd = new JMenuItem("Access Context: Verify WCD (No-Auth)");
        verifyWcd.setToolTipText("Replay this URL without cookies or auth headers — if the cached response still " +
                "returns authenticated content, it's a confirmed Web Cache Deception finding.");
        verifyWcd.addActionListener(e -> scanEngine.verifyWcdNoAuth(finalReq));
        menuItems.add(verifyWcd);

        JMenuItem runHeader = new JMenuItem("Access Context: Header Fuzz");
        runHeader.setToolTipText("Test 40+ header-based access control bypass variants: IP spoofing " +
                "(X-Forwarded-For, X-Real-IP…), host override, HTTP method tampering, and custom headers.");
        runHeader.addActionListener(e -> {
            if (ctx.headerEngine.isRunning.get()) return;
            if (!scanEngine.confirmOpsec(ctx.lblCurrentIpHeader)) return;
            ctx.mainTabs.setSelectedIndex(0);
            scanEngine.focusSuiteTab();
            scanEngine.flashTab(0, "🔐 Header Bypass");
            ctx.taskExecutor.submit(() -> scanEngine.startFuzzing(finalReq, ctx.headerEngine,
                    new HeaderPayloadBuilder(ctx).build(finalReq.request()),
                    (int) ctx.spinHeaderDelay.getValue()));
        });
        menuItems.add(runHeader);

        JMenuItem runPath = new JMenuItem("Access Context: Path Fuzz");
        runPath.setToolTipText("Test path normalization tricks, encoding bypasses, and the 4-phase Web Cache " +
                "Deception pipeline (delimiter discovery, extension combos, normalization discrepancy, exploit payloads).");
        runPath.addActionListener(e -> {
            if (ctx.pathEngine.isRunning.get()) return;
            if (!scanEngine.confirmOpsec(ctx.lblCurrentIpPath)) return;
            ctx.mainTabs.setSelectedIndex(1);
            scanEngine.focusSuiteTab();
            scanEngine.flashTab(1, "🔀 Path / GET Bypass");
            ctx.taskExecutor.submit(() -> scanEngine.startFuzzing(finalReq, ctx.pathEngine,
                    new PathPayloadBuilder(ctx).build(finalReq.request()),
                    (int) ctx.spinPathDelay.getValue()));
        });
        menuItems.add(runPath);

        if (event.messageEditorRequestResponse().isPresent()
                && event.messageEditorRequestResponse().get().selectionOffsets().isPresent()) {
            Range range = event.messageEditorRequestResponse().get().selectionOffsets().get();
            int start = range.startIndexInclusive(), end = range.endIndexExclusive();
            if (start < end) {
                JMenuItem runSel = new JMenuItem("Access Context: Fuzz Selection");
                runSel.setToolTipText("Fuzz the selected text with URL encoding, double encoding, IIS Unicode, " +
                        "UTF-8 fullwidth slash, and custom payloads — without modifying the rest of the request.");
                runSel.addActionListener(e -> {
                    if (ctx.selectionEngine.isRunning.get()) return;
                    if (!scanEngine.confirmOpsec(ctx.lblCurrentIpSel)) return;
                    ctx.mainTabs.setSelectedIndex(2);
                    scanEngine.focusSuiteTab();
                    scanEngine.flashTab(2, "🎯 Selection Fuzz");
                    ctx.taskExecutor.submit(() -> {
                        ctx.selectionEngine.lastSelectionRange = new int[]{start, end};
                        scanEngine.startFuzzing(finalReq, ctx.selectionEngine,
                                new SelectionPayloadBuilder(ctx).build(finalReq.request(), start, end),
                                (int) ctx.spinSelDelay.getValue());
                    });
                });
                menuItems.add(runSel);
            }
        }
        return menuItems;
    }
}
