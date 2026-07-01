package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import burp.core.ExtensionContext;
import burp.core.ScanEngine;
import burp.core.Variant;
import burp.payload.HeaderPayloadBuilder;
import burp.payload.PathPayloadBuilder;
import burp.payload.SelectionPayloadBuilder;
import burp.ui.AboutTab;
import burp.ui.HeaderEngineTab;
import burp.ui.PathEngineTab;
import burp.ui.SelectionEngineTab;
import burp.ui.SettingsTab;
import burp.ui.WcdFindingsTab;

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
        api.logging().logToOutput("[ACF] v2.4.0 loaded — WCD verify (warm+replay) + WCD Findings tab active");
        api.extension().registerUnloadingHandler(() -> {
            SettingsTab.save(ctx);
            ctx.taskExecutor.shutdownNow();
        });

        JPanel headerPanel    = HeaderEngineTab.build(ctx, scanEngine);
        JPanel pathPanel      = PathEngineTab.build(ctx, scanEngine);
        JPanel selectionPanel = SelectionEngineTab.build(ctx, scanEngine);
        JPanel settingsPanel  = SettingsTab.build(ctx, scanEngine);
        JPanel wcdPanel       = WcdFindingsTab.build(ctx);
        JPanel aboutPanel     = AboutTab.build(ctx);

        mainTabs.addTab("🔐 Header Bypass",        headerPanel);
        mainTabs.addTab("🔀 Path / GET Bypass",    pathPanel);
        mainTabs.addTab("🎯 Selection Fuzz",       selectionPanel);
        mainTabs.addTab("🎯 WCD Findings",         wcdPanel);
        mainTabs.addTab("⚙ Settings & History",   settingsPanel);
        mainTabs.addTab("ℹ About",                aboutPanel);

        api.userInterface().registerSuiteTab("Access Context", mainTabs);
        api.userInterface().registerContextMenuItemsProvider(this);

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

        JMenuItem verifyWcd = new JMenuItem("Access Context: Verify WCD (warm + no-auth replay)");
        verifyWcd.setToolTipText("Works on whichever message is open (request or response). Warms the cache with your " +
                "auth first, then replays without cookies/auth — if the no-auth response is served from cache with the " +
                "authenticated content, it's a confirmed Web Cache Deception finding. Result is added to the WCD Findings tab.");
        verifyWcd.addActionListener(e -> scanEngine.verifyWcdNoAuth(finalReq));
        menuItems.add(verifyWcd);

        JMenuItem runHeader = new JMenuItem("Access Context: Header Fuzz");
        runHeader.setToolTipText("Test 40+ header-based access control bypass variants: IP spoofing " +
                "(X-Forwarded-For, X-Real-IP…), host override, HTTP method tampering, and custom headers.");
        runHeader.addActionListener(e -> {
            if (ctx.headerEngine.isRunning.get()) return;
            if (!scanEngine.confirmOpsec(ctx.lblCurrentIp)) return;
            ctx.mainTabs.setSelectedIndex(0);
            scanEngine.focusSuiteTab();
            scanEngine.flashTab(0, "🔐 Header Bypass");
            // Build variants and read spinner on EDT before submitting to background thread
            List<Variant> variants = new HeaderPayloadBuilder(ctx).build(finalReq.request());
            int delay = (int) ctx.spinDelay.getValue();
            ScanEngine.ScanConfig cfg = new ScanEngine.ScanConfig(ctx);
            ctx.taskExecutor.submit(() -> scanEngine.startFuzzing(finalReq, ctx.headerEngine, variants, delay, cfg));
        });
        menuItems.add(runHeader);

        JMenuItem runPath = new JMenuItem("Access Context: Path Fuzz");
        runPath.setToolTipText("Test path normalization tricks, encoding bypasses, and the 4-phase Web Cache " +
                "Deception pipeline (delimiter discovery, extension combos, normalization discrepancy, exploit payloads).");
        runPath.addActionListener(e -> {
            if (ctx.pathEngine.isRunning.get()) return;
            if (!scanEngine.confirmOpsec(ctx.lblCurrentIp)) return;
            ctx.mainTabs.setSelectedIndex(1);
            scanEngine.focusSuiteTab();
            scanEngine.flashTab(1, "🔀 Path / GET Bypass");
            List<Variant> variants = new PathPayloadBuilder(ctx).build(finalReq.request());
            int delay = (int) ctx.spinDelay.getValue();
            ScanEngine.ScanConfig cfg = new ScanEngine.ScanConfig(ctx);
            ctx.taskExecutor.submit(() -> scanEngine.startFuzzing(finalReq, ctx.pathEngine, variants, delay, cfg));
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
                    if (!scanEngine.confirmOpsec(ctx.lblCurrentIp)) return;
                    ctx.mainTabs.setSelectedIndex(2);
                    scanEngine.focusSuiteTab();
                    scanEngine.flashTab(2, "🎯 Selection Fuzz");
                    List<Variant> variants = new SelectionPayloadBuilder(ctx).build(finalReq.request(), start, end);
                    int delay = (int) ctx.spinDelay.getValue();
                    ScanEngine.ScanConfig cfg = new ScanEngine.ScanConfig(ctx);
                    ctx.taskExecutor.submit(() -> {
                        ctx.selectionEngine.lastSelectionRange = new int[]{start, end};
                        scanEngine.startFuzzing(finalReq, ctx.selectionEngine, variants, delay, cfg);
                    });
                });
                menuItems.add(runSel);
            }
        }
        return menuItems;
    }
}
