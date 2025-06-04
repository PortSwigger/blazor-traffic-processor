package com.gdssecurity.providers;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;

import javax.swing.JMenuItem;
import javax.swing.JOptionPane;
import java.awt.Component;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Context menu factory for BTP frames.
 */
public class BTPContextMenuFactory implements ContextMenuItemsProvider {

    private final MontoyaApi api;
    private static final Logger logger = Logger.getLogger("BTP");

    public BTPContextMenuFactory(MontoyaApi api) {
        this.api = api;
        logger.info("[BTPContextMenuFactory] Constructor called. Thread: " + Thread.currentThread().getName());
    }

    /**
     * Provides context menu items for BTP frames.
     * @param event The context menu event from Burp.
     * @return List of JMenuItem as Component.
     */
    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        logger.info("[BTPContextMenuFactory] provideMenuItems() called. Thread: " + Thread.currentThread().getName());

        Optional<HttpRequestResponse> maybeReqResp = event.messageEditorRequestResponse().map(m -> m.requestResponse());
        if (maybeReqResp.isEmpty()) {
            logger.info("[BTPContextMenuFactory] No HttpRequestResponse found for context menu.");
            return List.of();
        }
        HttpRequestResponse reqResp = maybeReqResp.get();

        List<Component> menuItems = new ArrayList<>();

        JMenuItem sendToIntruder = new JMenuItem("Send to Intruder");
        sendToIntruder.addActionListener(e -> {
            try {
                api.intruder().sendToIntruder(reqResp.request());
                logger.info("[BTPContextMenuFactory] Sent to Intruder: " + reqResp.url());
            } catch (Exception ex) {
                logger.log(Level.SEVERE, "[BTPContextMenuFactory] Error sending to Intruder", ex);
                JOptionPane.showMessageDialog(null, "Failed to send to Intruder: " + ex.getMessage());
            }
        });
        menuItems.add(sendToIntruder);

        JMenuItem sendToRepeater = new JMenuItem("Send to Repeater");
        sendToRepeater.addActionListener(e -> {
            try {
                api.repeater().sendToRepeater(reqResp.request());
                logger.info("[BTPContextMenuFactory] Sent to Repeater: " + reqResp.url());
            } catch (Exception ex) {
                logger.log(Level.SEVERE, "[BTPContextMenuFactory] Error sending to Repeater", ex);
                JOptionPane.showMessageDialog(null, "Failed to send to Repeater: " + ex.getMessage());
            }
        });
        menuItems.add(sendToRepeater);

        JMenuItem copy = new JMenuItem("Copy");
        copy.addActionListener(e -> {
            try {
                ByteArray body = reqResp.response() != null ? reqResp.response().body() : null;
                StringSelection selection = new StringSelection(body == null ? "" : body.toString());
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, null);
                logger.info("[BTPContextMenuFactory] Copied response body to clipboard.");
            } catch (Exception ex) {
                logger.log(Level.SEVERE, "[BTPContextMenuFactory] Error copying to clipboard", ex);
                JOptionPane.showMessageDialog(null, "Failed to copy: " + ex.getMessage());
            }
        });
        menuItems.add(copy);

        return menuItems;
    }
}
