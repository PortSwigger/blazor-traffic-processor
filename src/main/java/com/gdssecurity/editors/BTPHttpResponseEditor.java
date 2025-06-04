/**
 * Copyright 2023 Aon plc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.gdssecurity.editors;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.extension.EditorMode;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import com.gdssecurity.MessageModel.GenericMessage;
import com.gdssecurity.helpers.BTPConstants;
import com.gdssecurity.helpers.BlazorHelper;

import java.awt.*;
import java.awt.Toolkit;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.ClipboardOwner;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;
import javax.swing.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

/**
 * Class to implement the "BTP" editor tab for HTTP responses
 */
public class BTPHttpResponseEditor implements ExtensionProvidedHttpResponseEditor {

    private MontoyaApi _montoya;
    private Logging logging;
    private HttpRequestResponse reqResp;
    private RawEditor editor;
    private BlazorHelper blazorHelper;
    private static final Logger logger = Logger.getLogger("BTP");

    static {
        try {
            FileHandler fh = new FileHandler("btp-extension.log", true);
            fh.setFormatter(new SimpleFormatter());
            logger.addHandler(fh);
            logger.setLevel(Level.ALL);
        } catch (Exception e) {
            Logger.getAnonymousLogger().log(Level.WARNING, "Failed to set up file handler for BTP logger", e);
        }
    }

    /**
     * Constructs a new BTPHttpResponseEditor based on a given message
     * @param api - instance of the MontoyaAPI
     * @param editorMode - options for the editor object
     */
    public BTPHttpResponseEditor(MontoyaApi api, EditorMode editorMode) {
        this._montoya = api;
        this.logging = this._montoya.logging();
        this.editor = this._montoya.userInterface().createRawEditor();
        this.blazorHelper = new BlazorHelper(this._montoya);
        logger.info("[BTPHttpResponseEditor] Constructor called. Thread: " + Thread.currentThread().getName());
        installEditorContextMenu();
    }

    /**
     * Returns the raw HTTP response, called when "Raw" tab is clicked
     * No need to re-serialize since, editing responses is not supported (yet)
     * @return - the HttpResponse object directly from the class variable, no need for conversion - not editing responses.
     */
    @Override
    public HttpResponse getResponse() {
        logger.info("[BTPHttpResponseEditor] getResponse() called.");
        return this.reqResp.response();
    }

    /**
     * Converts the provided HTTP response from BlazorPack to JSON, called when "BTP" tab is clicked
     * @param requestResponse - The response to deserialize from BlazorPack to JSON
     */
    private HttpRequestResponse originalReqResp;

    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        logger.info("[BTPHttpResponseEditor] setRequestResponse() called. URL: " + (requestResponse != null ? requestResponse.url() : "null"));
        this.originalReqResp = requestResponse;
        this.reqResp = requestResponse;
        assert requestResponse != null;
        byte[] body = requestResponse.response().body().getBytes();
        ArrayList<GenericMessage> messages = this.blazorHelper.blazorUnpack(body);
        ByteArrayOutputStream outstream = new ByteArrayOutputStream();
        try {
            String jsonStrMessages = this.blazorHelper.messageArrayToString(messages);
            outstream.write(jsonStrMessages.getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            String msg = "[-] setRequestResponse - IOException while writing bytes to buffer: " + e.getMessage();
            this.logging.logToError(msg);
            logger.log(Level.WARNING, "[BTPHttpResponseEditor] " + msg, e);
            this.editor.setContents(ByteArray.byteArray("An error occurred while converting Blazor to JSON."));
            return;
        } catch (Exception e) {
            String msg = "[-] setRequestResponse - Unexpected exception occurred: " + e.getMessage();
            this.logging.logToError(msg);
            logger.log(Level.SEVERE, "[BTPHttpResponseEditor] " + msg, e);
            this.editor.setContents(ByteArray.byteArray("An error occurred while converting Blazor to JSON."));
            return;
        }
        this.editor.setContents(this.reqResp.response().withBody(ByteArray.byteArray(outstream.toByteArray())).toByteArray());
    }

    /**
     * Check if the editor tab should be enabled for a given response.
     * @param requestResponse - the HTTP request/response pair to check.
     * @return true if it should be enabled, false otherwise
     */
    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        String url = null;
        try {
            url = (requestResponse != null) ? requestResponse.url() : null;
            logger.info("[BTPHttpResponseEditor] isEnabledFor() called. URL: " + url +
                    ", Thread: " + Thread.currentThread().getName() + ", Time: " + System.currentTimeMillis());
        } catch (Exception e) {
            String msg = "[BTPHttpResponseEditor] isEnabledFor: Unexpected exception: " + e.getMessage();
            logger.log(Level.SEVERE, msg, e);
            if (this.logging != null) this.logging.logToError(msg);
            return false;
        }

        if (requestResponse == null || requestResponse.response() == null) {
            logger.info("[BTPHttpResponseEditor] isEnabledFor: requestResponse or response is null.");
            return false;
        }
        if (requestResponse.response().body() == null || requestResponse.response().body().length() == 0) {
            logger.info("[BTPHttpResponseEditor] isEnabledFor: response body is null or empty.");
            return false;
        }


        // Accurate Content-Type extraction
        String contentType = null;
        for (HttpHeader header : requestResponse.response().headers()) {
            if ("Content-Type".equalsIgnoreCase(header.name())) {
                contentType = header.value();
                break;
            }
        }
        if (contentType == null || !contentType.toLowerCase().contains("application/octet-stream")) {
            logger.info("[BTPHttpResponseEditor] isEnabledFor: Content-Type is not application/octet-stream.");
            return false;
        }
        if (contentType == null || !contentType.toLowerCase().contains("application/octet-stream")) {
            logger.info("[BTPHttpResponseEditor] isEnabledFor: Content-Type is not application/octet-stream.");
            return false;
        }

        // Optionally keep your negotiation message filter
        if (requestResponse.response().body().length() == 3 && requestResponse.response().body().toString().startsWith("{}")) {
            logger.info("[BTPHttpResponseEditor] isEnabledFor: response body is negotiation message.");
            return false;
        }

        logger.info("[BTPHttpResponseEditor] isEnabledFor: returning true.");
        return true;
    }

    /**
     * Gets the caption for the response editor tab
     * @return "BTP" - BlazorTrafficProcessor
     */
    @Override
    public String caption() {
        logger.info("[BTPHttpResponseEditor] caption() called.");
        return BTPConstants.CAPTION;
    }

    /**
     * Gets the UI component of the editor
     * @return the UI component directly from the editor class variable
     */
    @Override
    public Component uiComponent() {
        logger.info("[BTPHttpResponseEditor] uiComponent() called.");
        return this.editor.uiComponent();
    }

    /**
     * Gets the data selected in the editor
     * @return - the selected data
     */
    @Override
    public Selection selectedData() {
        logger.info("[BTPHttpResponseEditor] selectedData() called.");
        return this.editor.selection().get();
    }

    private void installEditorContextMenu() {
        JPopupMenu popupMenu = new JPopupMenu();

        // "Send to Repeater"
        JMenuItem sendToRepeaterItem = new JMenuItem("Send to Repeater");
        sendToRepeaterItem.addActionListener(e -> {
            logger.info("[BTPHttpResponseEditor] 'Send to Repeater' clicked. Thread: " + Thread.currentThread().getName());
            try {
                if (this.originalReqResp != null && this.originalReqResp.response() != null) {
                    _montoya.repeater().sendToRepeater(this.originalReqResp.request(), String.valueOf(this.originalReqResp.response()));
                    logger.info("[BTPHttpResponseEditor] Sent to Repeater: " + (originalReqResp.url() != null ? originalReqResp.url() : "unknown URL"));
                } else {
                    logger.warning("[BTPHttpResponseEditor] Cannot send to Repeater: originalReqResp or response is null.");
                    JOptionPane.showMessageDialog(null, "No valid response to send to Repeater.", "Send to Repeater", JOptionPane.WARNING_MESSAGE);
                }
            } catch (Exception ex) {
                logger.log(Level.SEVERE, "[BTPHttpResponseEditor] Error sending to Repeater", ex);
                JOptionPane.showMessageDialog(null, "Failed to send to Repeater: " + ex.getMessage(), "Send to Repeater", JOptionPane.ERROR_MESSAGE);
            }
        });
        popupMenu.add(sendToRepeaterItem);

        // "Send to Intruder"
        JMenuItem sendToIntruderItem = new JMenuItem("Send to Intruder");
        sendToIntruderItem.addActionListener(e -> {
            logger.info("[BTPHttpResponseEditor] 'Send to Intruder' clicked. Thread: " + Thread.currentThread().getName());
            try {
                if (this.originalReqResp != null && this.originalReqResp.request() != null) {
                    _montoya.intruder().sendToIntruder(this.originalReqResp.request());
                    logger.info("[BTPHttpResponseEditor] Sent to Intruder: " + (originalReqResp.url() != null ? originalReqResp.url() : "unknown URL"));
                } else {
                    logger.warning("[BTPHttpResponseEditor] Cannot send to Intruder: originalReqResp or request is null.");
                    JOptionPane.showMessageDialog(null, "No valid request to send to Intruder.", "Send to Intruder", JOptionPane.WARNING_MESSAGE);
                }
            } catch (Exception ex) {
                logger.log(Level.SEVERE, "[BTPHttpResponseEditor] Error sending to Intruder", ex);
                JOptionPane.showMessageDialog(null, "Failed to send to Intruder: " + ex.getMessage(), "Send to Intruder", JOptionPane.ERROR_MESSAGE);
            }
        });
        //popupMenu.add(sendToIntruderItem);

        // Separator
        popupMenu.addSeparator();

        // "Copy"
        JMenuItem copyItem = new JMenuItem("Copy");
        copyItem.addActionListener(e -> {
            logger.info("[BTPHttpResponseEditor] 'Copy' clicked. Thread: " + Thread.currentThread().getName());
            try {
                java.util.Optional<Selection> selectionOpt = this.editor.selection();
                String selected = "";
                if (selectionOpt.isPresent()) {
                    Selection sel = selectionOpt.get();
                    selected = sel.contents().toString();
                }
                StringSelection selection = new StringSelection(selected);
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, null);
                logger.info("[BTPHttpResponseEditor] Copied selection to clipboard.");
            } catch (Exception ex) {
                logger.log(Level.SEVERE, "[BTPHttpResponseEditor] Error copying to clipboard", ex);
                JOptionPane.showMessageDialog(null, "Failed to copy: " + ex.getMessage(), "Copy", JOptionPane.ERROR_MESSAGE);
            }
        });
        popupMenu.add(copyItem);

        // Attach the popup menu to the editor component
        Component editorComponent = this.editor.uiComponent();
        editorComponent.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mousePressed(java.awt.event.MouseEvent e) {
                if (e.isPopupTrigger()) {
                    popupMenu.show(editorComponent, e.getX(), e.getY());
                    logger.info("[BTPHttpResponseEditor] Context menu shown (mousePressed). Thread: " + Thread.currentThread().getName());
                }
            }
            @Override
            public void mouseReleased(java.awt.event.MouseEvent e) {
                if (e.isPopupTrigger()) {
                    popupMenu.show(editorComponent, e.getX(), e.getY());
                    logger.info("[BTPHttpResponseEditor] Context menu shown (mouseReleased). Thread: " + Thread.currentThread().getName());
                }
            }
        });
    }




    /**
     * Checks if the editor text has been modified
     * @return true if it has, false otherwise
     */
    @Override
    public boolean isModified() {
        return this.editor.isModified();
    }
}


