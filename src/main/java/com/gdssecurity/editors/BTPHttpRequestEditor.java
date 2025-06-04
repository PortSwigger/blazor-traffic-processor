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
import burp.api.montoya.http.message.ContentType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.logging.Logging;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.extension.EditorMode;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import com.gdssecurity.MessageModel.GenericMessage;
import com.gdssecurity.helpers.ArraySliceHelper;
import com.gdssecurity.helpers.BTPConstants;
import com.gdssecurity.helpers.BlazorHelper;
import org.json.JSONArray;
import org.json.JSONException;

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
 * Class to implement the "BTP" editor tab for HTTP requests
 */
public class BTPHttpRequestEditor implements ExtensionProvidedHttpRequestEditor {

    private final MontoyaApi montoya;
    private HttpRequestResponse reqResp;
    private final RawEditor editor;
    private final BlazorHelper blazorHelper;
    private final Logging logging;
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

    private void installEditorContextMenu() {
        JPopupMenu popupMenu = new JPopupMenu();

        JMenuItem copyItem = new JMenuItem("Copy");
        copyItem.addActionListener(e -> {
            try {
                java.util.Optional<Selection> selectionOpt = this.editor.selection();
                String selected = "";
                if (selectionOpt.isPresent()) {
                    Selection sel = selectionOpt.get();
                    selected = sel.contents().toString();
                }
                StringSelection selection = new StringSelection(selected);
                Toolkit.getDefaultToolkit().getSystemClipboard().setContents(selection, null);
                logger.info("[BTPHttpRequestEditor] Copied selection to clipboard.");
            } catch (Exception ex) {
                logger.log(Level.SEVERE, "[BTPHttpRequestEditor] Error copying to clipboard", ex);
            }
        });



        popupMenu.add(copyItem);

        // Add more menu items as needed...

        Component editorComponent = this.editor.uiComponent();
        editorComponent.addMouseListener(new MouseAdapter() {
            @Override
            public void mousePressed(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    popupMenu.show(editorComponent, e.getX(), e.getY());
                }
            }
            @Override
            public void mouseReleased(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    popupMenu.show(editorComponent, e.getX(), e.getY());
                }
            }
        });
    }


    /**
     * Constructs a new BTPHttpRequestEditor object.
     * @param api An instance of the Montoya API.
     * @param editorMode Options for the editor object.
     */
    public BTPHttpRequestEditor(MontoyaApi api, EditorMode editorMode) {
        this.montoya = api;
        this.editor = this.montoya.userInterface().createRawEditor();
        this.blazorHelper = new BlazorHelper(this.montoya);
        this.logging = this.montoya.logging();
        installEditorContextMenu();
        logger.info(() -> String.format("[%1$tF %1$tT][%2$s][BTPHttpRequestEditor] Constructor called.",
                System.currentTimeMillis(), Thread.currentThread().getName()));
    }

    /**
     * Converts a JSON message to BlazorPack, called when the "Raw" tab is clicked
     * Just return the existing request body if editor not modified, re-serialize if editor is modified
     * @return - an HttpRequest object containing the BlazorPacked HTTP request/response pair
     */
    @Override
    public HttpRequest getRequest() {
        logger.info(() -> String.format("[%1$tF %1$tT][%2$s][BTPHttpRequestEditor] getRequest() called. isModified: %3$s",
                System.currentTimeMillis(), Thread.currentThread().getName(), this.editor.isModified()));
        byte[] body;
        if (this.editor.isModified()) {
            int bodyOffset = this.blazorHelper.getBodyOffset(this.editor.getContents().getBytes());
            body = ArraySliceHelper.getArraySlice(this.editor.getContents().getBytes(), bodyOffset, this.editor.getContents().length());
        } else {
            body = this.reqResp.request().body().getBytes();
        }
        if (body == null || body.length == 0) {
            String msg = "[-] getRequest: The selected editor body is empty/null.";
            this.logging.logToError(msg);
            logger.warning("[BTPHttpRequestEditor] " + msg);
            return null;
        }
        JSONArray messages;
        byte[] newBody;
        try {
            messages = new JSONArray(new String(body));
            newBody = this.blazorHelper.blazorPack(messages);
        } catch (JSONException e) {
            String msg = "[-] getRequest - JSONException while parsing JSON array: " + e.getMessage();
            this.logging.logToError(msg);
            logger.log(Level.WARNING, "[BTPHttpRequestEditor] " + msg, e);
            return null;
        } catch (Exception e) {
            String msg = "[-] getRequest - Unexpected exception while getting the request: " + e.getMessage();
            this.logging.logToError(msg);
            logger.log(Level.SEVERE, "[BTPHttpRequestEditor] " + msg, e);
            return null;
        }
        logger.info(() -> String.format("[%1$tF %1$tT][%2$s][BTPHttpRequestEditor] getRequest() returning new HttpRequest with body length: %3$d",
                System.currentTimeMillis(), Thread.currentThread().getName(), (newBody != null ? newBody.length : 0)));
        return this.reqResp.request().withBody(ByteArray.byteArray(newBody));
    }

    /**
     * Converts a given BlazorPack message to JSON, called when the "BTP" tab is clicked.
     * Handles filtering: disables the editor and shows a message if not a BlazorPack request.
     * @param requestResponse The request to deserialize from BlazorPack to JSON.
     */
    @Override
    public void setRequestResponse(HttpRequestResponse requestResponse) {
        logger.info(() -> String.format("[%1$tF %1$tT][%2$s][BTPHttpRequestEditor] setRequestResponse() called. URL: %3$s",
                System.currentTimeMillis(), Thread.currentThread().getName(), (requestResponse != null ? safeUrl(requestResponse) : "null")));
        this.reqResp = requestResponse;

        // Filtering: Only handle BlazorPack requests
        boolean isBlazorPack = requestResponse != null &&
                requestResponse.request() != null &&
                requestResponse.request().body() != null &&
                requestResponse.request().body().length() > 0 &&
                requestResponse.url() != null &&
                requestResponse.url().contains(BTPConstants.BLAZOR_URL);

        if (!isBlazorPack) {
            this.editor.setContents(ByteArray.byteArray("Not a BlazorPack request.".getBytes(StandardCharsets.UTF_8)));
            this.editor.setEditable(false);
            logger.info(() -> String.format("[%1$tF %1$tT][%2$s][BTPHttpRequestEditor] Not a BlazorPack request. Editor disabled.",
                    System.currentTimeMillis(), Thread.currentThread().getName()));
            return;
        }

        this.editor.setEditable(true);

        byte[] body = requestResponse.request().body().getBytes();
        ArrayList<GenericMessage> messages = this.blazorHelper.blazorUnpack(body);
        ByteArrayOutputStream outstream = new ByteArrayOutputStream();
        try {
            String jsonStrMessages = this.blazorHelper.messageArrayToString(messages);
            outstream.write(jsonStrMessages.getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            String msg = "[-] setRequestResponse - IOException while writing bytes to buffer: " + e.getMessage();
            this.logging.logToError(msg);
            logger.log(Level.WARNING, "[BTPHttpRequestEditor] " + msg, e);
            return;
        } catch (JSONException e) {
            String msg = "[-] setRequestResponse - JSONException while parsing JSON array: " + e.getMessage();
            this.logging.logToError(msg);
            logger.log(Level.WARNING, "[BTPHttpRequestEditor] " + msg, e);
            return;
        } catch (Exception e) {
            String msg = "[-] setRequestResponse - Unexpected exception: " + e.getMessage();
            this.logging.logToError(msg);
            logger.log(Level.SEVERE, "[BTPHttpRequestEditor] " + msg, e);
            return;
        }
        HttpRequest newReq = this.reqResp.request().withBody(ByteArray.byteArray(outstream.toByteArray()));
        this.reqResp = HttpRequestResponse.httpRequestResponse(newReq, this.reqResp.response());
        this.editor.setContents(this.reqResp.request().toByteArray());

        logger.info(() -> String.format("[%1$tF %1$tT][%2$s][BTPHttpRequestEditor] setRequestResponse() completed. Editor contents set.",
                System.currentTimeMillis(), Thread.currentThread().getName()));
    }

    /**
     * Helper to safely get URL for logging without throwing.
     */
    private String safeUrl(HttpRequestResponse requestResponse) {
        try {
            return requestResponse.url();
        } catch (Exception e) {
            return "MALFORMED_URL";
        }
    }

    /**
     * Gets the caption for the editor tab.
     * @return "BTP" - BlazorTrafficProcessor
     */
    @Override
    public String caption() {
        logger.info(() -> String.format("[%1$tF %1$tT][%2$s][BTPHttpRequestEditor] caption() called.",
                System.currentTimeMillis(), Thread.currentThread().getName()));
        return BTPConstants.CAPTION;
    }

    /**
     * Gets the UI component for the editor tab.
     * @return The editor's UI component.
     */
    @Override
    public Component uiComponent() {
        logger.info(() -> String.format("[%1$tF %1$tT][%2$s][BTPHttpRequestEditor] uiComponent() called.",
                System.currentTimeMillis(), Thread.currentThread().getName()));
        return this.editor.uiComponent();
    }

    /**
     * Get the selected data within the editor.
     * @return The editor's selection object.
     */
    @Override
    public Selection selectedData() {
        logger.info(() -> String.format("[%1$tF %1$tT][%2$s][BTPHttpRequestEditor] selectedData() called.",
                System.currentTimeMillis(), Thread.currentThread().getName()));
        return this.editor.selection().get();
    }

    /**
     * Check if the editor has been modified. If not, the getHttpRequest function is not called.
     * @return true if modified, false otherwise.
     */
    @Override
    public boolean isModified() {
        boolean modified = this.editor.isModified();
        logger.info(() -> String.format("[%1$tF %1$tT][%2$s][BTPHttpRequestEditor] isModified() called. Result: %3$s",
                System.currentTimeMillis(), Thread.currentThread().getName(), modified));
        return modified;
    }

    @Override
    public boolean isEnabledFor(HttpRequestResponse requestResponse) {
        logger.info(() -> String.format("[%1$tF %1$tT][%2$s][BTPHttpRequestEditor] isEnabledFor() called. URL: %3$s",
                System.currentTimeMillis(), Thread.currentThread().getName(),
                (requestResponse != null ? safeUrl(requestResponse) : "null")));

        if (requestResponse == null || requestResponse.request() == null) {
            logger.info("[BTPHttpRequestEditor] isEnabledFor: requestResponse or request is null.");
            return false;
        }
        if (requestResponse.request().body() == null || requestResponse.request().body().length() == 0) {
            logger.info("[BTPHttpRequestEditor] isEnabledFor: request body is null or empty.");
            return false;
        }
        String url;
        try {
            url = requestResponse.url();
        } catch (Exception e) {
            logger.log(Level.WARNING, "[BTPHttpRequestEditor] isEnabledFor: Exception getting URL: " + e.getMessage(), e);
            return false;
        }
        if (url == null) {
            logger.info("[BTPHttpRequestEditor] isEnabledFor: url is null.");
            return false;
        }
        if (!url.contains(BTPConstants.BLAZOR_URL)) {
            logger.info("[BTPHttpRequestEditor] isEnabledFor: url does not contain BLAZOR_URL (" + BTPConstants.BLAZOR_URL + ").");
            return false;
        }
        logger.info("[BTPHttpRequestEditor] isEnabledFor: returning true.");
        return true;
    }

}
