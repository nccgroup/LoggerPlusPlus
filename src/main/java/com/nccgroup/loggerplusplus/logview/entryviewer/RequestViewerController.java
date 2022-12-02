package com.nccgroup.loggerplusplus.logview.entryviewer;

import burp.IHttpService;
import burp.IMessageEditor;
import burp.IMessageEditorController;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.logentry.LogEntry;

public class RequestViewerController implements IMessageEditorController {

    private final Preferences preferences;
    private final IMessageEditor requestEditor;
    private final IMessageEditor responseEditor;
    private final RequestViewerPanel requestViewerPanel;

    private LogEntry currentEntry;

    public RequestViewerController(Preferences preferences, boolean requestEditable, boolean responseEditable) {
        this.preferences = preferences;
        this.requestEditor = LoggerPlusPlus.callbacks.createMessageEditor(this, requestEditable);
        this.responseEditor = LoggerPlusPlus.callbacks.createMessageEditor(this, responseEditable);
        this.requestViewerPanel = new RequestViewerPanel(this);
    }

    public void setDisplayedEntity(LogEntry logEntry) {
        // Only update message if it's new. This fixes issue #164 and improves performance during heavy scanning.
        if (this.currentEntry == logEntry) { return; }

        this.currentEntry = logEntry;

        if (logEntry == null) {
            requestEditor.setMessage(new byte[0], true);
            responseEditor.setMessage(new byte[0], false);
            return;
        }

        if (logEntry.getRequest() != null) {
            requestEditor.setMessage(logEntry.getRequest(), true);
        } else {
            requestEditor.setMessage(new byte[0], true);
        }

        if (logEntry.getResponse() != null) {
            responseEditor.setMessage(logEntry.getResponse(), false);
        } else {
            responseEditor.setMessage(new byte[0], false);
        }
    }

    public IMessageEditor getRequestEditor() {
        return requestEditor;
    }

    public IMessageEditor getResponseEditor() {
        return responseEditor;
    }

    public Preferences getPreferences() {
        return preferences;
    }

    public RequestViewerPanel getRequestViewerPanel() {
        return requestViewerPanel;
    }

    @Override
    public byte[] getRequest() {
        if (currentEntry != null && currentEntry.getRequest() != null) {
            return currentEntry.getRequest();
        } else {
            return new byte[0];
        }
    }

    @Override
    public byte[] getResponse() {
        if (currentEntry != null && currentEntry.getResponse() != null) {
            return currentEntry.getResponse();
        } else {
            return new byte[0];
        }
    }

    @Override
    public IHttpService getHttpService() {
        if (currentEntry == null) return null;
        return currentEntry.getHttpService();
    }
}
