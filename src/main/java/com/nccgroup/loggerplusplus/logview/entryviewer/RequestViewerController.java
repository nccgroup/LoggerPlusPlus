package com.nccgroup.loggerplusplus.logview.entryviewer;

import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.logentry.LogEntry;
import lombok.Getter;

@Getter
public class RequestViewerController {

    private final Preferences preferences;
    private final HttpRequestEditor requestEditor;
    private final HttpResponseEditor responseEditor;
    private final RequestViewerPanel requestViewerPanel;

    private LogEntry currentEntry;

    public RequestViewerController(Preferences preferences) {
        this.preferences = preferences;
        this.requestEditor = LoggerPlusPlus.montoya.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        this.responseEditor = LoggerPlusPlus.montoya.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
        this.requestViewerPanel = new RequestViewerPanel(this);
    }

    public void setDisplayedEntity(LogEntry logEntry) {
        // Only update message if it's new. This fixes issue #164 and improves performance during heavy scanning.
        if (this.currentEntry == logEntry) { return; }

        this.currentEntry = logEntry;

        if (logEntry == null || logEntry.getRequest() == null) {
            requestEditor.setRequest(null);
        }else{
            requestEditor.setRequest(logEntry.getRequest());
        }

        if (logEntry == null || logEntry.getResponse() == null) {
            responseEditor.setResponse(null);
        }else{
            responseEditor.setResponse(logEntry.getResponse());
        }
    }

    public void setMarkers(){

    }
}
