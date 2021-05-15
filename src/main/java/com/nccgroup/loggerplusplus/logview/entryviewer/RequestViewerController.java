package com.nccgroup.loggerplusplus.logview.entryviewer;

import burp.IHttpRequestResponse;
import burp.IHttpService;
import burp.IMessageEditor;
import burp.IMessageEditorController;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;

public class RequestViewerController implements IMessageEditorController {

    private final Preferences preferences;
    private final IMessageEditor requestEditor;
    private final IMessageEditor responseEditor;
    private final RequestViewerPanel requestViewerPanel;

    private IHttpRequestResponse currentItem;

    public RequestViewerController(Preferences preferences, boolean requestEditable, boolean responseEditable) {
        this.preferences = preferences;
        this.requestEditor = LoggerPlusPlus.callbacks.createMessageEditor(this, requestEditable);
        this.responseEditor = LoggerPlusPlus.callbacks.createMessageEditor(this, responseEditable);
        this.requestViewerPanel = new RequestViewerPanel(this);
    }

    public IHttpRequestResponse getDisplayedEntity() {
        return this.currentItem;
    }

    public void setDisplayedEntity(IHttpRequestResponse requestResponse) {
        if(requestResponse != null && requestResponse.equals(currentItem)) return;

        this.currentItem = requestResponse;
        if (requestResponse != null && requestResponse.getRequest() != null) {
            requestEditor.setMessage(requestResponse.getRequest(), true);
        }else{
            requestEditor.setMessage(new byte[0], false);
        }

        if (requestResponse != null && requestResponse.getResponse() != null) {
            responseEditor.setMessage(requestResponse.getResponse(), false);
        }else {
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
    public byte[] getRequest()
    {
        if(currentItem == null || currentItem.getRequest() == null)
            return new byte[0];
        else
            return currentItem.getRequest();
    }

    @Override
    public byte[] getResponse()
    {
        if(currentItem == null || currentItem.getResponse() == null)
            return new byte[0];
        else
            return currentItem.getResponse();
    }

    @Override
    public IHttpService getHttpService()
    {
        if(currentItem == null) return null;
        return currentItem.getHttpService();
    }
}
