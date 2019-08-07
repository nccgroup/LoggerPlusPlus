package loggerplusplus;

import burp.*;

public class RequestViewerController implements IMessageEditorController {

    private IHttpRequestResponse currentItem;
    private IMessageEditor requestEditor;
    private IMessageEditor responseEditor;

    public RequestViewerController(IBurpExtenderCallbacks callbacks, boolean requestEditable, boolean responseEditable){
        requestEditor = callbacks.createMessageEditor(this, requestEditable);
        responseEditor = callbacks.createMessageEditor(this, responseEditable);
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
