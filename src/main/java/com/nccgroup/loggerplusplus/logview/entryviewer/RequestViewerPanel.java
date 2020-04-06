package com.nccgroup.loggerplusplus.logview.entryviewer;

import com.coreyd97.BurpExtenderUtilities.PopOutPanel;
import com.coreyd97.BurpExtenderUtilities.VariableViewPanel;
import com.nccgroup.loggerplusplus.util.Globals;

public class RequestViewerPanel extends PopOutPanel {

    private final RequestViewerController controller;
    private final VariableViewPanel variableViewPanel;

    public RequestViewerPanel(RequestViewerController controller){
        super();
        this.controller = controller;

        this.variableViewPanel = new VariableViewPanel(controller.getPreferences(), Globals.PREF_MESSAGE_VIEW_LAYOUT,
                controller.getRequestEditor().getComponent(), "Request",
                controller.getResponseEditor().getComponent(), "Response",
                VariableViewPanel.View.HORIZONTAL);

        this.setComponent(variableViewPanel);
        this.setTitle("Request/Response Viewer");
        //TODO set log view variable panel to Vertical when popped out
    }

    public VariableViewPanel getVariableViewPanel() {
        return variableViewPanel;
    }
}
