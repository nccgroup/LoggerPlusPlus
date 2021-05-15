package com.nccgroup.loggerplusplus.logview;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.coreyd97.BurpExtenderUtilities.VariableViewPanel;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.filter.logfilter.LogFilterController;
import com.nccgroup.loggerplusplus.filterlibrary.FilterLibraryController;
import com.nccgroup.loggerplusplus.logview.entryviewer.RequestViewerController;
import com.nccgroup.loggerplusplus.logview.logtable.LogTableController;

public class LogViewController {

    private final LoggerPlusPlus loggerPlusPlus;
    private final FilterLibraryController filterLibraryController;
    private final Preferences preferences;
    private final LogFilterController logFilterController;
    private final LogTableController logTableController;
    private final RequestViewerController requestViewerController;

    private final LogViewPanel logViewPanel;

    public LogViewController(LoggerPlusPlus loggerPlusPlus, FilterLibraryController filterLibraryController){
        this.loggerPlusPlus = loggerPlusPlus;
        this.filterLibraryController = filterLibraryController;
        this.preferences = loggerPlusPlus.getPreferencesController().getPreferences();

        this.logTableController = new LogTableController(this, filterLibraryController);
        this.logFilterController = new LogFilterController(this);
        this.requestViewerController = new RequestViewerController(preferences, false, false);

        //Build UI
        this.logViewPanel = new LogViewPanel(this);
    }

    public void setPanelLayout(VariableViewPanel.View view){
        this.logViewPanel.getTableViewerSplitPanel().setView(view);
    }

    public void setEntryViewerLayout(VariableViewPanel.View view){
        this.logViewPanel.getRequestViewerPanel().getVariableViewPanel().setView(view);
    }

    public LoggerPlusPlus getLoggerPlusPlus() {
        return loggerPlusPlus;
    }

    public LogViewPanel getLogViewPanel() {
        return logViewPanel;
    }

    public LogFilterController getLogFilterController() {
        return logFilterController;
    }

    public LogTableController getLogTableController() {
        return logTableController;
    }

    public RequestViewerController getRequestViewerController() {
        return requestViewerController;
    }

    public Preferences getPreferences() {
        return preferences;
    }
}
