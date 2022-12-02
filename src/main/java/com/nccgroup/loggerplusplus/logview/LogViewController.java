package com.nccgroup.loggerplusplus.logview;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.coreyd97.BurpExtenderUtilities.VariableViewPanel;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.filter.logfilter.LogFilterController;
import com.nccgroup.loggerplusplus.filterlibrary.FilterLibraryController;
import com.nccgroup.loggerplusplus.logview.entryviewer.RequestViewerController;
import com.nccgroup.loggerplusplus.logview.logtable.LogTableController;
import lombok.Getter;

public class LogViewController {

    @Getter
    private final FilterLibraryController filterLibraryController;

    @Getter
    private final Preferences preferences;

    @Getter
    private final LogFilterController logFilterController;

    @Getter
    private final LogTableController logTableController;

    @Getter
    private final RequestViewerController requestViewerController;

    @Getter
    private final LogViewPanel logViewPanel;

    public LogViewController(FilterLibraryController filterLibraryController){
        this.filterLibraryController = filterLibraryController;
        this.preferences = LoggerPlusPlus.instance.getPreferencesController().getPreferences();

        this.logTableController = new LogTableController(this, filterLibraryController);
        this.logFilterController = new LogFilterController(this);
        this.requestViewerController = new RequestViewerController(preferences);

        //Build UI
        this.logViewPanel = new LogViewPanel(this);
    }

    public void setPanelLayout(VariableViewPanel.View view){
        this.logViewPanel.getTableViewerSplitPanel().setView(view);
    }

    public void setEntryViewerLayout(VariableViewPanel.View view){
        this.logViewPanel.getRequestViewerPanel().getVariableViewPanel().setView(view);
    }
}
