package com.nccgroup.loggerplusplus.logview.logtable;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.loggerplusplus.filterlibrary.FilterLibraryController;
import com.nccgroup.loggerplusplus.logview.LogViewController;
import com.nccgroup.loggerplusplus.util.Globals;

public class LogTableController {

    private final LogViewController logViewController;
    private final FilterLibraryController filterLibraryController;
    private final Preferences preferences;
    private final LogTableModel logTableModel;
    private final LogTableColumnModel logTableColumnModel;
    private final TableHeader tableHeader;
    private final LogTable logTable;

    public LogTableController(LogViewController logViewController, FilterLibraryController filterLibraryController){
        this.logViewController = logViewController;
        this.filterLibraryController = filterLibraryController;
        this.preferences = logViewController.getPreferences();

        this.logTableColumnModel = new LogTableColumnModel(this);
        this.logTableModel = new LogTableModel(this, logTableColumnModel);
        this.tableHeader = new TableHeader(this);
        this.logTable = new LogTable(this);

        this.filterLibraryController.addColorFilterListener(logTableModel);
        this.filterLibraryController.addTagListener(logTableModel);
    }

    public LogViewController getLogViewController() {
        return logViewController;
    }

    public LogTableColumnModel getLogTableColumnModel() {
        return logTableColumnModel;
    }

    public LogTableModel getLogTableModel() {
        return logTableModel;
    }

    public LogTable getLogTable() {
        return logTable;
    }

    public TableHeader getTableHeader() {
        return tableHeader;
    }

    public Preferences getPreferences() {
        return preferences;
    }


    public void reset(){
        logTableModel.reset();
    }

    public int getMaximumEntries(){
        return preferences.getSetting(Globals.PREF_MAXIMUM_ENTRIES);
    }

    public void reinitialize(){
        //TODO Reinitialize table model
    }
}
