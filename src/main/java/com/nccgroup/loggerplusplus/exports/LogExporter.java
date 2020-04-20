package com.nccgroup.loggerplusplus.exports;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.logentry.LogEntry;

import javax.swing.*;
import java.util.List;

public abstract class LogExporter {

    protected final ExportController exportController;
    protected final Preferences preferences;

    protected LogExporter(ExportController exportController, Preferences preferences){
        this.exportController = exportController;
        this.preferences = preferences;
    }

    public abstract void exportEntries(List<LogEntry> entries) throws Exception;

    /**
     * Build the control panel to be displayed in the preferences tab
     * @return
     */
    public abstract JComponent getExportPanel();

    public abstract JMenuItem getExportEntriesMenuItem(List<LogEntry> entries);

    public Preferences getPreferences() {
        return preferences;
    }
}
