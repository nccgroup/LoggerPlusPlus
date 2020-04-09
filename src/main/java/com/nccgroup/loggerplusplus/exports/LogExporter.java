package com.nccgroup.loggerplusplus.exports;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.logentry.LogEntry;

import javax.swing.*;

public abstract class LogExporter {

    protected final ExportController exportController;
    protected final Preferences preferences;

    protected LogExporter(ExportController exportController, Preferences preferences){
        this.exportController = exportController;
        this.preferences = preferences;
    }

    /**
     * Configure the exporter ready for use
     * @throws Exception Setup not completed
     */
    abstract void setup() throws Exception;

    /**
     * Handle the export of a received entry
     * @param logEntry
     */
    abstract void exportNewEntry(LogEntry logEntry);

    /**
     * Handle the export of a received entry
     * @param logEntry
     */
    abstract void exportUpdatedEntry(LogEntry logEntry);

    /**
     * Clean up the exporter and its resources
     * @throws Exception
     */
    abstract void shutdown() throws Exception;

    /**
     * Build the control panel to be displayed in the preferences tab
     * @return
     */
    public abstract JComponent getExportPanel();

}
