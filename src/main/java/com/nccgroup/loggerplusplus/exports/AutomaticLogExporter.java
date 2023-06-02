package com.nccgroup.loggerplusplus.exports;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.loggerplusplus.logentry.LogEntry;

public abstract class AutomaticLogExporter extends LogExporter {

    protected AutomaticLogExporter(ExportController exportController, Preferences preferences){
        super(exportController, preferences);
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

}
