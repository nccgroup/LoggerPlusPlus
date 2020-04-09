package com.nccgroup.loggerplusplus.exports;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.logentry.LogEntry;
import com.nccgroup.loggerplusplus.preferences.PreferencesController;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class ExportController {

    private final LoggerPlusPlus loggerPlusPlus;
    private final Preferences preferences;
    private final List<LogExporter> exporters;
    private final List<LogExporter> enabledExporters;
    
    public ExportController(LoggerPlusPlus loggerPlusPlus, Preferences preferences){
        this.loggerPlusPlus = loggerPlusPlus;
        this.preferences = preferences;

        this.exporters = new ArrayList<>();
        this.enabledExporters = Collections.synchronizedList(new ArrayList());

        initializeExporters();
    }

    private void initializeExporters(){
        this.exporters.add(new CSVExporter(this, preferences));
    }

    public List<LogExporter> getExporters() {
        return exporters;
    }

    public List<LogExporter> getEnabledExporters() {
        return enabledExporters;
    }

    public void enableExporter(LogExporter logExporter) throws Exception {
        logExporter.setup();
        this.enabledExporters.add(logExporter);
    }

    public void disableExporter(LogExporter logExporter) throws Exception {
        this.enabledExporters.remove(logExporter);
        logExporter.shutdown();
    }

    public void exportNewEntry(LogEntry logEntry){
        for (LogExporter exporter : this.enabledExporters) {
            exporter.exportNewEntry(logEntry);
        }
    }

    public void exportUpdatedEntry(LogEntry logEntry){
        for (LogExporter exporter : this.enabledExporters) {
            exporter.exportUpdatedEntry(logEntry);
        }
    }

    public LoggerPlusPlus getLoggerPlusPlus() {
        return loggerPlusPlus;
    }
}
