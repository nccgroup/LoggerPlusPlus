package com.nccgroup.loggerplusplus.exports;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.loggerplusplus.logentry.LogEntry;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

public class ExportController {
    private final Preferences preferences;
    private final HashMap<Class<? extends LogExporter>, LogExporter> exporters;
    private final List<AutomaticLogExporter> enabledExporters;

    public ExportController(Preferences preferences) {
        this.preferences = preferences;

        this.exporters = new HashMap<>();
        this.enabledExporters = Collections.synchronizedList(new ArrayList<>());

        initializeExporters();
    }

    private void initializeExporters() {
        this.exporters.put(CSVExporter.class, new CSVExporter(this, preferences));
        this.exporters.put(JSONExporter.class, new JSONExporter(this, preferences));
        this.exporters.put(HARExporter.class, new HARExporter(this, preferences));
        this.exporters.put(Base64Exporter.class, new Base64Exporter(this, preferences));
        this.exporters.put(ElasticExporter.class, new ElasticExporter(this, preferences));
    }

    public HashMap<Class<? extends LogExporter>, LogExporter> getExporters() {
        return exporters;
    }

    public List<AutomaticLogExporter> getEnabledExporters() {
        return enabledExporters;
    }

    public void enableExporter(AutomaticLogExporter logExporter) throws Exception {
        logExporter.setup();
        this.enabledExporters.add(logExporter);
    }

    public void disableExporter(AutomaticLogExporter logExporter) throws Exception {
        this.enabledExporters.remove(logExporter);
        logExporter.shutdown();
    }

    public void exportNewEntry(LogEntry logEntry) {
        for (AutomaticLogExporter exporter : this.enabledExporters) {
            exporter.exportNewEntry(logEntry);
        }
    }

    public void exportUpdatedEntry(LogEntry logEntry) {
        for (AutomaticLogExporter exporter : this.enabledExporters) {
            exporter.exportUpdatedEntry(logEntry);
        }
    }
}
