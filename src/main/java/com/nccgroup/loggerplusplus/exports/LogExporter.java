package com.nccgroup.loggerplusplus.exports;

import com.coreyd97.BurpExtenderUtilities.Preferences;

public abstract class LogExporter {

    protected final ExportController exportController;
    protected final Preferences preferences;

    protected LogExporter(ExportController exportController, Preferences preferences){
        this.exportController = exportController;
        this.preferences = preferences;
    }

    public Preferences getPreferences() {
        return preferences;
    }
}
