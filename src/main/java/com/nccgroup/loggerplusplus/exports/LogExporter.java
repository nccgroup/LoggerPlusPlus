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
     * Build the control panel to be displayed in the preferences tab
     * @return
     */
    public abstract JComponent getExportPanel();

    public Preferences getPreferences() {
        return preferences;
    }
}
