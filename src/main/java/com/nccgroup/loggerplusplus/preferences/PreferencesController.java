package com.nccgroup.loggerplusplus.preferences;

import com.coreyd97.BurpExtenderUtilities.IGsonProvider;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.logging.LoggingController;
import com.nccgroup.loggerplusplus.util.Globals;

import java.util.Arrays;
import java.util.HashSet;

public class PreferencesController {
    private final LoggerPlusPlus loggerPlusPlus;
    private final IGsonProvider gsonProvider;
    private final Preferences preferences;

    private PreferencesPanel preferencesPanel;

    public PreferencesController(LoggerPlusPlus loggerPlusPlus, LoggingController loggingController) {
        this.loggerPlusPlus = loggerPlusPlus;
        this.gsonProvider = loggerPlusPlus.getGsonProvider();
        this.preferences = new LoggerPreferenceFactory(
                gsonProvider,
                loggingController,
                LoggerPlusPlus.callbacks
        ).buildPreferences();
    }

    public PreferencesPanel getPreferencesPanel() {
        if(preferencesPanel == null) {
            preferencesPanel = new PreferencesPanel(this);
        }
        return preferencesPanel;
    }

    public LoggerPlusPlus getLoggerPlusPlus() {
        return loggerPlusPlus;
    }

    public IGsonProvider getGsonProvider() {
        return gsonProvider;
    }

    public Preferences getPreferences() {
        return preferences;
    }
}
