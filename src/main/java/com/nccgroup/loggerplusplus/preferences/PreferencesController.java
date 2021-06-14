package com.nccgroup.loggerplusplus.preferences;

import com.coreyd97.BurpExtenderUtilities.IGsonProvider;
import com.coreyd97.BurpExtenderUtilities.ILogProvider;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class PreferencesController {
    private final LoggerPlusPlus loggerPlusPlus;
    private final IGsonProvider gsonProvider;
    private final Preferences preferences;

    private PreferencesPanel preferencesPanel;

    private Logger logger = LogManager.getLogger(this.getClass());

    public PreferencesController(LoggerPlusPlus loggerPlusPlus) {
        this.loggerPlusPlus = loggerPlusPlus;
        this.gsonProvider = loggerPlusPlus.getGsonProvider();
        this.preferences = new LoggerPreferenceFactory(
                gsonProvider,
                new ILogProvider() {
                    @Override
                    public void logOutput(String message) {
                        logger.debug(message);
                    }

                    @Override
                    public void logError(String errorMessage) {
                        logger.error(errorMessage);
                    }
                },
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
