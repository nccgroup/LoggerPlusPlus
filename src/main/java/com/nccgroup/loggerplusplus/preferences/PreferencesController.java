package com.nccgroup.loggerplusplus.preferences;

import burp.api.montoya.MontoyaApi;
import com.coreyd97.BurpExtenderUtilities.IGsonProvider;
import com.coreyd97.BurpExtenderUtilities.ILogProvider;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.logging.Log;
import lombok.Getter;

public class PreferencesController {

    @Getter
    private final IGsonProvider gsonProvider;

    @Getter
    private final Preferences preferences;

    private PreferencesPanel preferencesPanel;

    public PreferencesController(MontoyaApi montoya) {
        this.gsonProvider = LoggerPlusPlus.gsonProvider;
        this.preferences = new LoggerPreferenceFactory(montoya,
                gsonProvider,
                new ILogProvider() {
                    @Override
                    public void logOutput(String message) {
                        Log.debug(message);
                    }

                    @Override
                    public void logError(String errorMessage) {
                        Log.error(errorMessage);
                    }
                }
        ).buildPreferences();
    }

    public PreferencesPanel getPreferencesPanel() {
        if(this.preferencesPanel == null) {
            this.preferencesPanel = new PreferencesPanel(this);
        }

        return preferencesPanel;
    }
}
