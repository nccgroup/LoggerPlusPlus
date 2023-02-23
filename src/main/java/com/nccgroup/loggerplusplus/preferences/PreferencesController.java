package com.nccgroup.loggerplusplus.preferences;

import burp.api.montoya.MontoyaApi;
import com.coreyd97.BurpExtenderUtilities.IGsonProvider;
import com.coreyd97.BurpExtenderUtilities.ILogProvider;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import lombok.Getter;
import lombok.extern.log4j.Log4j2;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

@Log4j2
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
                        log.debug(message);
                    }

                    @Override
                    public void logError(String errorMessage) {
                        log.error(errorMessage);
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
