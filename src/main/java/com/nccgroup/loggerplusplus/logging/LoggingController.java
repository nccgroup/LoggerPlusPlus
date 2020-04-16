package com.nccgroup.loggerplusplus.logging;

import burp.IBurpExtenderCallbacks;
import com.coreyd97.BurpExtenderUtilities.IGsonProvider;
import com.coreyd97.BurpExtenderUtilities.ILogProvider;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.util.Globals;

public class LoggingController implements ILogProvider {

    private final LoggerPlusPlus loggerPlusPlus;
    private final IGsonProvider gsonProvider;
    private IBurpExtenderCallbacks callbacks;

    public LoggingController(LoggerPlusPlus loggerPlusPlus){
        this.loggerPlusPlus = loggerPlusPlus;
        this.gsonProvider = loggerPlusPlus.getGsonProvider();
        this.callbacks = LoggerPlusPlus.callbacks;
    }

    @Override
    public void logOutput(String message) {
        callbacks.printOutput(message);

        Preferences preferences = loggerPlusPlus.getPreferencesController() != null ?
                loggerPlusPlus.getPreferencesController().getPreferences() : null;

        if(preferences == null) {
            Boolean isDebug = gsonProvider.getGson().fromJson(callbacks.loadExtensionSetting(Globals.PREF_IS_DEBUG), Boolean.class);
            if(isDebug != null && isDebug){
                System.out.println(message);
            }
        }else{
            if (preferences.getSetting(Globals.PREF_IS_DEBUG) != null
                    && (boolean) preferences.getSetting(Globals.PREF_IS_DEBUG)) {
                System.out.println(message);
            }
        }
    }

    @Override
    public void logError(String errorMessage) {
        callbacks.printError(errorMessage);

        Preferences preferences = loggerPlusPlus.getPreferencesController() != null ?
                loggerPlusPlus.getPreferencesController().getPreferences() : null;

        if(preferences == null) {
            Boolean isDebug = gsonProvider.getGson().fromJson(callbacks.loadExtensionSetting(Globals.PREF_IS_DEBUG), Boolean.class);
            if(isDebug != null && isDebug){
                System.err.println(errorMessage);
            }
        }else{
            if (preferences.getSetting(Globals.PREF_IS_DEBUG) != null
                    && (boolean) preferences.getSetting(Globals.PREF_IS_DEBUG)) {
                System.err.println(errorMessage);
            }
        }
    }
}
