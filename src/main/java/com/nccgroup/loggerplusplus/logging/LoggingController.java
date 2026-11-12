package com.nccgroup.loggerplusplus.logging;

import burp.api.montoya.MontoyaApi;
import com.coreyd97.BurpExtenderUtilities.IGsonProvider;
import com.nccgroup.loggerplusplus.util.Globals;

/** Sets the log up when the extension loads, from the level saved in Burp's preferences. */
public class LoggingController {

    public LoggingController(IGsonProvider gsonProvider, MontoyaApi montoyaApi) {
        String savedLevel =
                montoyaApi.persistence().preferences().getString(Globals.PREF_LOG_LEVEL);
        LogLevel level =
                savedLevel == null
                        ? LogLevel.INFO
                        : new LogLevel.Serializer()
                                .deserialize(
                                        com.google.gson.JsonParser.parseString(savedLevel),
                                        LogLevel.class,
                                        null);
        // No jar file name: the extension was loaded from a class path, by a developer.
        Log.setAlsoToConsole(montoyaApi.extension().filename() == null);
        setLogLevel(level);
    }

    public void setLogLevel(LogLevel logLevel) {
        Log.setLevel(logLevel);
    }
}
