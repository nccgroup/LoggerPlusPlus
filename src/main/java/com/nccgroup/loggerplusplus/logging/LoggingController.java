package com.nccgroup.loggerplusplus.logging;

import burp.api.montoya.MontoyaApi;
import com.coreyd97.BurpExtenderUtilities.IGsonProvider;
import com.nccgroup.loggerplusplus.util.Globals;
import lombok.extern.log4j.Log4j2;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.ConsoleAppender;

@Log4j2
public class LoggingController {

    private final IGsonProvider gsonProvider;
    private Level logLevel;

    public LoggingController(IGsonProvider gsonProvider, MontoyaApi montoyaApi) {
        this.gsonProvider = gsonProvider;
        logLevel = gsonProvider.getGson().fromJson(montoyaApi.persistence().preferences().getString(Globals.PREF_LOG_LEVEL), Level.class);
        if(montoyaApi.extension().filename() == null){ //Loaded from classpath. Log to console!
            LoggerContext context = (LoggerContext) LogManager.getContext(false);
            ConsoleAppender.Builder appenderBuilder = new ConsoleAppender.Builder();
            appenderBuilder.setName("ConsoleAppender");
            ConsoleAppender consoleAppender = appenderBuilder.build();
            consoleAppender.start();
            context.getRootLogger().addAppender(consoleAppender);
        }
        setLogLevel(logLevel);
    }

    public void setLogLevel(Level logLevel) {
        this.logLevel = logLevel;
        LoggerContext context = (LoggerContext) LogManager.getContext(false);
        context.getConfiguration().getRootLogger().setLevel(logLevel);
        context.updateLoggers();
    }
}
