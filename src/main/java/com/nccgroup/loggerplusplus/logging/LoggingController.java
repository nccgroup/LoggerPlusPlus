package com.nccgroup.loggerplusplus.logging;

import burp.IBurpExtenderCallbacks;
import com.coreyd97.BurpExtenderUtilities.IGsonProvider;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.util.Globals;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.Appender;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.LoggerContext;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.Configuration;
import org.apache.logging.log4j.core.layout.PatternLayout;

public class LoggingController {

    private final IGsonProvider gsonProvider;
    private IBurpExtenderCallbacks callbacks;
    private Level logLevel;

    public LoggingController(IGsonProvider gsonProvider) {
        this.gsonProvider = gsonProvider;
        this.callbacks = LoggerPlusPlus.callbacks;
        configureLogger();
    }

    private void configureLogger() {
        logLevel = gsonProvider.getGson().fromJson(callbacks.loadExtensionSetting(Globals.PREF_LOG_LEVEL), Level.class);

        if (logLevel == null) { //Handle change from debug boolean to log level.
            logLevel = Level.INFO;
            callbacks.saveExtensionSetting(Globals.PREF_LOG_LEVEL, gsonProvider.getGson().toJson(logLevel));
        }

        LoggerContext context = (LoggerContext) LogManager.getContext(false);
        Configuration config = context.getConfiguration();
        PatternLayout logLayout = PatternLayout.newBuilder()
                .withConfiguration(config)
                .withPattern("[%-5level] %d{yyyy-MM-dd HH:mm:ss} %msg%n")
                .build();

        Appender burpAppender = new AbstractAppender("Burp Appender", null, logLayout, false, null) {
            @Override
            public void append(LogEvent event) {
                String message = new String(this.getLayout().toByteArray(event));
                if (event.getLevel().isMoreSpecificThan(Level.INFO)) {
                    callbacks.printError(message);
                } else {
                    callbacks.printOutput(message);
                }
            }
        };
        burpAppender.start();

        context.getConfiguration().getRootLogger().addAppender(burpAppender, logLevel, null);
        context.updateLoggers();
    }

    public void setLogLevel(Level logLevel) {
        this.logLevel = logLevel;
        LoggerContext context = (LoggerContext) LogManager.getContext(false);
        context.getConfiguration().getRootLogger().setLevel(logLevel);
        context.updateLoggers();
    }
}
