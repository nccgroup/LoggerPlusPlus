package com.nccgroup.loggerplusplus.logging;

import burp.api.montoya.MontoyaApi;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import java.io.PrintWriter;
import java.io.StringWriter;

/**
 * The extension's log: messages go to Burp's output and error tabs for the extension.
 *
 * <p>This replaces Log4j, which the extension used for some thirty messages and which added
 * nearly two megabytes to its jar. Before Burp has handed over its API, and when the extension
 * runs from a class path instead of a jar, messages go to the console.
 */
public final class Log {
    private static volatile LogLevel level = LogLevel.INFO;
    private static volatile boolean alsoToConsole;

    private Log() {}

    public static void setLevel(LogLevel newLevel) {
        level = newLevel == null ? LogLevel.INFO : newLevel;
    }

    public static LogLevel getLevel() {
        return level;
    }

    /** Whether to copy every message to the console, as when run from a development class path. */
    public static void setAlsoToConsole(boolean console) {
        alsoToConsole = console;
    }

    /** Detail for finding a fault; written only at the DEBUG level. */
    public static void debug(String message) {
        if (level == LogLevel.DEBUG) {
            output(message);
        }
    }

    public static void info(String message) {
        output(message);
    }

    public static void error(String message) {
        error(message, null);
    }

    /** An error that has nothing to say beyond the exception itself. */
    public static void error(Throwable cause) {
        error(String.valueOf(cause.getMessage()), cause);
    }

    /** An error, followed by the stack trace of what caused it. */
    public static void error(String message, Throwable cause) {
        String text =
                cause == null ? message : message + System.lineSeparator() + stackTrace(cause);
        MontoyaApi burp = LoggerPlusPlus.montoya;
        if (burp != null) {
            burp.logging().logToError(text);
        }
        if (burp == null || alsoToConsole) {
            System.err.println(text);
        }
    }

    private static void output(String message) {
        MontoyaApi burp = LoggerPlusPlus.montoya;
        if (burp != null) {
            burp.logging().logToOutput(message);
        }
        if (burp == null || alsoToConsole) {
            System.out.println(message);
        }
    }

    private static String stackTrace(Throwable cause) {
        StringWriter trace = new StringWriter();
        cause.printStackTrace(new PrintWriter(trace));
        return trace.toString().stripTrailing();
    }
}
