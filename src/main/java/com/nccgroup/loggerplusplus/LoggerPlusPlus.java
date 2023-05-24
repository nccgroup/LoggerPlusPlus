package com.nccgroup.loggerplusplus;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Registration;
import com.coreyd97.BurpExtenderUtilities.DefaultGsonProvider;
import com.coreyd97.BurpExtenderUtilities.IGsonProvider;
import com.nccgroup.loggerplusplus.exports.ExportController;
import com.nccgroup.loggerplusplus.filterlibrary.FilterLibraryController;
import com.nccgroup.loggerplusplus.grepper.GrepperController;
import com.nccgroup.loggerplusplus.logentry.LogEntry;
import com.nccgroup.loggerplusplus.logging.LoggingController;
import com.nccgroup.loggerplusplus.logview.LogViewController;
import com.nccgroup.loggerplusplus.logview.processor.LogProcessor;
import com.nccgroup.loggerplusplus.preferences.PreferencesController;
import com.nccgroup.loggerplusplus.reflection.ReflectionController;
import com.nccgroup.loggerplusplus.util.Globals;
import com.nccgroup.loggerplusplus.util.userinterface.LoggerMenu;
import lombok.Getter;
import lombok.extern.log4j.Log4j2;
import org.apache.logging.log4j.Level;

import javax.swing.*;
import java.awt.*;
import java.util.Arrays;
import java.util.List;

import static com.nccgroup.loggerplusplus.util.Globals.PREF_RESTRICT_TO_SCOPE;

/**
 * Created by corey on 07/09/17.
 */
@Log4j2
@Getter
public class LoggerPlusPlus implements BurpExtension {

    private static String NAME = "Logger++";

    public static LoggingController loggingController;
    public static LoggerPlusPlus instance;
    public static MontoyaApi montoya;
    public static IGsonProvider gsonProvider = new DefaultGsonProvider();

    private Registration menuBarRegistration;
    private LogProcessor logProcessor;
    private ExportController exportController;
    private PreferencesController preferencesController;
    private LogViewController logViewController;
    private FilterLibraryController libraryController;
    private LoggerContextMenuFactory contextMenuFactory;
    private GrepperController grepperController;
    private MainViewController mainViewController;
    private ReflectionController reflectionController;

    //UX
    private LoggerMenu loggerMenu;

    public LoggerPlusPlus() {
        LoggerPlusPlus.instance = this;
    }

    @Override
    public void initialize(MontoyaApi montoya) {
        //Woohoo! Montoya!
        LoggerPlusPlus.montoya = montoya;
        montoya.extension().setName(NAME);
        montoya.extension().registerUnloadingHandler(this::unloadExtension);

        //TODO Set Logging Level from prefs
        loggingController = new LoggingController(gsonProvider, montoya);
        log.info("Logger++ " + Globals.VERSION + " by @CoreyD97.");
        log.info("Please submit any bug reports or feature requests via GitHub.");
        log.info("Feel free to reach out on Twitter (@CoreyD97) with any questions.");

        preferencesController = new PreferencesController(montoya);
        preferencesController.getPreferences().addSettingListener((source, settingName, newValue) -> {
            if (settingName.equals(Globals.PREF_LOG_LEVEL)) {
                loggingController.setLogLevel((Level) newValue);
            }
        });
        reflectionController = new ReflectionController(preferencesController.getPreferences());
        exportController = new ExportController(preferencesController.getPreferences());
        libraryController = new FilterLibraryController(preferencesController);
        logViewController = new LogViewController(libraryController);
        logProcessor = new LogProcessor(logViewController.getLogTableController(), exportController);
        grepperController = new GrepperController(logViewController.getLogTableController(), preferencesController);
        contextMenuFactory = new LoggerContextMenuFactory();
        mainViewController = new MainViewController();


        montoya.userInterface().registerContextMenuItemsProvider(contextMenuFactory);
        montoya.userInterface().registerSuiteTab(NAME, mainViewController.getUiComponent());

        montoya.http().registerHttpHandler(logProcessor.getHttpHandler());
        montoya.proxy().registerResponseHandler(logProcessor.getProxyResponseHandler());


        loggerMenu = new LoggerMenu(LoggerPlusPlus.this);
        menuBarRegistration = montoya.userInterface().menuBar().registerMenu(loggerMenu);

    }

    public void unloadExtension() {
        if(loggerMenu != null && loggerMenu.getParent() != null){
            loggerMenu.getParent().remove(loggerMenu);
        }
        if(mainViewController.getPopOutWrapper().isPoppedOut()) {
            mainViewController.getPopOutWrapper().getPopoutFrame().dispose();
        }
        if(logViewController.getRequestViewerController().getRequestViewerPanel().isPoppedOut()) {
            logViewController.getRequestViewerController().getRequestViewerPanel().getPopoutFrame().dispose();
        }

        //Stop log processor executors and pending tasks.
        logProcessor.shutdown();

        menuBarRegistration.deregister();

        //Null out static variables so not leftover.
        LoggerPlusPlus.instance = null;
    }

    public static boolean isUrlInScope(String url){
        return (!(Boolean) instance.getPreferencesController().getPreferences().getSetting(PREF_RESTRICT_TO_SCOPE)
                || montoya.scope().isInScope(url));
    }

    public List<LogEntry> getLogEntries(){
        return logViewController.getLogTableController().getLogTableModel().getData();
    }

    public Frame getLoggerFrame() {
        if (mainViewController == null) {
            return Arrays.stream(JFrame.getFrames()).filter(frame -> {
                return frame.getTitle().startsWith("Burp Suite") && frame.isVisible();
            }).findFirst().orElse(null);
        }
        return JOptionPane.getFrameForComponent(mainViewController.getTabbedPanel());
    }
}
