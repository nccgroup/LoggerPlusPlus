package com.nccgroup.loggerplusplus;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionStateListener;
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
import org.apache.logging.log4j.Level;

import javax.swing.*;
import java.awt.*;
import java.net.URL;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

import static com.nccgroup.loggerplusplus.util.Globals.PREF_RESTRICT_TO_SCOPE;

/**
 * Created by corey on 07/09/17.
 */
public class LoggerPlusPlus implements IBurpExtender, IExtensionStateListener {
    public static LoggerPlusPlus instance;
    public static IBurpExtenderCallbacks callbacks;

    private final IGsonProvider gsonProvider;
    private LoggingController loggingController;
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


    public LoggerPlusPlus(){
        this.gsonProvider = new DefaultGsonProvider();
    }

    private JFrame getBurpFrame() throws Exception {
        // Get all frames
        Frame[] allFrames = JFrame.getFrames();
        // Filter the stream find the main burp window frame, and convert to a list
        List<Frame> filteredFrames = Arrays.stream(allFrames).filter(f ->
                f.getTitle().startsWith("Burp Suite") && f.isVisible()
        ).collect(Collectors.toList());
        //  If size is 1, we have the main burp frame. Otherwise fails
        if (filteredFrames.size() == 1) {
            return (JFrame) filteredFrames.get(0);
        } else {
            throw new Exception("Expected one burp pane, but found " + filteredFrames.size());
        }
    }

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {

        //Fix Darcula's issue with JSpinner UI.
        try {
            Class spinnerUI = Class.forName("com.bulenkov.darcula.ui.DarculaSpinnerUI");
            UIManager.put("com.bulenkov.darcula.ui.DarculaSpinnerUI", spinnerUI);
            Class sliderUI = Class.forName("com.bulenkov.darcula.ui.DarculaSliderUI");
            UIManager.put("com.bulenkov.darcula.ui.DarculaSliderUI", sliderUI);
        } catch (ClassNotFoundException e) {
            //Darcula is not installed.
        }

        //Burp Specific
        LoggerPlusPlus.instance = this;
        LoggerPlusPlus.callbacks = callbacks;
        callbacks.setExtensionName("Logger++");
        LoggerPlusPlus.callbacks.registerExtensionStateListener(LoggerPlusPlus.this);

        loggingController = new LoggingController(gsonProvider);
        preferencesController = new PreferencesController(this);
        preferencesController.getPreferences().addSettingListener((source, settingName, newValue) -> {
            if (settingName.equals(Globals.PREF_LOG_LEVEL)) {
                loggingController.setLogLevel((Level) newValue);
            }
        });
        reflectionController = new ReflectionController(preferencesController.getPreferences());
        exportController = new ExportController(this, preferencesController.getPreferences());
        libraryController = new FilterLibraryController(this, preferencesController);
        logViewController = new LogViewController(this, libraryController);
        logProcessor = new LogProcessor(this, logViewController.getLogTableController(), exportController);
        grepperController = new GrepperController(this, logViewController.getLogTableController(), preferencesController);
        contextMenuFactory = new LoggerContextMenuFactory(this);

        mainViewController = new MainViewController(this);

        LoggerPlusPlus.callbacks.registerContextMenuFactory(contextMenuFactory);


        SwingUtilities.invokeLater(() -> {

            LoggerPlusPlus.callbacks.addSuiteTab(mainViewController);

            //Add menu item to Burp's frame menu.
            JFrame rootFrame = null;
            try {
                rootFrame = getBurpFrame();
            } catch (Exception e) {
                callbacks.printError("Could not find root frame. Window JMenu will not be added");
                throw new RuntimeException(e);
            }
            try{
                JMenuBar menuBar = rootFrame.getJMenuBar();
                loggerMenu = new LoggerMenu(LoggerPlusPlus.this);
                menuBar.add(loggerMenu, menuBar.getMenuCount() - 1);
            }catch (NullPointerException nPException){
                loggerMenu = null;
            }
        });

    }

    @Override
    public void extensionUnloaded() {
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

        //Null out static variables so not leftover.
        LoggerPlusPlus.instance = null;
        LoggerPlusPlus.callbacks = null;
    }

    public static boolean isUrlInScope(URL url){
        return (!(Boolean) instance.getPreferencesController().getPreferences().getSetting(PREF_RESTRICT_TO_SCOPE)
                || callbacks.isInScope(url));
    }


    public LogViewController getLogViewController() {
        return logViewController;
    }

    public IGsonProvider getGsonProvider() {
        return gsonProvider;
    }

    public GrepperController getGrepperController() {
        return grepperController;
    }

    public MainViewController getMainViewController() {
        return mainViewController;
    }

    public FilterLibraryController getLibraryController() {
        return libraryController;
    }

    public LoggingController getLoggingController() {
        return loggingController;
    }

    public PreferencesController getPreferencesController() {
        return preferencesController;
    }

    public LogProcessor getLogProcessor() {
        return logProcessor;
    }

    public ReflectionController getReflectionController() {
        return reflectionController;
    }

    public LoggerMenu getLoggerMenu() {
        return loggerMenu;
    }

    public List<LogEntry> getLogEntries(){
        return logViewController.getLogTableController().getLogTableModel().getData();
    }

    public ExportController getExportController() {
        return exportController;
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
