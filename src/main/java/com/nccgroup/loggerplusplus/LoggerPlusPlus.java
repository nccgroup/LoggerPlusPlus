package com.nccgroup.loggerplusplus;

import burp.IBurpExtender;
import burp.IBurpExtenderCallbacks;
import burp.IExtensionStateListener;
import burp.ITab;
import com.coreyd97.BurpExtenderUtilities.*;
import com.nccgroup.loggerplusplus.filter.colorfilter.ColorFilterListener;
import com.nccgroup.loggerplusplus.filter.logfilter.LogFilterController;
import com.nccgroup.loggerplusplus.filterlibrary.FilterLibraryController;
import com.nccgroup.loggerplusplus.grepper.GrepperController;
import com.nccgroup.loggerplusplus.logentry.LogManager;
import com.nccgroup.loggerplusplus.logentry.logger.ElasticSearchLogger;
import com.nccgroup.loggerplusplus.logview.LogViewPanel;
import com.nccgroup.loggerplusplus.logview.RequestViewerController;
import com.nccgroup.loggerplusplus.userinterface.*;
import com.nccgroup.loggerplusplus.logview.logtable.LogTable;
import com.nccgroup.loggerplusplus.util.Globals;
import com.nccgroup.loggerplusplus.util.MoreHelp;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;

/**
 * Created by corey on 07/09/17.
 */
public class LoggerPlusPlus implements ITab, IBurpExtender, IExtensionStateListener, ILogProvider {
    public static LoggerPlusPlus instance;
    public static IBurpExtenderCallbacks callbacks;
    public static IGsonProvider gsonProvider;
    public static Preferences preferences;

    private LogManager logManager;
    private LogFilterController logFilterController;
    private FilterLibraryController libraryController;
    private ElasticSearchLogger elasticSearchLogger;

    //UX
    private PopOutPanel uiPopOutPanel;
    private PopOutPanel uiReqRespPopOut;
    private JTabbedPane tabbedWrapper;
    private LogViewPanel logViewPanel;
    private VariableViewPanel logSplitPanel;
    private VariableViewPanel reqRespPanel;
    private LoggerOptionsPanel optionsJPanel;
    private LoggerMenu loggerMenu;

    private RequestViewerController requestViewerController;
    private GrepperController grepperController;

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
        LoggerPlusPlus.gsonProvider = new DefaultGsonProvider();
        LoggerPlusPlus.preferences = new LoggerPreferenceFactory(LoggerPlusPlus.gsonProvider, this, callbacks).buildPreferences();

        logFilterController = new LogFilterController(preferences);
        grepperController = new GrepperController(preferences);
        libraryController = new FilterLibraryController(preferences);
        logManager = new LogManager();

        Double lastVersion = preferences.getSetting(Globals.PREF_LAST_USED_VERSION);
        preferences.resetSettings(new HashSet<>(Arrays.asList(Globals.VERSION_CHANGE_SETTINGS_TO_RESET)));
        if(lastVersion > Globals.VERSION){
            //If we had a newer version previously.
            //reset all settings
            preferences.resetSettings(preferences.getRegisteredSettings().keySet());
        }else if(lastVersion < Globals.VERSION){
            //Reset preferences which may cause issues.
            preferences.resetSettings(new HashSet<>(Arrays.asList(Globals.VERSION_CHANGE_SETTINGS_TO_RESET)));
        }

        callbacks.setExtensionName("Logger++");
        elasticSearchLogger = new ElasticSearchLogger(logManager);

        if(!callbacks.isExtensionBapp() && (boolean) preferences.getSetting(Globals.PREF_UPDATE_ON_STARTUP)){
            MoreHelp.checkForUpdate(false);
        }

        buildUI();
    }

    private void buildUI(){
        SwingUtilities.invokeLater(new Runnable()
        {
            @Override
            public void run()
            {
                //UI
                JPanel logOuterPanel = new JPanel(new GridBagLayout());
                logViewPanel = new LogViewPanel(logManager);
                logFilterController.addFilterListener(logViewPanel.getLogTable());
                GridBagConstraints gbc = new GridBagConstraints();
                gbc.weighty = 0;
                gbc.weightx = 1;
                gbc.gridy = 0;
                gbc.fill = GridBagConstraints.BOTH;
                logOuterPanel.add(new MainControlsPanel(logFilterController), gbc);

                requestViewerController = new RequestViewerController(callbacks, false, false);
                reqRespPanel = new VariableViewPanel(preferences, Globals.PREF_MESSAGE_VIEW_LAYOUT,
                        requestViewerController.getRequestEditor().getComponent(), "Request",
                        requestViewerController.getResponseEditor().getComponent(), "Response",
                        VariableViewPanel.View.HORIZONTAL);

                uiReqRespPopOut = new PopOutPanel(reqRespPanel, "Request/Response"){
                    @Override
                    public void popOut() {
                        LoggerPlusPlus.this.logSplitPanel.setView(VariableViewPanel.View.VERTICAL);
                        super.popOut();
                    }

                    @Override
                    public void popIn() {
                        super.popIn();
                    }
                };

                logSplitPanel = new VariableViewPanel(preferences, Globals.PREF_LAYOUT,
                        logViewPanel, "Log Table",
                        uiReqRespPopOut, "Request/Response", VariableViewPanel.View.VERTICAL);

                gbc.gridy++;
                gbc.weighty = 1;
                logOuterPanel.add(logSplitPanel, gbc);

                optionsJPanel = new LoggerOptionsPanel();
                tabbedWrapper = new JTabbedPane();
                uiPopOutPanel = new PopOutPanel(tabbedWrapper, "Logger++");
                tabbedWrapper.addTab("View Logs", null, logOuterPanel, null);
                tabbedWrapper.addTab("Filter Library", null, libraryController.getUIComponent(), null);
                tabbedWrapper.addTab("Grep Values", null, grepperController.getUIComponent(), null);
                tabbedWrapper.addTab("Options", null, optionsJPanel, null);
                tabbedWrapper.addTab("About", null, new AboutPanel(), null);
                tabbedWrapper.addTab("Help", null, new HelpPanel(), null);


                LoggerPlusPlus.callbacks.addSuiteTab(LoggerPlusPlus.this);

                //Add menu item to Burp's frame menu.
                JFrame rootFrame = (JFrame) SwingUtilities.getWindowAncestor(uiPopOutPanel);
                try{
                    JMenuBar menuBar = rootFrame.getJMenuBar();
                    loggerMenu = new LoggerMenu();
                    loggerMenu.add(uiPopOutPanel.getPopoutMenuItem(), 1);
                    loggerMenu.add(uiReqRespPopOut.getPopoutMenuItem(), 2);
                    menuBar.add(loggerMenu, menuBar.getMenuCount() - 1);
                }catch (NullPointerException nPException){
                    loggerMenu = null;
                }

                LoggerPlusPlus.callbacks.registerHttpListener(logManager);
                LoggerPlusPlus.callbacks.registerProxyListener(logManager);
                LoggerPlusPlus.callbacks.registerContextMenuFactory(new LoggerContextMenuFactory());
                LoggerPlusPlus.callbacks.registerExtensionStateListener(LoggerPlusPlus.this);

                if(LoggerPlusPlus.preferences.getSetting(Globals.PREF_AUTO_IMPORT_PROXY_HISTORY)){
                    Thread importThread = new Thread(() -> {
                        logManager.importProxyHistory(false);
                    });
                    importThread.start();
                }
            }
        });
    }

    @Override
    public void extensionUnloaded() {
        if(loggerMenu != null && loggerMenu.getParent() != null){
            loggerMenu.getParent().remove(loggerMenu);
        }
        if(uiPopOutPanel.isPoppedOut()) uiPopOutPanel.getPopoutFrame().dispose();
        if(uiReqRespPopOut.isPoppedOut()) uiReqRespPopOut.getPopoutFrame().dispose();

        //Stop LogManager executors and pending tasks.
        logManager.shutdown();
    }

    @Override
    public String getTabCaption()
    {
        return "Logger++";
    }

    @Override
    public Component getUiComponent()
    {
        return uiPopOutPanel;
    }

    @Override
    public void logOutput(String message) {
        callbacks.printOutput(message);
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

    public void reset(){
        this.logManager.reset();
        this.logViewPanel.getLogTable().getModel().fireTableDataChanged();
    }

    public LogFilterController getLogFilterController() {
        return logFilterController;
    }

    public Preferences getPreferences() {
        return preferences;
    }

    public LogTable getLogTable() {
        return logViewPanel.getLogTable();
    }

    public LoggerOptionsPanel getLoggerOptionsPanel() {
        return optionsJPanel;
    }

    public VariableViewPanel getLogSplitPanel() {
        return logSplitPanel;
    }

    public VariableViewPanel getReqRespPanel() {
        return reqRespPanel;
    }

    public LogViewPanel getLogViewPanel() {
        return logViewPanel;
    }

    public JScrollPane getLogScrollPanel() {
        return logViewPanel.getScrollPane();
    }

    public FilterLibraryController getLibraryController() {
        return libraryController;
    }

    public RequestViewerController getRequestViewerController(){
        return requestViewerController;
    }

    public JTabbedPane getTabbedPane() {
        return this.tabbedWrapper;
    }

    public LogManager getLogManager() {
        return logManager;
    }

    public void setEsEnabled(boolean esEnabled) throws Exception {
        this.elasticSearchLogger.setEnabled(esEnabled);
    }
}
