package loggerplusplus;

import burp.*;
import com.coreyd97.BurpExtenderUtilities.*;
import loggerplusplus.filter.FilterListener;
import loggerplusplus.filter.LogFilter;
import loggerplusplus.filter.parser.ParseException;
import loggerplusplus.userinterface.*;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.concurrent.Future;

/**
 * Created by corey on 07/09/17.
 */
public class LoggerPlusPlus implements ITab, IBurpExtender, IExtensionStateListener, ILogProvider {
    public static LoggerPlusPlus instance;
    public static IBurpExtenderCallbacks callbacks;
    public static IGsonProvider gsonProvider;
    public static Preferences preferences;

    private static IContextMenuFactory contextMenuFactory;
    private ArrayList<FilterListener> filterListeners;
    private LogManager logManager;
    private ElasticSearchLogger elasticSearchLogger;

    //UX
    private PopOutPanel uiPopOutPanel;
    private PopOutPanel uiReqRespPopOut;
    private JTabbedPane tabbedWrapper;
    private LogViewPanel logViewPanel;
    private VariableViewPanel logSplitPanel;
    private VariableViewPanel reqRespPanel;
    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private GrepPanel grepPanel;
    private LoggerOptionsPanel optionsJPanel;
    private LoggerMenu loggerMenu;

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
        //Burp Specific
        LoggerPlusPlus.instance = this;
        LoggerPlusPlus.callbacks = callbacks;
        LoggerPlusPlus.contextMenuFactory = new LoggerContextMenuFactory();
        LoggerPlusPlus.gsonProvider = new DefaultGsonProvider();
        LoggerPlusPlus.preferences = new LoggerPreferenceFactory(LoggerPlusPlus.gsonProvider, this, callbacks).buildPreferences();
        logManager = new LogManager();

        Double lastVersion = (Double) preferences.getSetting(Globals.PREF_LAST_USED_VERSION);
        preferences.resetSettings(new HashSet<>(Arrays.asList(Globals.VERSION_CHANGE_SETTINGS_TO_RESET)));
        if(lastVersion > Globals.VERSION){
            //If we had a newer version previously.
            //reset all settings
            preferences.resetSettings(preferences.getPreferenceKeys());
        }else if(lastVersion < Globals.VERSION){
            //Reset preferences which may cause issues.
            preferences.resetSettings(new HashSet<>(Arrays.asList(Globals.VERSION_CHANGE_SETTINGS_TO_RESET)));
        }

        callbacks.setExtensionName("Logger++");
        filterListeners = new ArrayList<>();
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
                GridBagConstraints gbc = new GridBagConstraints();
                gbc.weighty = 0;
                gbc.weightx = 1;
                gbc.gridy = 0;
                gbc.fill = GridBagConstraints.BOTH;
                logOuterPanel.add(logViewPanel.getFilterPanel(), gbc);

                requestViewer = LoggerPlusPlus.callbacks.createMessageEditor(logViewPanel.getLogTable().getModel(), false);
                responseViewer = LoggerPlusPlus.callbacks.createMessageEditor(logViewPanel.getLogTable().getModel(), false);
                reqRespPanel = new VariableViewPanel(preferences, Globals.PREF_MESSAGE_VIEW_LAYOUT,
                        requestViewer.getComponent(), "Request", responseViewer.getComponent(), "Response", VariableViewPanel.View.HORIZONTAL);
                uiReqRespPopOut = new PopOutPanel(reqRespPanel, "Request/Response"){
                    @Override
                    public void popOut() {
                        LoggerPlusPlus.this.logSplitPanel.setView(VariableViewPanel.View.VERTICAL);
                        super.popOut();
                        LoggerPlusPlus.this.getMenu().getPopoutReqRespMenuItem().setText("Pop In Request/Response Panel");
                    }

                    @Override
                    public void popIn() {
                        super.popIn();
                        LoggerPlusPlus.this.getMenu().getPopoutReqRespMenuItem().setText("Pop Out Request/Response Panel");
                    }
                };

                logSplitPanel = new VariableViewPanel(preferences, Globals.PREF_LAYOUT,
                        logViewPanel, "Log Table",
                        uiReqRespPopOut, "Request/Response", VariableViewPanel.View.VERTICAL);

                gbc.gridy++;
                gbc.weighty = 1;
                logOuterPanel.add(logSplitPanel, gbc);

                grepPanel = new GrepPanel();
                optionsJPanel = new LoggerOptionsPanel();
                tabbedWrapper = new JTabbedPane();
                uiPopOutPanel = new PopOutPanel(tabbedWrapper, "Logger++"){
                    @Override
                    public void popOut() {
                        super.popOut();
                        LoggerPlusPlus.this.getMenu().getPopoutMainMenuItem().setText("Pop In Main Panel");
                    }

                    @Override
                    public void popIn() {
                        super.popIn();
                        LoggerPlusPlus.this.getMenu().getPopoutMainMenuItem().setText("Pop Out Main Panel");
                    }
                };
                tabbedWrapper.addTab("View Logs", null, logOuterPanel, null);
                tabbedWrapper.addTab("Filter Library", null, new SavedFiltersPanel(), null);
                tabbedWrapper.addTab("Grep Values", null, grepPanel, null);
                tabbedWrapper.addTab("Options", null, optionsJPanel, null);
                tabbedWrapper.addTab("About", null, new AboutPanel(), null);
                tabbedWrapper.addTab("Help", null, new HelpPanel(), null);


                LoggerPlusPlus.callbacks.addSuiteTab(LoggerPlusPlus.this);

                //Add menu item to Burp's frame menu.
                JFrame rootFrame = (JFrame) SwingUtilities.getWindowAncestor(uiPopOutPanel);
                try{
                    JMenuBar menuBar = rootFrame.getJMenuBar();
                    loggerMenu = new LoggerMenu();
                    menuBar.add(loggerMenu, menuBar.getMenuCount() - 1);
                }catch (NullPointerException nPException){
                    loggerMenu = null;
                }

                LoggerPlusPlus.callbacks.registerHttpListener(logManager);
                LoggerPlusPlus.callbacks.registerProxyListener(logManager);
                LoggerPlusPlus.callbacks.registerContextMenuFactory(contextMenuFactory);
                LoggerPlusPlus.callbacks.registerExtensionStateListener(LoggerPlusPlus.this);

                if((Boolean) LoggerPlusPlus.preferences.getSetting(Globals.PREF_AUTO_IMPORT_PROXY_HISTORY)){
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

        //Stop importing...
        this.getLogManager().getExecutorService().shutdownNow();
        Future importFuture = this.getLogManager().getImportFuture();
        if(!importFuture.isDone()){
            importFuture.cancel(true);
        }

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

    public void setFilter(String filterString){
        if (filterString == null || filterString.length() == 0) {
            setFilter((LogFilter) null);
        } else {
            try {
                LogFilter filter = new LogFilter(filterString);
                setFilter(filter);
            } catch (ParseException e) {
                logViewPanel.getLogTable().setFilter(null);
                formatFilter(filterString, Color.RED);
            }
        }
    }

    public void formatFilter(String string, Color color){
        if(string != logViewPanel.getFilterPanel().getFilterField().getSelectedItem()) {
            logViewPanel.getFilterPanel().getFilterField().setSelectedItem(string);
        }
        logViewPanel.getFilterPanel().getFilterField().setColor(color);
    }

    public void setFilter(LogFilter filter){
        HistoryField filterComboField = logViewPanel.getFilterPanel().getFilterField();
        Color color;
        String filterString;
        if (filter == null) {
            logViewPanel.getLogTable().setFilter(null);
            filterString = "";
            color = Color.WHITE;
        } else {
            logViewPanel.getLogTable().setFilter(filter);
            filterString = filter.toString();
            ((HistoryField.HistoryComboModel) filterComboField.getModel()).addToHistory(filterString);
            color = Color.GREEN;
        }
        formatFilter(filterString, color);
    }

    public void reset(){
        this.logManager.reset();
        this.logViewPanel.getLogTable().getModel().fireTableDataChanged();
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

    public ArrayList<FilterListener> getFilterListeners() {
        return filterListeners;
    }

    public void addFilterListener(FilterListener listener) {
        filterListeners.add(listener);
    }

    public IMessageEditor getRequestViewer() {
        return requestViewer;
    }

    public IMessageEditor getResponseViewer() {
        return responseViewer;
    }

    public JTabbedPane getTabbedPane() {
        return this.tabbedWrapper;
    }

    public PopOutPanel getMainPopOutPanel() {
        return uiPopOutPanel;
    }

    public LoggerMenu getMenu() {
        return loggerMenu;
    }

    public LogManager getLogManager() {
        return logManager;
    }

    public static IContextMenuFactory getContextMenuFactory() {
        return contextMenuFactory;
    }

    public void setEsEnabled(boolean esEnabled) throws Exception {
        this.elasticSearchLogger.setEnabled(esEnabled);
    }

    public PopOutPanel getReqRespPopOutPanel() {
        return this.uiReqRespPopOut;
    }
}
