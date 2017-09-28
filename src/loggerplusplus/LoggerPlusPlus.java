package loggerplusplus;

import burp.*;
import loggerplusplus.filter.Filter;
import loggerplusplus.filter.FilterCompiler;
import loggerplusplus.filter.FilterListener;
import loggerplusplus.userinterface.*;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;

/**
 * Created by corey on 07/09/17.
 */
public class LoggerPlusPlus implements ITab, IBurpExtender {
    public static IBurpExtenderCallbacks callbacks;
    public static LoggerPlusPlus instance;
    private static IContextMenuFactory contextMenuFactory;
    private ArrayList<FilterListener> filterListeners;
    private LoggerPreferences loggerPreferences;
    private LogManager logManager;

    //UX
    private PopOutPanel uiPopOutPanel;
    private JTabbedPane tabbedWrapper;
    private LogViewPanel logWrapperPanel;
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
        LoggerPlusPlus.callbacks = callbacks;
        LoggerPlusPlus.instance = this;
        LoggerPlusPlus.contextMenuFactory = new LoggerContextMenuFactory();

        callbacks.setExtensionName("Logger++");

        filterListeners = new ArrayList<>();
        loggerPreferences = new LoggerPreferences(LoggerPlusPlus.this);
        logManager = new LogManager(loggerPreferences);

        if(!callbacks.isExtensionBapp() && loggerPreferences.checkUpdatesOnStartup()){
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
                try {
                    Class.forName("org.apache.commons.lang3.StringEscapeUtils");
                    loggerPreferences.setCanSaveCSV(true);
                } catch(ClassNotFoundException e) {
                    LoggerPlusPlus.getCallbacks().printError("Warning: Error in loading Appache Commons Lang library.\r\nThe results cannot be saved in CSV format.\r\n"
                            + "Please reload this extension after adding this library to the Java Environment section of burp suite.\r\n"
                            + "This library is downloadable via http://commons.apache.org/proper/commons-lang/download_lang.cgi");
                }

                //UI
                logWrapperPanel = new LogViewPanel(logManager);
                requestViewer = LoggerPlusPlus.getCallbacks().createMessageEditor(logWrapperPanel.getLogTable().getModel(), false);
                responseViewer = LoggerPlusPlus.getCallbacks().createMessageEditor(logWrapperPanel.getLogTable().getModel(), false);
                reqRespPanel = new VariableViewPanel(requestViewer.getComponent(), "Request", responseViewer.getComponent(), "Response", loggerPreferences.getReqRespView()){
                    @Override
                    public void setView(View view) {
                        loggerPreferences.setReqRespView(view);
                        super.setView(view);
                    }
                };
                logSplitPanel = new VariableViewPanel(logWrapperPanel, "Log Table", reqRespPanel, "Request/Response", loggerPreferences.getView()){
                    @Override
                    public void setView(View view) {
                        loggerPreferences.setView(view);
                        super.setView(view);
                    }
                };

                grepPanel = new GrepPanel();
                optionsJPanel = new LoggerOptionsPanel();
                tabbedWrapper = new JTabbedPane();
                uiPopOutPanel = new PopOutPanel(tabbedWrapper, "Logger++"){
                    @Override
                    public void popOut() {
                        super.popOut();
                        LoggerPlusPlus.this.getMenu().getPopoutItem().setText("Pop In");
                    }

                    @Override
                    public void popIn() {
                        super.popIn();
                        LoggerPlusPlus.this.getMenu().getPopoutItem().setText("Pop Out");
                    }

                    @Override
                    public void removeNotify(){
                        if(loggerMenu != null && loggerMenu.getParent() != null){
                            loggerMenu.getParent().remove(loggerMenu);
                        }
                        super.removeNotify();
                    }
                };
                tabbedWrapper.addTab("View Logs", null, logSplitPanel, null);
                tabbedWrapper.addTab("Filter Library", null, new FilterLibraryPanel(), null);
                tabbedWrapper.addTab("Grep Values", null, grepPanel, null);
                tabbedWrapper.addTab("Options", null, optionsJPanel, null);
                tabbedWrapper.addTab("About", null, new AboutPanel(), null);
                tabbedWrapper.addTab("Help", null, new HelpPanel(), null);


                LoggerPlusPlus.getCallbacks().addSuiteTab(LoggerPlusPlus.this);

                //Add menu item to Burp's frame menu.
                JFrame rootFrame = (JFrame) SwingUtilities.getWindowAncestor(uiPopOutPanel);
                try{
                    JMenuBar menuBar = rootFrame.getJMenuBar();
                    loggerMenu = new LoggerMenu();
                    menuBar.add(loggerMenu, menuBar.getMenuCount() - 1);
                }catch (NullPointerException nPException){
                    loggerMenu = null;
                }

                LoggerPlusPlus.getCallbacks().registerHttpListener(logManager);
                LoggerPlusPlus.getCallbacks().registerProxyListener(logManager);
                LoggerPlusPlus.getCallbacks().registerContextMenuFactory(contextMenuFactory);
            }
        });
    }

    public static IBurpExtenderCallbacks getCallbacks() {
        return callbacks;
    }

    public static LoggerPlusPlus getInstance() {
        return instance;
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


    public void setFilter(String filterString){
        if (filterString == null || filterString.length() == 0) {
            setFilter((Filter) null);
        } else {
            try {
                Filter filter = FilterCompiler.parseString(filterString);
                setFilter(filter);
            } catch (Filter.FilterException fException) {
                logWrapperPanel.getLogTable().setFilter(null);
                formatFilter(filterString, Color.RED);
            }
        }
    }

    public void formatFilter(String string, Color color){
        if(string != logWrapperPanel.getFilterPanel().getFilterField().getSelectedItem()) {
            logWrapperPanel.getFilterPanel().getFilterField().setSelectedItem(string);
        }
        logWrapperPanel.getFilterPanel().getFilterField().setColor(color);
    }

    public void setFilter(Filter filter){
        HistoryField filterComboField = logWrapperPanel.getFilterPanel().getFilterField();
        Color color;
        String filterString;
        if (filter == null) {
            logWrapperPanel.getLogTable().setFilter(null);
            filterString = "";
            color = Color.WHITE;
        } else {
            logWrapperPanel.getLogTable().setFilter(filter);
            filterString = filter.toString();
            ((HistoryField.HistoryComboModel) filterComboField.getModel()).addToHistory(filterString);
            color = Color.GREEN;
        }
        formatFilter(filterString, color);
    }

    public void reset(){
        this.logManager.reset();
        this.logWrapperPanel.getLogTable().getModel().fireTableDataChanged();
    }

    public LoggerPreferences getLoggerPreferences() {
        return loggerPreferences;
    }

    public LogTable getLogTable() {
        return logWrapperPanel.getLogTable();
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

    public JScrollPane getLogScrollPanel() {
        return logWrapperPanel.getScrollPane();
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

    public PopOutPanel getPopoutPanel() {
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
}
