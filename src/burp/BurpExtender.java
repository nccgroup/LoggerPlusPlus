//
// Burp Suite Logger++
// 
// Released as open source by NCC Group Plc - https://www.nccgroup.trust/
// 
// Developed by Soroush Dalili (@irsdl)
//
// Project link: http://www.github.com/nccgroup/BurpSuiteLoggerPlusPlus
//
// Released under AGPL see LICENSE for more information
//

package burp;

import burp.dialog.ColorFilterDialog;
import burp.dialog.ColorFilterTableModel;
import burp.filter.ColorFilter;
import burp.filter.Filter;
import burp.filter.FilterCompiler;
import burp.filter.FilterListener;
import burp.VariableViewPanel.View;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.io.PrintWriter;
import java.net.URL;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;


public class BurpExtender implements IBurpExtender, ITab, IHttpListener, IProxyListener
{
	private static BurpExtender instance;
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	private PopOutPanel uiPopOutPanel;
	private ArrayList<LogEntry> logEntries;
	private HashMap<Integer, LogEntry.PendingRequestEntry> pendingRequests;
	private JTabbedPane tabbedWrapper;
	private boolean canSaveCSV = false;
	private LoggerPreferences loggerPreferences;
	private AboutPanel aboutJPanel;
	private LoggerOptionsPanel optionsJPanel;
	private ArrayList<FilterListener> filterListeners;
	private VariableViewPanel reqRespPanel;
	private VariableViewPanel mainPanel;
	private JMenu loggerMenu;
	private int totalRequests = 0;
	private short lateResponses = 0;
	private ArrayList<LogEntryListener> logEntryListeners;
	private JMenuItem popoutbutton;
	private LogViewPanel logViewPanel;
	private IMessageEditor requestViewer;
	private IMessageEditor responseViewer;
	//
	// implement IBurpExtender
	//

	@Override
	public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
	{
		//Burp Specific
		callbacks.setExtensionName("Logger++");
		this.callbacks = callbacks;
		this.helpers = callbacks.getHelpers();

		//Logger++ Setup
		instance = this;
		logEntries = new ArrayList<LogEntry>();
		logEntryListeners = new ArrayList<>();
		filterListeners = new ArrayList<FilterListener>();
		pendingRequests = new HashMap<Integer, LogEntry.PendingRequestEntry>();
		loggerPreferences = new LoggerPreferences();
		aboutJPanel = new AboutPanel();

		//Add ui elements to ui.
		SwingUtilities.invokeLater(new Runnable()
		{
			@Override
			public void run()
			{

				try {
					Class.forName("org.apache.commons.lang3.StringEscapeUtils");
					canSaveCSV = true;
				} catch(ClassNotFoundException e) {
					callbacks.printError("Warning: Error in loading Appache Commons Lang library.\r\nThe results cannot be saved in CSV format.\r\n"
							+ "Please reload this extension after adding this library to the Java Environment section of burp suite.\r\n"
							+ "This library is downloadable via http://commons.apache.org/proper/commons-lang/download_lang.cgi");
				}

				//UI
				logViewPanel = new LogViewPanel(logEntries);
				requestViewer = callbacks.createMessageEditor(logViewPanel.getLogTable().getModel(), false);
				responseViewer = callbacks.createMessageEditor(logViewPanel.getLogTable().getModel(), false);
				reqRespPanel = new VariableViewPanel(requestViewer.getComponent(), "Request", responseViewer.getComponent(), "Response", loggerPreferences.getReqRespView()){
					@Override
					public void setView(View view) {
						loggerPreferences.setReqRespView(view);
						super.setView(view);
					}
				};
				mainPanel = new VariableViewPanel(logViewPanel, "Log Table", reqRespPanel, "Request/Response", loggerPreferences.getView()){
					@Override
					public void setView(View view) {
						loggerPreferences.setView(view);
						super.setView(view);
					}
				};
				optionsJPanel = new LoggerOptionsPanel(canSaveCSV);
				tabbedWrapper = new JTabbedPane();
				tabbedWrapper.addTab("View Logs", null, mainPanel, null);
				tabbedWrapper.addTab("Filter Library", null, new FilterLibrary(), null);
				tabbedWrapper.addTab("Options", null, optionsJPanel, null);
				tabbedWrapper.addTab("About", null, aboutJPanel, null);
				tabbedWrapper.addTab("Help", null, new HelpPanel(), null);
				uiPopOutPanel = new PopOutPanel(tabbedWrapper, "Logger++"){
					@Override
					public void popOut() {
						super.popOut();
						popoutbutton.setText("Pop In");
					}

					@Override
					public void popIn() {
						super.popIn();
						popoutbutton.setText("Pop Out");
					}

					@Override
					public void removeNotify(){
						if(loggerMenu != null){
							loggerMenu.getParent().remove(loggerMenu);
						}
						super.removeNotify();
					}
				};

				// add the custom tab to Burp's UI
				callbacks.addSuiteTab(BurpExtender.this);
				// register ourselves as an HTTP listener
				callbacks.registerHttpListener(BurpExtender.this);
				// register ourselves as an HTTP proxy listener as well!
				callbacks.registerProxyListener(BurpExtender.this);


				//Add menu item to Burp's frame menu.
				JFrame rootFrame = (JFrame) SwingUtilities.getWindowAncestor(tabbedWrapper);
				try{
					JMenuBar menuBar = rootFrame.getJMenuBar();
					loggerMenu = new JMenu(getTabCaption());
					JMenuItem colorFilters = new JMenuItem(new AbstractAction("Color Filters") {
						@Override
						public void actionPerformed(ActionEvent actionEvent) {
							new ColorFilterDialog(filterListeners).setVisible(true);
						}
					});
					loggerMenu.add(colorFilters);

					popoutbutton = new JMenuItem(new AbstractAction("Pop Out") {
						@Override
						public void actionPerformed(ActionEvent actionEvent) {
							uiPopOutPanel.toggle();
						}
					});
					loggerMenu.add(popoutbutton);

					JMenu viewMenu = new JMenu("View");
					ButtonGroup bGroup = new ButtonGroup();
					JRadioButtonMenuItem viewMenuItem = new JRadioButtonMenuItem(new AbstractAction("Top/Bottom Split") {
						@Override
						public void actionPerformed(ActionEvent actionEvent) {
							mainPanel.setView(View.VERTICAL);
						}
					});
					viewMenuItem.setSelected(loggerPreferences.getView() == View.VERTICAL);
					viewMenu.add(viewMenuItem);
					bGroup.add(viewMenuItem);
					viewMenuItem = new JRadioButtonMenuItem(new AbstractAction("Left/Right Split") {
						@Override
						public void actionPerformed(ActionEvent actionEvent) {
							mainPanel.setView(View.VERTICAL);
						}
					});
					viewMenuItem.setSelected(loggerPreferences.getView() == View.HORIZONTAL);
					viewMenu.add(viewMenuItem);
					bGroup.add(viewMenuItem);
					viewMenuItem = new JRadioButtonMenuItem(new AbstractAction("Tabs") {
						@Override
						public void actionPerformed(ActionEvent actionEvent) {
							mainPanel.setView(View.TABS);
						}
					});
					viewMenuItem.setSelected(loggerPreferences.getView() == View.TABS);
					viewMenu.add(viewMenuItem);
					bGroup.add(viewMenuItem);
					loggerMenu.add(viewMenu);

					viewMenu = new JMenu("Request/Response View");
					bGroup = new ButtonGroup();
					viewMenuItem = new JRadioButtonMenuItem(new AbstractAction("Top/Bottom Split") {
						@Override
						public void actionPerformed(ActionEvent actionEvent) {
							reqRespPanel.setView(View.VERTICAL);
						}
					});
					viewMenu.add(viewMenuItem);
					bGroup.add(viewMenuItem);
					viewMenuItem.setSelected(loggerPreferences.getReqRespView() == View.VERTICAL);
					viewMenuItem = new JRadioButtonMenuItem(new AbstractAction("Left/Right Split") {
						@Override
						public void actionPerformed(ActionEvent actionEvent) {
							reqRespPanel.setView(View.HORIZONTAL);
						}
					});
					viewMenu.add(viewMenuItem);
					bGroup.add(viewMenuItem);
					viewMenuItem.setSelected(loggerPreferences.getReqRespView() == View.HORIZONTAL);
					viewMenuItem = new JRadioButtonMenuItem(new AbstractAction("Tabs") {
						@Override
						public void actionPerformed(ActionEvent actionEvent) {
							reqRespPanel.setView(View.TABS);
						}
					});
					viewMenu.add(viewMenuItem);
					bGroup.add(viewMenuItem);
					viewMenuItem.setSelected(loggerPreferences.getReqRespView() == View.TABS);

					loggerMenu.add(viewMenu);
					menuBar.add(loggerMenu, menuBar.getMenuCount() - 1);
				}catch (NullPointerException nPException){
					loggerMenu = null;
				}
			}
		});

		if(!callbacks.isExtensionBapp() && loggerPreferences.checkUpdatesOnStartup()){
			aboutJPanel.checkForUpdate(false);
		}

		//Create incomplete request cleanup thread so map doesn't get too big.
		ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();
		Runnable cleanupTask = new Runnable() {
			@Override
			public void run() {
				SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
				Set<Integer> keys = new HashSet<>(pendingRequests.keySet());
				synchronized (pendingRequests){
					for (Integer reference : keys) {
						try {
							Date date = dateFormat.parse(pendingRequests.get(reference).requestTime);
							if(new Date().getTime() - date.getTime() > BurpExtender.getInstance().getLoggerPreferences().getResponseTimeout()){
								pendingRequests.remove(reference);
							}
						} catch (ParseException e) {
							pendingRequests.remove(reference);
						}
					}
				}
			}
		};

		executor.scheduleAtFixedRate(cleanupTask, 30000, 30000, TimeUnit.MILLISECONDS);
	}

	public static BurpExtender getInstance() {
		return instance;
	}


	//
	// implement ITab
	//

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

	//
	// implement IHttpListener
	//

	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
		if(toolFlag != IBurpExtenderCallbacks.TOOL_PROXY) logIt(toolFlag, messageIsRequest, messageInfo, null);
	}

	//
	// implement IProxyListener
	// This is used next to IHttpListener to retrieve more data from the Proxy tab such as the listener port or  the client IP
	//

	@Override
	public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
		logIt(IBurpExtenderCallbacks.TOOL_PROXY, messageIsRequest, null, message);
	}

	private void logIt(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo,IInterceptedProxyMessage message){
		// Is it enabled?
		// We also have a separate module for the Proxy tool and we do it under processProxyMessage
		if(loggerPreferences.isEnabled()){
			// When it comes from the proxy listener "messageInfo" is null and "message" is available.
			if(messageInfo==null && message!=null){
				messageInfo = message.getMessageInfo();
			}

			IRequestInfo analyzedReq = helpers.analyzeRequest(messageInfo);
			URL uUrl = analyzedReq.getUrl();

			// Check for the scope if it is restricted to scope
			if (!loggerPreferences.isRestrictedToScope() || callbacks.isInScope(uUrl))
			{
				boolean isValidTool = (loggerPreferences.isEnabled4All() ||
							(loggerPreferences.isEnabled4Proxy() && toolFlag== IBurpExtenderCallbacks.TOOL_PROXY) ||
							(loggerPreferences.isEnabled4Intruder() && toolFlag== IBurpExtenderCallbacks.TOOL_INTRUDER) ||
							(loggerPreferences.isEnabled4Repeater() && toolFlag== IBurpExtenderCallbacks.TOOL_REPEATER) ||
							(loggerPreferences.isEnabled4Scanner() && toolFlag== IBurpExtenderCallbacks.TOOL_SCANNER) ||
							(loggerPreferences.isEnabled4Sequencer() && toolFlag== IBurpExtenderCallbacks.TOOL_SEQUENCER) ||
							(loggerPreferences.isEnabled4Spider() && toolFlag== IBurpExtenderCallbacks.TOOL_SPIDER) ||
							(loggerPreferences.isEnabled4Extender() && toolFlag== IBurpExtenderCallbacks.TOOL_EXTENDER) ||
							(loggerPreferences.isEnabled4TargetTab() && toolFlag== IBurpExtenderCallbacks.TOOL_TARGET));

				if(isValidTool){

					LogEntry logEntry = null;
					if (messageIsRequest){
						// Burp does not provide any way to trace a request to its response - only in proxy there is a unique reference
						if(toolFlag== IBurpExtenderCallbacks.TOOL_PROXY) {
							//We need to change messageInfo when we get a response so do not save to buffers
							logEntry = new LogEntry.PendingRequestEntry(toolFlag, messageIsRequest, messageInfo, uUrl, analyzedReq, message);

							for (ColorFilter colorFilter : loggerPreferences.getColorFilters().values()) {
								logEntry.testColorFilter(colorFilter, false);
							}
							synchronized (pendingRequests) {
								pendingRequests.put(message.getMessageReference(), (LogEntry.PendingRequestEntry) logEntry);
							}
						}
					}else{
						if(toolFlag== IBurpExtenderCallbacks.TOOL_PROXY){
							//Get from pending list
							LogEntry.PendingRequestEntry pendingRequest;
							synchronized (pendingRequests) {
								pendingRequest = pendingRequests.remove(message.getMessageReference());
							}
							if (pendingRequest != null) {
								//Fill in gaps of request with response
								pendingRequest.processResponse(messageInfo);

								for (ColorFilter colorFilter : loggerPreferences.getColorFilters().values()) {
									pendingRequest.testColorFilter(colorFilter, true);
								}
								//Calculate adjusted row in case it's moved. Update 10 either side to account for deleted rows
								if(logEntries.size() == loggerPreferences.getMaximumEntries()) {
									int newRow = pendingRequest.logRow - loggerPreferences.getMaximumEntries() - totalRequests;
									logViewPanel.getLogTable().getModel().fireTableRowsUpdated(newRow - 10, Math.min(loggerPreferences.getMaximumEntries(), newRow + 10));
								}else{
									logViewPanel.getLogTable().getModel().fireTableRowsUpdated(pendingRequest.logRow, pendingRequest.logRow);
								}

								for (LogEntryListener logEntryListener : logEntryListeners) {
									logEntryListener.onResponseReceived(pendingRequest);
								}

							} else {
								lateResponses++;
								if(totalRequests > 100 && ((float)lateResponses)/totalRequests > 0.1){
									MoreHelp.showWarningMessage(lateResponses + " responses have been delivered after the Logger++ timeout. Consider increasing this value.");
								}
							}
							return;
						}else {
							//We will not need to change messageInfo so save to temp file
							logEntry = new LogEntry(toolFlag, messageIsRequest, callbacks.saveBuffersToTempFiles(messageInfo), uUrl, analyzedReq, message);
							//Check entry against colorfilters.
							for (ColorFilter colorFilter : loggerPreferences.getColorFilters().values()) {
								logEntry.testColorFilter(colorFilter, false);
							}
						}
					}

					if(logEntry != null) {
						//After handling request / response logEntries generation.
						//Add to table / modify existing entry.
						synchronized (logEntries) {
							logViewPanel.getLogTable().getModel().addRow(logEntry);
							totalRequests++;
							if(logEntry instanceof LogEntry.PendingRequestEntry){
								((LogEntry.PendingRequestEntry) logEntry).logRow = totalRequests-1;
							}
						}
					}
				}
			}
		}
	}

	public void setFilter(String filterString){
		JTextField filterField = logViewPanel.getFilterPanel().getFilterField();
		if(filterString.length() == 0){
			setFilter((Filter) null);
		}else{
			try{
				Filter filter = FilterCompiler.parseString(filterString);
				logViewPanel.getLogTable().setFilter(filter);
				filterField.setText(filter.toString());
				filterField.setBackground(Color.green);
			}catch (Filter.FilterException fException){
				logViewPanel.getLogTable().setFilter(null);
				filterField.setBackground(Color.RED);
			}
		}
	}

	public void setFilter(Filter filter){
		if(filter == null){
			logViewPanel.getLogTable().setFilter(null);
			logViewPanel.getFilterPanel().getFilterField().setText("");
			logViewPanel.getFilterPanel().getFilterField().setBackground(Color.white);
		} else {
			logViewPanel.getLogTable().setFilter(filter);
			logViewPanel.getFilterPanel().getFilterField().setText(filter.toString());
			logViewPanel.getFilterPanel().getFilterField().setBackground(Color.green);
		}
	}

	public static void main(String [] args){
		System.out.println("You have built the Logger++. You shall play with the jar file now!");
		burp.StartBurp.main(args);
	}

	public void reset(){
		this.logEntries.clear();
		this.pendingRequests.clear();
		this.totalRequests = 0;
		this.logViewPanel.getLogTable().getModel().fireTableDataChanged();
	}

	public LoggerPreferences getLoggerPreferences() {
		return loggerPreferences;
	}

	public LogTable getLogTable() {
		return logViewPanel.getLogTable();
	}

	public HashMap<Integer, LogEntry.PendingRequestEntry> getPendingRequests() {
		return pendingRequests;
	}

	public IExtensionHelpers getHelpers() {
		return helpers;
	}

	public IBurpExtenderCallbacks getCallbacks() {
		return callbacks;
	}

	public LoggerOptionsPanel getLoggerOptionsPanel() {
		return optionsJPanel;
	}

	public List<LogEntry> getLogEntries() {
		return logEntries;
	}

	public void addLogListener(LogEntryListener listener) {
		logEntryListeners.add(listener);
	}

	public void removeLogListener(LogEntryListener listener) {
		logEntryListeners.remove(listener);
	}

	public ArrayList<LogEntryListener> getLogEntryListeners() {
		return logEntryListeners;
	}

	public VariableViewPanel getMainPanel() {
		return mainPanel;
	}

	public VariableViewPanel getReqRespPanel() {
		return reqRespPanel;
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
}
