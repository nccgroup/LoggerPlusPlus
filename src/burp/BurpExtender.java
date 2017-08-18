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

import burp.filter.ColorFilter;
import burp.filter.FilterListener;

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
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;


public class BurpExtender implements IBurpExtender, ITab, IHttpListener, IMessageEditorController, IProxyListener, FilterListener
{
	private static BurpExtender instance;
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	private PrintWriter stdout;
	private PrintWriter stderr;
	private IMessageEditor requestViewer;
	private IMessageEditor responseViewer;
	private final List<LogEntry> log = new ArrayList<LogEntry>();
	private final HashMap<Integer, LogEntry.PendingRequestEntry> pendingRequests = new HashMap<Integer, LogEntry.PendingRequestEntry>();
	private JPanel mainUIWrapper;
	private JTabbedPane mainUI;
	private boolean canSaveCSV = false;
	private LoggerPreferences loggerPreferences;
	private AboutPanel aboutJPanel;
	private LoggerOptionsPanel optionsJPanel;
	private boolean isDebug; // To enabled debugging, it needs to be true in registry
	private LogTable logTable;
	private JTextField filterField;
	private ColorFilterDialog colorFilterDialog;
	private final ArrayList<FilterListener> filterListeners = new ArrayList<FilterListener>();
	private JScrollBar logTableScrollBar;
	private JPanel logViewJPanelWrapper;
	private JSplitPane logViewSplit;
	private JTabbedPane logViewTabbed;
	private JPanel logTablePanel;
	private JPanel reqRespPanel;
	private JTabbedPane reqRespTabbedPane;
	private JSplitPane reqRespSplitPane;
	private JMenu loggerMenu;
	private LoggerPreferences.View currentView;
	private LoggerPreferences.View currentReqRespView;
	ScheduledFuture cleanup;
	int totalRequests = 0;
	//
	// implement IBurpExtender
	//

	@Override
	public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
	{
		instance = this;
		// set our extension name
		callbacks.setExtensionName("Logger++");

		// keep a reference to our callbacks object
		this.callbacks = callbacks;
		// obtain an extension helpers object
		this.helpers = callbacks.getHelpers();

		// obtain our output stream
		stdout = new PrintWriter(callbacks.getStdout(), true);
		stderr = new PrintWriter(callbacks.getStderr(), true);

		try { 
			Class.forName("org.apache.commons.lang3.StringEscapeUtils");
			canSaveCSV = true;
		} catch(ClassNotFoundException e) {
			stderr.println("Warning: Error in loading Appache Commons Lang library.\r\nThe results cannot be saved in CSV format.\r\n"
					+ "Please reload this extension after adding this library to the Java Environment section of burp suite.\r\n"
					+ "This library is downloadable via http://commons.apache.org/proper/commons-lang/download_lang.cgi");
		}   

		loggerPreferences = new LoggerPreferences();
		if(loggerPreferences.getColorFilters() == null) loggerPreferences.setColorFilters(new HashMap<UUID, ColorFilter>());
		this.filterListeners.add(this);
		this.isDebug = loggerPreferences.isDebugMode();

		// create our UI
		requestViewer = callbacks.createMessageEditor(BurpExtender.this, false);
		responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);
		logTable = new LogTable(log, stdout, stderr, isDebug);

		// Options Panel
		optionsJPanel = new LoggerOptionsPanel(callbacks, stdout, stderr, canSaveCSV, loggerPreferences, isDebug);
		// About Panel
		aboutJPanel = new AboutPanel(callbacks, stdout, stderr, loggerPreferences, isDebug); //Options

		//Add ui elements to ui.
		SwingUtilities.invokeLater(new Runnable() 
		{
			@Override
			public void run()
			{
				mainUI = new JTabbedPane();
				//Let the user resize the splitter at will:
				//mainUI.setMinimumSize(new Dimension(0, 0));

				// Log View Panel
				logViewJPanelWrapper = new JPanel(new BorderLayout());
				logViewSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
				logViewTabbed = new JTabbedPane();

				//LogTablePanel
				logTablePanel = new JPanel(new GridBagLayout());
				JScrollPane logTableScrollPane = new JScrollPane(logTable,ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS,ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);//View
				logTableScrollBar = logTableScrollPane.getVerticalScrollBar();
				GridBagConstraints gbc = new GridBagConstraints();
				gbc.weighty = 1;
				gbc.gridy = 0;
				gbc.fill = GridBagConstraints.BOTH;
				gbc.weightx = 1;
				logTablePanel.add(getFilterPanel(), gbc);
				gbc.weighty = 999;
				gbc.gridy = 1;
				logTablePanel.add(logTableScrollPane, gbc);
				//LogTablePanel

				reqRespPanel = new JPanel(new BorderLayout());
				reqRespTabbedPane = new JTabbedPane();
				reqRespSplitPane = new JSplitPane();

				LoggerPreferences.View reqRespView = LoggerPreferences.View.HORIZONTAL;
				setRequestResponseLayout(reqRespView);


				//Split
				logViewSplit.setBottomComponent(reqRespPanel);
				logViewSplit.setResizeWeight(0.5);

				logViewTabbed.addTab("Log LogTable", logTablePanel);
				logViewTabbed.addTab("Request/Response", reqRespPanel);

				setLayout(loggerPreferences.getView());
				setRequestResponseLayout(loggerPreferences.getReqRespView());

				// customize our UI components
				//callbacks.customizeUiComponent(mainUI); // disabled to be able to drag and drop columns
				mainUI.addTab("View Logs", null, logViewJPanelWrapper, null);
				mainUI.addTab("Options", null, optionsJPanel, null);
				mainUI.addTab("About", null, aboutJPanel, null);

				mainUIWrapper = new JPanel(new BorderLayout()){
					@Override
					public void removeNotify(){
						super.removeNotify();
						if(loggerMenu != null){
							loggerMenu.getParent().remove(loggerMenu);
						}
					}
				};
				mainUIWrapper.add(mainUI, BorderLayout.CENTER);

				// add the custom tab to Burp's UI
				callbacks.addSuiteTab(BurpExtender.this);

				// register ourselves as an HTTP listener
				callbacks.registerHttpListener(BurpExtender.this);

				// register ourselves as an HTTP proxy listener as well!
				callbacks.registerProxyListener(BurpExtender.this);

				JFrame rootFrame = (JFrame) SwingUtilities.getWindowAncestor(mainUI);
				try{
					JMenuBar menuBar = rootFrame.getJMenuBar();
					loggerMenu = new JMenu(getTabCaption());
					JMenuItem colorFilters = new JMenuItem(new AbstractAction("Color Filters") {
						@Override
						public void actionPerformed(ActionEvent actionEvent) {
							colorFilterDialog.setVisible(true);
						}
					});
					loggerMenu.add(colorFilters);

					final JMenuItem popout = new JMenuItem(new AbstractAction("Pop Out") {
						@Override
						public void actionPerformed(ActionEvent actionEvent) {
							popOut();
						}
					});
					loggerMenu.add(popout);

					JMenu viewMenu = new JMenu("View");
					ButtonGroup bGroup = new ButtonGroup();
					JRadioButtonMenuItem viewMenuItem = new JRadioButtonMenuItem(new AbstractAction("Top/Bottom Split") {
						@Override
						public void actionPerformed(ActionEvent actionEvent) {
							setLayout(LoggerPreferences.View.VERTICAL);
						}
					});
//					viewMenuItem.setSelected(loggerPreferences.getView() == LoggerPreferences.View.VERTICAL);
					viewMenu.add(viewMenuItem);
					bGroup.add(viewMenuItem);
					viewMenuItem = new JRadioButtonMenuItem(new AbstractAction("Left/Right Split") {
						@Override
						public void actionPerformed(ActionEvent actionEvent) {
							setLayout(LoggerPreferences.View.HORIZONTAL);
						}
					});
//					viewMenuItem.setSelected(loggerPreferences.getView() == LoggerPreferences.View.HORIZONTAL);
					viewMenu.add(viewMenuItem);
					bGroup.add(viewMenuItem);
					viewMenuItem = new JRadioButtonMenuItem(new AbstractAction("Tabs") {
						@Override
						public void actionPerformed(ActionEvent actionEvent) {
							setLayout(LoggerPreferences.View.TABS);
						}
					});
//					viewMenuItem.setSelected(loggerPreferences.getView() == LoggerPreferences.View.TABS);
					viewMenu.add(viewMenuItem);
					loggerMenu.add(viewMenu);

					viewMenu = new JMenu("Request/Response View");
					bGroup = new ButtonGroup();
					viewMenuItem = new JRadioButtonMenuItem(new AbstractAction("Top/Bottom Split") {
						@Override
						public void actionPerformed(ActionEvent actionEvent) {
							setRequestResponseLayout(LoggerPreferences.View.VERTICAL);
						}
					});
					viewMenu.add(viewMenuItem);
					bGroup.add(viewMenuItem);
					viewMenuItem = new JRadioButtonMenuItem(new AbstractAction("Left/Right Split") {
						@Override
						public void actionPerformed(ActionEvent actionEvent) {
							setRequestResponseLayout(LoggerPreferences.View.HORIZONTAL);
						}
					});
					viewMenu.add(viewMenuItem);
					bGroup.add(viewMenuItem);
					viewMenuItem = new JRadioButtonMenuItem(new AbstractAction("Tabs") {
						@Override
						public void actionPerformed(ActionEvent actionEvent) {
							setRequestResponseLayout(LoggerPreferences.View.TABS);
						}
					});
					viewMenu.add(viewMenuItem);
					bGroup.add(viewMenuItem);

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
				int count = 0;
				String refs = "";
				Set<Integer> keys = new HashSet<>(pendingRequests.keySet());
				synchronized (pendingRequests){
					for (Integer reference : keys) {
						try {
							Date date = dateFormat.parse(pendingRequests.get(reference).requestTime);
							if(new Date().getTime() - date.getTime() > BurpExtender.getInstance().getLoggerPreferences().getResponseTimeout()){
								pendingRequests.remove(reference);
								refs += reference + ", ";
								count++;
							}
						} catch (ParseException e) {
							pendingRequests.remove(reference);
						}
					}
				}
			}
		};

		cleanup = executor.scheduleAtFixedRate(cleanupTask, 30000, 30000, TimeUnit.MILLISECONDS);
	}

	public static BurpExtender getInstance() {
		return instance;
	}

	public void setLayout(LoggerPreferences.View view){
		if(view == null) view = LoggerPreferences.View.HORIZONTAL;

		if((currentView == LoggerPreferences.View.TABS || currentView == null) && view != LoggerPreferences.View.TABS){
			logViewJPanelWrapper.removeAll();
			//SplitResetup
			logViewSplit.setTopComponent(logTablePanel);
			logViewSplit.setBottomComponent(reqRespPanel);
			logViewSplit.setDividerLocation(0.5);
			logViewJPanelWrapper.add(logViewSplit);
		}else if((currentView != LoggerPreferences.View.TABS) && view == LoggerPreferences.View.TABS){
			logViewJPanelWrapper.removeAll();
			//TabbedResetup
			logViewTabbed.removeAll();
			logViewTabbed.addTab("Logs", logTablePanel);
			logViewTabbed.addTab("Request / Response", reqRespPanel);
			logViewJPanelWrapper.add(logViewTabbed);
		}

		switch (view) {
			case VERTICAL:
				logViewSplit.setOrientation(JSplitPane.VERTICAL_SPLIT);
				break;
			case HORIZONTAL:
				logViewSplit.setOrientation(JSplitPane.HORIZONTAL_SPLIT);
				break;
		}

		loggerPreferences.setView(view);
		currentView = view;
	}

	public void setRequestResponseLayout(LoggerPreferences.View view){
		if(view == null) view = LoggerPreferences.View.VERTICAL;

		if(view == LoggerPreferences.View.HORIZONTAL || view == LoggerPreferences.View.VERTICAL) {
			reqRespPanel.remove(reqRespTabbedPane);
			reqRespSplitPane.setResizeWeight(0.5);
			reqRespSplitPane.setLeftComponent(requestViewer.getComponent());
			reqRespSplitPane.setRightComponent(responseViewer.getComponent());
			reqRespPanel.add(reqRespSplitPane, BorderLayout.CENTER);
			switch (view) {
				case VERTICAL:
					reqRespSplitPane.setOrientation(JSplitPane.VERTICAL_SPLIT);
					break;
				case HORIZONTAL:
					reqRespSplitPane.setOrientation(JSplitPane.HORIZONTAL_SPLIT);
					break;
			}
			reqRespSplitPane.setDividerLocation(0.5);
		}else {
			reqRespPanel.remove(reqRespSplitPane);
			reqRespTabbedPane.removeAll();
			reqRespTabbedPane.addTab("Request", requestViewer.getComponent());
			reqRespTabbedPane.addTab("Response", responseViewer.getComponent());
			reqRespPanel.add(reqRespTabbedPane, BorderLayout.CENTER);
		}

		loggerPreferences.setReqRespView(view);
		currentReqRespView = view;
	}

	private JPanel getFilterPanel(){
		JPanel filterPanel = new JPanel(new GridBagLayout());
		colorFilterDialog = new ColorFilterDialog(loggerPreferences, filterListeners);

		filterField = new JTextField();
		filterField.getInputMap(JComponent.WHEN_FOCUSED).put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0), "submit");
		filterField.getActionMap().put("submit", new AbstractAction() {
			@Override
			public void actionPerformed(ActionEvent actionEvent) {
				logTable.setFilter(filterField);
			}
		});
		GridBagConstraints fieldConstraints = new GridBagConstraints();
		fieldConstraints.fill = GridBagConstraints.BOTH;
		fieldConstraints.gridx = 0;
		fieldConstraints.weightx = fieldConstraints.weighty = 6.0;

		final JButton filterButton = new JButton("Filter");
		filterButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent actionEvent) {
				logTable.setFilter(filterField);
			}
		});

		GridBagConstraints filterBtnConstraints = new GridBagConstraints();
		filterBtnConstraints.fill = GridBagConstraints.BOTH;
		filterBtnConstraints.gridx = 1;
		filterBtnConstraints.weightx = filterBtnConstraints.weighty = 1.0;

		final JButton colorFilterButton = new JButton("Colorize");
		colorFilterButton.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent actionEvent) {
				colorFilterDialog.setVisible(true);
			}
		});

		GridBagConstraints colorFilterBtnConstraints = new GridBagConstraints();
		colorFilterBtnConstraints.fill = GridBagConstraints.BOTH;
		colorFilterBtnConstraints.gridx = 2;
		colorFilterBtnConstraints.weightx = colorFilterBtnConstraints.weighty = 1.0;

		filterPanel.add(filterField, fieldConstraints);
		filterPanel.add(filterButton, filterBtnConstraints);
		filterPanel.add(colorFilterButton, colorFilterBtnConstraints);

		return filterPanel;
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
		return mainUIWrapper;
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
	short lateResponses = 0;
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
							synchronized (pendingRequests) {
								LogEntry.PendingRequestEntry pendingRequest = pendingRequests.remove(message.getMessageReference());
								if (pendingRequest != null) {
									//Fill in gaps of request with response
									pendingRequest.processResponse(messageInfo);

									for (ColorFilter colorFilter : loggerPreferences.getColorFilters().values()) {
										pendingRequest.testColorFilter(colorFilter, true);
									}
									int newRow = pendingRequest.logRow - loggerPreferences.getMaximumEntries() - totalRequests;
									logTable.getModel().fireTableRowsUpdated(newRow, newRow);
								} else {
									lateResponses++;
									if(log.size() > 100 && ((float)lateResponses)/log.size() > 0.1){
										MoreHelp.showWarningMessage(lateResponses + " responses have been delivered after the Logger++ timeout. Consider increasing this value.");
									}
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
						//After handling request / response log generation.
						//Add to table / modify existing entry.
						int v = (int) (logTableScrollBar.getValue() + (logTableScrollBar.getHeight() * 1.25));
						int m = logTableScrollBar.getMaximum();
						boolean isAtBottom = v >= m;
						synchronized (log) {
							int row = log.size();
							log.add(logEntry);
							totalRequests++;
							if(log.size() > loggerPreferences.getMaximumEntries()){
								for (int i = 0; i <= log.size() - loggerPreferences.getMaximumEntries(); i++) {
									log.remove(0);
									logTable.getModel().fireTableRowsDeleted(0,0);
								}
							}else {
								logTable.getModel().fireTableRowsInserted(row, row);
							}
							if(logEntry instanceof LogEntry.PendingRequestEntry){
								((LogEntry.PendingRequestEntry) logEntry).logRow = totalRequests;
							}
						}
						if (isAtBottom)
							logTableScrollBar.setValue(logTableScrollBar.getMaximum() + logTable.getRowHeight());
						if (loggerPreferences.getAutoSave()) {
							optionsJPanel.autoLogItem(logEntry);
						}
					}
				}
			}
		}
	}

	public void popOut(){
		final JFrame popout = new JFrame();
		popout.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
		popout.setVisible(true);
		popout.addWindowListener(new WindowListener() {
			@Override
			public void windowOpened(WindowEvent windowEvent) {
				popout.add(mainUI);
				popout.pack();
			}

			@Override
			public void windowClosing(WindowEvent windowEvent) {
				mainUIWrapper.add(mainUI, BorderLayout.CENTER);
				mainUIWrapper.revalidate();
			}

			@Override
			public void windowClosed(WindowEvent windowEvent) {}

			@Override
			public void windowIconified(WindowEvent windowEvent) {}

			@Override
			public void windowDeiconified(WindowEvent windowEvent) {}

			@Override
			public void windowActivated(WindowEvent windowEvent) {}

			@Override
			public void windowDeactivated(WindowEvent windowEvent) {}
		});
	}

	public void addColorFilter(ColorFilter colorFilter, boolean showDialog){
		((ColorFilterTableModel) colorFilterDialog.getFilterTable().getModel()).addFilter(colorFilter);
		if(showDialog) colorFilterDialog.setVisible(true);
	}


	//
	// implement IMessageEditorController
	// this allows our request/response viewers to obtain details about the messages being displayed
	//

	@Override
	public byte[] getRequest()
	{
		if(logTable.getModel().getCurrentlyDisplayedItem()==null)
			return "".getBytes();
		return logTable.getModel().getCurrentlyDisplayedItem().getRequest();
	}

	@Override
	public byte[] getResponse()
	{
		if(logTable.getModel().getCurrentlyDisplayedItem()==null)
			return "".getBytes();
		return logTable.getModel().getCurrentlyDisplayedItem().getResponse();
	}

	@Override
	public IHttpService getHttpService()
	{
		if(logTable.getModel().getCurrentlyDisplayedItem()==null)
			return null;
		return logTable.getModel().getCurrentlyDisplayedItem().getHttpService();
	}


	public static void main(String [] args){
		System.out.println("You have built the Logger++. You shall play with the jar file now!");
		burp.StartBurp.main(args);
	}

	//FilterListeners
	@Override
	public void onChange(final ColorFilter filter) {
		Thread onChangeThread = new Thread(new Runnable() {
			@Override
			public void run() {
				for (int i=0; i<log.size(); i++) {
					boolean colorResult = log.get(i).testColorFilter(filter, filter.shouldRetest());
					if(colorResult || filter.isModified()){
						logTable.getModel().fireTableRowsUpdated(i, i);
					}
				}
			}
		});
		onChangeThread.start();
	}

	@Override
	public void onAdd(final ColorFilter filter) {
		if(!filter.isEnabled() || filter.getFilter() == null) return;
		Thread onAddThread = new Thread(new Runnable() {
			@Override
			public void run() {
				for (int i=0; i<log.size(); i++) {
					boolean colorResult = log.get(i).testColorFilter(filter, false);
					if(colorResult) logTable.getModel().fireTableRowsUpdated(i, i);
				}
			}
		});
		onAddThread.start();
	}

	@Override
	public void onRemove(final ColorFilter filter) {
		if(!filter.isEnabled() || filter.getFilter() == null) return;
		Thread onRemoveThread = new Thread(new Runnable(){
			@Override
			public void run() {
				for (int i=0; i<log.size(); i++) {
					boolean wasPresent = log.get(i).matchingColorFilters.remove(filter.getUid());
					if(wasPresent) logTable.getModel().fireTableRowsUpdated(i, i);
				}
			}
		});
		onRemoveThread.start();
	}

	@Override
	public void onRemoveAll() {}

	public void reset(){
		this.log.clear();
		this.pendingRequests.clear();
		this.totalRequests = 0;
		this.logTable.getModel().fireTableDataChanged();
	}

	public JTextField getFilterField() {
		return filterField;
	}

	public IMessageEditor getRequestViewer() { return requestViewer; }
	public IMessageEditor getResponseViewer() { return responseViewer; }

	public LoggerPreferences getLoggerPreferences() {
		return loggerPreferences;
	}

	public LogTable getLogTable() {
		return logTable;
	}

	public HashMap<Integer, LogEntry.PendingRequestEntry> getPendingRequests() {
		return pendingRequests;
	}

	public IExtensionHelpers getHelpers() {
		return helpers;
	}

	public boolean isDebug() {
		return isDebug;
	}

	public PrintWriter getStderr() {
		return stderr;
	}

	public IBurpExtenderCallbacks getCallbacks() {
		return callbacks;
	}

	public LoggerOptionsPanel getLoggerOptionsPanel() {
		return optionsJPanel;
	}

	public List<LogEntry> getLog() {
		return log;
	}

	public PrintWriter getStdout() {
		return stdout;
	}
}
