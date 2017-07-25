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

import java.awt.*;
import java.awt.event.*;
import java.io.PrintWriter;
import java.net.URL;
import java.util.*;
import java.util.List;

import javax.swing.*;

import burp.filter.*;


public class BurpExtender implements IBurpExtender, ITab, IHttpListener, IMessageEditorController, IProxyListener, FilterListener
{
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	private PrintWriter stdout;
	private PrintWriter stderr;
	private IMessageEditor requestViewer;
	private IMessageEditor responseViewer;
	private final List<LogEntry> log = new ArrayList<LogEntry>();
	private List<LogEntry> filteredLog = new ArrayList<LogEntry>();
	private JTabbedPane mainUI;
	private boolean canSaveCSV = false;
	private LoggerPreferences loggerPreferences;
	private AboutPanel aboutJPanel;
	private LoggerOptionsPanel optionsJPanel;
	private boolean isDebug; // To enabled debugging, it needs to be true in registry
	private Table logTable;
	private JTextField filterField;
	private ColorFilterDialog colorFilterDialog;
	private ArrayList<FilterListener> filterListeners;
	private JScrollBar logTableScrollBar;
	private JPanel logViewJPanelWrapper;
	private JSplitPane logViewSplit;
	private JTabbedPane logViewTabbed;
	private JPanel logTablePanel;
	private JTabbedPane reqRespTabbedPane;
	private JSplitPane reqRespSplitPane;
	private JMenu loggerMenu;
	private LoggerPreferences.View currentView;
	//
	// implement IBurpExtender
	//

	@Override
	public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
	{
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

		loggerPreferences = new LoggerPreferences(stdout,stderr,isDebug);
		if(loggerPreferences.getColorFilters() == null) loggerPreferences.setColorFilters(new HashMap<UUID, ColorFilter>());
		this.filterListeners = new ArrayList<FilterListener>();
		this.filterListeners.add(this);
		this.isDebug = loggerPreferences.isDebugMode();

		// create our UI
		requestViewer = callbacks.createMessageEditor(BurpExtender.this, false);
		responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);
		logTable = new Table(log, requestViewer, responseViewer, helpers, loggerPreferences, loggerPreferences.getColorFilters(), stdout, stderr, isDebug);

		// Options Panel
		optionsJPanel = new LoggerOptionsPanel(callbacks, stdout, stderr, logTable, log,
				canSaveCSV, loggerPreferences, isDebug);
		// About Panel
		aboutJPanel = new AboutPanel(callbacks, stdout, stderr, loggerPreferences, isDebug); //Options

		//Add ui elements to ui.
		SwingUtilities.invokeLater(new Runnable() 
		{
			@Override
			public void run()
			{
				mainUI = new JTabbedPane(){
					@Override
					public void removeNotify(){
						super.removeNotify();
						if(loggerMenu != null){
							loggerMenu.getParent().remove(loggerMenu);
						}
					}
				};
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


				//Split
				logViewSplit.setBottomComponent(reqRespTabbedPane);
				logViewSplit.setResizeWeight(0.5);
				reqRespTabbedPane = new JTabbedPane();
				reqRespTabbedPane.addTab("Request", requestViewer.getComponent());
				reqRespTabbedPane.addTab("Response", responseViewer.getComponent());

				//Tabbed
				reqRespSplitPane = new JSplitPane();
				reqRespSplitPane.setResizeWeight(0.5);
				logViewTabbed.addTab("Log Table", logTablePanel);
				logViewTabbed.addTab("Request/Response", reqRespSplitPane);

				setLayout(loggerPreferences.getView());

				// customize our UI components
				//callbacks.customizeUiComponent(mainUI); // disabled to be able to drag and drop columns
				mainUI.addTab("View Logs", null, logViewJPanelWrapper, null);
				mainUI.addTab("Options", null, optionsJPanel, null);
				mainUI.addTab("About", null, aboutJPanel, null);

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
					JMenu viewMenu = new JMenu("View");
					ButtonGroup bGroup = new ButtonGroup();
					JRadioButtonMenuItem viewMenuItem = new JRadioButtonMenuItem(new AbstractAction("Top/Bottom Split") {
						@Override
						public void actionPerformed(ActionEvent actionEvent) {
							setLayout(LoggerPreferences.View.VERTICAL);
						}
					});
					viewMenuItem.setSelected(loggerPreferences.getView() == LoggerPreferences.View.VERTICAL);
					viewMenu.add(viewMenuItem);
					bGroup.add(viewMenuItem);
					viewMenuItem = new JRadioButtonMenuItem(new AbstractAction("Left/Right Split") {
						@Override
						public void actionPerformed(ActionEvent actionEvent) {
							setLayout(LoggerPreferences.View.HORIZONTAL);
						}
					});
					viewMenu.add(viewMenuItem);
					bGroup.add(viewMenuItem);
					viewMenuItem = new JRadioButtonMenuItem(new AbstractAction("Tabs") {
						@Override
						public void actionPerformed(ActionEvent actionEvent) {
							setLayout(LoggerPreferences.View.TABS);
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
	}

	private void setLayout(LoggerPreferences.View view){
		if(view == null) view = LoggerPreferences.View.HORIZONTAL;

		if((currentView == LoggerPreferences.View.TABS || currentView == null) && view != LoggerPreferences.View.TABS){
			logViewJPanelWrapper.removeAll();
			//SplitResetup
			logViewSplit.setTopComponent(logTablePanel);
			reqRespTabbedPane.removeAll();
			reqRespTabbedPane.addTab("Request", requestViewer.getComponent());
			reqRespTabbedPane.addTab("Response", responseViewer.getComponent());
			logViewSplit.setBottomComponent(reqRespTabbedPane);
			logViewJPanelWrapper.add(logViewSplit);
		}else if((currentView != LoggerPreferences.View.TABS || currentView == null) && view == LoggerPreferences.View.TABS){
			logViewJPanelWrapper.removeAll();
			//TabbedResetup
			logViewTabbed.removeAll();
			logViewTabbed.addTab("Logs", logTablePanel);
			reqRespSplitPane.setLeftComponent(requestViewer.getComponent());
			reqRespSplitPane.setRightComponent(responseViewer.getComponent());
			logViewTabbed.addTab("Request / Response", reqRespSplitPane);
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

	private JPanel getFilterPanel(){
		JPanel filterPanel = new JPanel(new GridBagLayout());
		colorFilterDialog = new ColorFilterDialog(loggerPreferences, filterListeners);

		filterField = new JTextField();
		filterField.getInputMap(JComponent.WHEN_FOCUSED).put(KeyStroke.getKeyStroke(KeyEvent.VK_ENTER, 0), "submit");
		filterField.getActionMap().put("submit", new AbstractAction() {
			@Override
			public void actionPerformed(ActionEvent actionEvent) {
				setFilter();
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
				setFilter();
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

	private void setFilter(){
		try{
			if(filterField.getText().length() == 0){
				logTable.setFilter(null);
				filterField.setBackground(Color.white);
			}else {
				logTable.setFilter(FilterCompiler.parseString(filterField.getText()));
				filterField.setBackground(Color.green);
			}
		} catch (Filter.FilterException e) {
			filterField.setBackground(Color.red);
			logTable.setFilter(null);
		}
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
		return mainUI;
	}

	//
	// implement IHttpListener
	//

	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo)
	{
		if(toolFlag!=callbacks.TOOL_PROXY) logIt(toolFlag, messageIsRequest, messageInfo, null);
	}

	//
	// implement IProxyListener
	// This is used next to IHttpListener to retrieve more data from the Proxy tab such as the listener port or  the client IP
	//

	@Override
	public void processProxyMessage(boolean messageIsRequest,
			IInterceptedProxyMessage message) {
		logIt(callbacks.TOOL_PROXY, messageIsRequest, null, message);

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
							(loggerPreferences.isEnabled4Proxy() && toolFlag==callbacks.TOOL_PROXY) ||
							(loggerPreferences.isEnabled4Intruder() && toolFlag==callbacks.TOOL_INTRUDER) ||
							(loggerPreferences.isEnabled4Repeater() && toolFlag==callbacks.TOOL_REPEATER) ||
							(loggerPreferences.isEnabled4Scanner() && toolFlag==callbacks.TOOL_SCANNER) ||
							(loggerPreferences.isEnabled4Sequencer() && toolFlag==callbacks.TOOL_SEQUENCER) ||
							(loggerPreferences.isEnabled4Spider() && toolFlag==callbacks.TOOL_SPIDER) ||
							(loggerPreferences.isEnabled4Extender() && toolFlag==callbacks.TOOL_EXTENDER) ||
							(loggerPreferences.isEnabled4TargetTab() && toolFlag==callbacks.TOOL_TARGET));

				//stdout.println(toolFlag +" - "+LoggerPreferences.isEnabled4All());
				if(isValidTool){
					// only process responses


					if (messageIsRequest && toolFlag==callbacks.TOOL_PROXY){
						// Burp does not provide any way to trace a request to its response - only in proxy there is a unique reference
						// BUG: The unique reference is added multiple times to the View table due to the race condition
						// This needs to be fixed in future versions so then we can at least show the live requests that are sent via the proxy section
						// create a new log entry with the message details
						//						synchronized(log)
						//						{
						//							int row = log.size();
						//							log.add(new LogEntry(toolFlag, messageIsRequest, callbacks.saveBuffersToTempFiles(messageInfo), uUrl, analyzedReq, message));
						//							tableHelper.getLogTableModel().fireTableRowsInserted(row, row);
						//						}

					}else if(!messageIsRequest){
						// create a new log entry with the message details
						LogEntry entry = new LogEntry(logTable.getModel(), toolFlag, messageIsRequest, callbacks.saveBuffersToTempFiles(messageInfo), uUrl, analyzedReq, message, logTable, loggerPreferences, stderr, stderr, isValidTool, callbacks);
						//Check entry against colorfilters.
						for (ColorFilter colorFilter : loggerPreferences.getColorFilters().values()) {
							entry.testColorFilter(colorFilter, false);
						}

						int v = (int) (logTableScrollBar.getValue() + (logTableScrollBar.getHeight()*1.1));
						int m = logTableScrollBar.getMaximum();
						boolean isAtBottom = v >= m;

						synchronized (log) {
							int row = log.size();
							log.add(entry);
							logTable.getModel().fireTableRowsInserted(row, row);

							// For proxy - disabled due to the race condition bug!
							//							if(toolFlag!=callbacks.TOOL_PROXY){
							//								int row = log.size();
							//								log.add(new LogEntry(toolFlag, messageIsRequest, callbacks.saveBuffersToTempFiles(messageInfo), uUrl, analyzedReq, message));
							//								tableHelper.getLogTableModel().fireTableRowsInserted(row, row);
							//							}else{
							//								LogEntry responseLog = new LogEntry(toolFlag, messageIsRequest, callbacks.saveBuffersToTempFiles(messageInfo), uUrl, analyzedReq, message);
							//								if (log.contains(responseLog)) {
							//									log.set(log.indexOf(responseLog),responseLog);
							//									tableHelper.getLogTableModel().fireTableDataChanged();
							//								}else{
							//									if(isDebug){
							//										stderr.println("Item was not found: " + message.getMessageReference() + " " + responseLog.uniqueIdentifier);
							//									}
							//								}
							//
							//							}
						}
						if(isAtBottom)
							logTableScrollBar.setValue(logTableScrollBar.getMaximum() + logTable.getRowHeight());
						if(loggerPreferences.getAutoSave()){
							optionsJPanel.autoLogItem(entry);
						}
					}
				}
			}
		}
	}

//	private boolean matchesFilter(LogEntry entry){
//		return filterHelper.matchesFilter(entry);
//	}


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
	public void onChange(ColorFilter filter) {
		if(!filter.isEnabled() || filter.getFilter() == null) return;
		synchronized (log){
			for (int i=0; i<log.size(); i++) {
				boolean colorResult = log.get(i).testColorFilter(filter, true);
				if(colorResult) logTable.getModel().fireTableRowsUpdated(i, i);
			}
		}
	}

	@Override
	public void onAdd(ColorFilter filter) {
		if(!filter.isEnabled() || filter.getFilter() == null) return;
		synchronized (log){
			for (int i=0; i<log.size(); i++) {
				boolean colorResult = log.get(i).testColorFilter(filter, false);
				if(colorResult) logTable.getModel().fireTableRowsUpdated(i, i);
			}
		}
	}

	@Override
	public void onRemove(ColorFilter filter) {
		if(!filter.isEnabled() || filter.getFilter() == null) return;
		synchronized (log){
			for (int i=0; i<log.size(); i++) {
				boolean wasPresent = log.get(i).matchingColorFilters.remove(filter.getUid());
				if(wasPresent) logTable.getModel().fireTableRowsUpdated(i, i);
			}
		}
	}

	@Override
	public void onRemoveAll() {}
}
