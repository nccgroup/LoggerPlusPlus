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
import javax.swing.table.*;

import burp.filter.Filter;


public class BurpExtender implements IBurpExtender, ITab, IHttpListener, IMessageEditorController, IProxyListener
{
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	private PrintWriter stdout;
	private PrintWriter stderr;
	private IMessageEditor requestViewer;
	private IMessageEditor responseViewer;
	private List<LogEntry> log = new ArrayList<LogEntry>();
	private List<LogEntry> filteredLog = new ArrayList<LogEntry>();
	private JTabbedPane topTabs;
	private boolean canSaveCSV = false;
	private LoggerPreferences loggerPreferences;
	private boolean isDebug; // To enabled debugging, it needs to be true in registry
	private Table logTable;
	private TableRowSorter tableRowSorter;
	private JTextField filterField;


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

		this.isDebug = loggerPreferences.isDebugMode();

		// create our UI
		SwingUtilities.invokeLater(new Runnable() 
		{
			@Override
			public void run()
			{

				requestViewer = callbacks.createMessageEditor(BurpExtender.this, false);
				responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);
				logTable = new Table(log, requestViewer, responseViewer, helpers, loggerPreferences, stdout, stderr, isDebug);
				tableRowSorter = new TableRowSorter(logTable.getModel());
				logTable.setRowSorter(tableRowSorter);

				// generating the table columns
				logTable.generatingTableColumns();

				// main split pane for the View section
				JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);
				JPanel viewPanel = new JPanel();
				viewPanel.setLayout(new BoxLayout(viewPanel, BoxLayout.Y_AXIS));

				// create isFiltered pane
				JPanel viewFilterPanel = new JPanel(new BorderLayout());
				JPanel filterPanel = new JPanel(new GridBagLayout());

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
				fieldConstraints.weightx = fieldConstraints.weighty = 4.0;

				final JButton filterButton = new JButton("filter");
				filterButton.addActionListener(new ActionListener() {
					@Override
					public void actionPerformed(ActionEvent actionEvent) {
						setFilter();
					}
				});

				GridBagConstraints btnConstraints = new GridBagConstraints();
				btnConstraints.fill = GridBagConstraints.BOTH;
				btnConstraints.gridx = 1;
				btnConstraints.weightx = btnConstraints.weighty = 1.0;

				filterPanel.add(filterField, fieldConstraints);
				filterPanel.add(filterButton, btnConstraints);
				viewFilterPanel.add(filterPanel, BorderLayout.CENTER);

				JScrollPane viewScrollPane = new JScrollPane(logTable,ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS,ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);//View
				viewPanel.add(viewFilterPanel);
				viewPanel.add(viewScrollPane);

				// tabs with request/response viewers
				JTabbedPane tabs = new JTabbedPane();

				tabs.addTab("Request", requestViewer.getComponent());
				tabs.addTab("Response", responseViewer.getComponent());
				splitPane.setLeftComponent(viewPanel);
				splitPane.setRightComponent(tabs);

				// Option tab
				LoggerOptionsPanel optionsJPanel = new LoggerOptionsPanel(callbacks, stdout, stderr, logTable, log,
						canSaveCSV, loggerPreferences, isDebug);

				// About tab
				AboutPanel aboutJPanel = new AboutPanel(callbacks, stdout, stderr, loggerPreferences, isDebug); //Options

				topTabs = new JTabbedPane();
				//Let the user resize the splitter at will:
				//topTabs.setMinimumSize(new Dimension(0, 0));
				topTabs.addTab("View Logs", null, splitPane, null);
				topTabs.addTab("Options", null, optionsJPanel, null);				
				topTabs.addTab("About", null, aboutJPanel, null);	

				// customize our UI components
				//callbacks.customizeUiComponent(topTabs); // disabled to be able to drag and drop columns

				// add the custom tab to Burp's UI
				callbacks.addSuiteTab(BurpExtender.this);

				// register ourselves as an HTTP listener
				callbacks.registerHttpListener(BurpExtender.this);

				// register ourselves as an HTTP proxy listener as well!
				callbacks.registerProxyListener(BurpExtender.this);

			}
		});
	}

	private void setFilter(){
		try{
			if(filterField.getText().length() == 0){
				tableRowSorter.setRowFilter(null);
				filterField.setBackground(Color.white);
			}else {
				tableRowSorter.setRowFilter(Filter.parseString(filterField.getText()));
				filterField.setBackground(Color.green);
			}
		} catch (Filter.FilterException e) {
			e.printStackTrace();
			filterField.setBackground(Color.red);
			tableRowSorter.setRowFilter(null);
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
		return topTabs;
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
						LogEntry entry = new LogEntry(toolFlag, messageIsRequest, callbacks.saveBuffersToTempFiles(messageInfo), uUrl, analyzedReq, message, logTable, loggerPreferences, stderr, stderr, isValidTool, callbacks);
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


}
