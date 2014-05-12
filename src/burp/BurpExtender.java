package burp;

import java.awt.Component;
import java.io.PrintWriter;
import java.net.URL;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingUtilities;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.TableColumn;
import javax.swing.table.TableModel;
import org.apache.commons.lang3.*;

// Bugs:
// Unknown: it shows error if you sort a table with content and then clear it and then click on the table tab

public class BurpExtender implements IBurpExtender, ITab, IHttpListener, IMessageEditorController
{
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	private PrintWriter stdout;
	private PrintWriter stderr;
	private IMessageEditor requestViewer;
	private IMessageEditor responseViewer;
	private List<LogEntry> log = new ArrayList<LogEntry>();
	private IHttpRequestResponse currentlyDisplayedItem;
	private JSplitPane splitPane;
	private boolean canSaveCSV = false;
	private Table logTable;
	private LogTableModel logTableModel;
	private LoggerPreferences loggerPreferences;
	
	// Future implementation: dynamic columns...
	private static final Object[][] loggerTableDetails = {
		{"number","#",50,"int","static"},{"tool","Tool",70,"string","static"},
		{"status","Status",70,"short","static"},{"protocol","Protocol",80,"string","static"},{"host","Host",150,"string","static"},
		{"targetPort","Port",50,"int","static"},{"url","URL",250,"string","static"},{"method","Method",100,"string","static"},
		{"requstContentType","Req Type",150,"string","static"}, {"urlExtension","Extension",70,"string","static"},
		{"referrerURL","Referrer URL",250,"string","static"}, {"hasQueryStringParam","QS?",100,"boolean","static"},
		{"hasBodyParam","BodyParam?",100,"boolean","static"}, {"hasCookieParam","Cookie?",100,"boolean","static"},
		{"requestLength","Req Length",100,"int","static"}, {"responseContentType","Resp Type",150,"string","static"},
		{"responseContentType_burp","Detected Type",150,"string","static"},{"responseInferredContentType_burp","Inferred Type",150,"string","static"}, 
		{"hasSetCookies","Set-Cookie?",100,"boolean","static"}, {"responseLength","Resp Length",100,"int","static"},
		{"responseTime","Resp Time",150,"string","static"},{"comment","Comment",200,"string","editable"}
	};




	//
	// implement IBurpExtender
	//

	@Override
	public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
	{
		// keep a reference to our callbacks object
		this.callbacks = callbacks;

		// obtain an extension helpers object
		this.helpers = callbacks.getHelpers();

		// obtain our output stream
		stdout = new PrintWriter(callbacks.getStdout(), true);
		stderr = new PrintWriter(callbacks.getStderr(), true);

		// set our extension name
		callbacks.setExtensionName("Custom logger++");
		
		try { 
			Class.forName("org.apache.commons.lang3.StringEscapeUtils");
			canSaveCSV = true;
		} catch(ClassNotFoundException e) {
			stderr.println("Warning: Error in loading Appache Commons Lang library.\r\nThe results cannot be saved in CSV format.\r\n"
					+ "Please reload this extension after adding this library to the Java Environment section of burp suite.\r\n"
					+ "This library is downloadable via http://commons.apache.org/proper/commons-lang/download_lang.cgi");
		}   
		
		loggerPreferences = new LoggerPreferences();
		// create our UI
		SwingUtilities.invokeLater(new Runnable() 
		{
			@Override
			public void run()
			{
				// main split pane
				splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT);


				// table of log entries
				logTableModel = new LogTableModel();
				logTable = new Table(logTableModel);
				logTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF); // to have horizontal scroll bar
				logTable.setAutoCreateRowSorter(true); // To fix the sorting

				for (int i=0; i<logTableModel.getColumnCount(); i++) {
					TableColumn column = logTable.getColumnModel().getColumn(i);
					column.setMinWidth(50);
					column.setPreferredWidth((int) loggerTableDetails[i][2]);

				}

				JScrollPane viewScrollPane = new JScrollPane(logTable,ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS,ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);//View
				LoggerOptionsPanel optionsJPanel = new LoggerOptionsPanel(callbacks, stdout, stderr,logTableModel, log, canSaveCSV, loggerPreferences); //Options

				// tabs with View/Options viewers
				JTabbedPane topTabs = new JTabbedPane();
				requestViewer = callbacks.createMessageEditor(BurpExtender.this, false);
				responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);
				topTabs.addTab("View Logs", null, viewScrollPane, null);
				topTabs.addTab("Options", null, optionsJPanel, null);
				//splitPane.setRightComponent(topTabs);
				splitPane.setLeftComponent(topTabs);

				// tabs with request/response viewers
				JTabbedPane tabs = new JTabbedPane();
				requestViewer = callbacks.createMessageEditor(BurpExtender.this, false);
				responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);
				tabs.addTab("Request", requestViewer.getComponent());
				tabs.addTab("Response", responseViewer.getComponent());
				splitPane.setRightComponent(tabs);

				// customize our UI components
				callbacks.customizeUiComponent(splitPane);
				callbacks.customizeUiComponent(viewScrollPane);
				callbacks.customizeUiComponent(optionsJPanel);
				callbacks.customizeUiComponent(tabs);

				// add the custom tab to Burp's UI
				callbacks.addSuiteTab(BurpExtender.this);

				// register ourselves as an HTTP listener
				callbacks.registerHttpListener(BurpExtender.this);
				
				
			}
		});
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
		return splitPane;
	}

	//
	// implement IHttpListener
	//

	@Override
	public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo)
	{
		//Is it enabled?
		if(loggerPreferences.isEnabled()){
			IRequestInfo analyzedReq = helpers.analyzeRequest(messageInfo);
			URL uUrl = analyzedReq.getUrl();

			// Check for the scope if it is restricted to scope
			if (!loggerPreferences.isRestrictedToScope() || callbacks.isInScope(uUrl))
			{
				boolean isValidTool = false;
				if(loggerPreferences.isEnabled4All()){
					isValidTool = true;
				}else if(loggerPreferences.isEnabled4Proxy() && toolFlag==callbacks.TOOL_PROXY){
					isValidTool = true;
				}else if(loggerPreferences.isEnabled4Intruder() && toolFlag==callbacks.TOOL_INTRUDER){
					isValidTool = true;
				}else if(loggerPreferences.isEnabled4Repeater() && toolFlag==callbacks.TOOL_REPEATER){
					isValidTool = true;
				}else if(loggerPreferences.isEnabled4Scanner() && toolFlag==callbacks.TOOL_SCANNER){
					isValidTool = true;
				}else if(loggerPreferences.isEnabled4Sequencer() && toolFlag==callbacks.TOOL_SEQUENCER){
					isValidTool = true;
				}else if(loggerPreferences.isEnabled4Spider() && toolFlag==callbacks.TOOL_SPIDER){
					isValidTool = true;
				}else if(loggerPreferences.isEnabled4Extender() && toolFlag==callbacks.TOOL_EXTENDER){
					isValidTool = true;
				}else if(loggerPreferences.isEnabled4TargetTab() && toolFlag==callbacks.TOOL_TARGET){
					isValidTool = true;
				}
				
				//stdout.println(toolFlag +" - "+LoggerPreferences.isEnabled4All());
				if(isValidTool){
					// only process responses


					if (messageIsRequest){
						// to be implemented: I need to log the requests and calculate the delay between request and response!
						// I need to create a unique identifier probably here
						// Do I need to add them to LogEntry? should I have a LogEntry for req and one for resp
						// Or should I have a temp one for requests....

//						if(loggerPreferences.isOutputRedirected()){
//							// Needs to be implemented....
//						}

					}else{
						// create a new log entry with the message details
						synchronized(log)
						{
							int row = log.size();




							log.add(new LogEntry(toolFlag, callbacks.saveBuffersToTempFiles(messageInfo), uUrl, analyzedReq));


							logTableModel.fireTableRowsInserted(row, row);
						}
					}
				}
			}
		}
	}


	//
	// implement IMessageEditorController
	// this allows our request/response viewers to obtain details about the messages being displayed
	//

	@Override
	public byte[] getRequest()
	{
		return currentlyDisplayedItem.getRequest();
	}

	@Override
	public byte[] getResponse()
	{
		return currentlyDisplayedItem.getResponse();
	}

	@Override
	public IHttpService getHttpService()
	{
		return currentlyDisplayedItem.getHttpService();
	}

	//
	// extend JTable to handle cell selection
	//

	public class Table extends JTable
	{
		public Table(TableModel tableModel)
		{
			super(tableModel);

		}

		@Override
		public void changeSelection(int row, int col, boolean toggle, boolean extend)
		{
			// show the log entry for the selected row
			if(log.size()>=row){
				LogEntry logEntry = log.get(logTable.convertRowIndexToModel(row));
				requestViewer.setMessage(logEntry.requestResponse.getRequest(), true);
				responseViewer.setMessage(logEntry.requestResponse.getResponse(), false);
				currentlyDisplayedItem = logEntry.requestResponse;

				super.changeSelection(row, col, toggle, extend);
			}
		} 


	}

	//
	// class to hold details of each log entry
	//

	public class LogEntry
	{
		// Request Related
		final int tool;
		final IHttpRequestResponsePersisted requestResponse;
		final URL url;
		String host;
		boolean hasQueryStringParam;
		boolean hasBodyParam;
		boolean hasCookieParam;
		//		String targetIP; // Burp Suite API does not give it to me!
		String urlExtension;
		String referrerURL = "";
		String requstContentType = "";
		String protocol;
		int targetPort;
		int requestLength;
		String method;

		// Response Related
		Short status;
		boolean hasSetCookies;
		String responseTime;
		String responseContentType_burp;
		String responseInferredContentType_burp;
		int responseLength;
		String responseContentType;
		boolean isCompleted = true; // Currently it is true unless I use requests too

		// User Related
		String comment;



		// Future Implementation
		//		final String requestTime; // I can get this only on request
		//		final String requestResponseDelay; // I can get this only on request
		//		final String requestUID; // I need something like this when I want to get the requests to match them with their responses

		LogEntry(int tool, IHttpRequestResponsePersisted requestResponse, URL url, IRequestInfo tempAnalyzedReq )
		{


			IHttpService tempRequestResponseHttpService = requestResponse.getHttpService();
			IResponseInfo tempAnalyzedResp = helpers.analyzeResponse(requestResponse.getResponse());
			String strFullResponse = new String(requestResponse.getResponse());
			String strFullRequest = new String(requestResponse.getRequest());
			List<String> lstFullRequestHeader = tempAnalyzedReq.getHeaders();
			List<String> lstFullResponseHeader = tempAnalyzedResp.getHeaders();

			this.tool = tool;
			this.requestResponse = requestResponse;
			this.url = url;
			this.host = tempRequestResponseHttpService.getHost();
			this.protocol = tempRequestResponseHttpService.getProtocol();
			this.targetPort = tempRequestResponseHttpService.getPort();
			this.status= tempAnalyzedResp.getStatusCode();
			this.method = tempAnalyzedReq.getMethod();
			try{
				// I do not want to purify this to get rid of sessions after ";" or path after "/" as these information can be useful! 
				this.urlExtension = url.getPath().substring(url.getPath().lastIndexOf(".")).toLowerCase();
			}catch(Exception e){
				this.urlExtension = "";
			}

			this.requestLength = strFullRequest.length() - tempAnalyzedReq.getBodyOffset();

			this.hasQueryStringParam = (url.getQuery()!=null) ? true : false;
			this.hasBodyParam = (requestLength>0) ? true : false;
			this.hasCookieParam = false;

			for(String item:lstFullRequestHeader){
				item = item.toLowerCase();
				if(item.startsWith("cookie:")){
					this.hasCookieParam = true;
				}else if(item.startsWith("referer: ")){
					String[] temp = item.split("referer:\\s",2);
					if(temp.length>0)
						this.referrerURL = temp[1];
				}else if(item.startsWith("content-type: ")){
					String[] temp = item.split("content-type:\\s",2);
					if(temp.length>0)
						this.requstContentType = temp[1];
				}
			}


			this.hasSetCookies = (tempAnalyzedResp.getCookies().size()>0) ? true : false;
			this.responseContentType_burp=tempAnalyzedResp.getStatedMimeType();
			this.responseInferredContentType_burp = tempAnalyzedResp.getInferredMimeType();
			this.responseLength= strFullResponse.length() - tempAnalyzedResp.getBodyOffset();
			DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
			Date date = new Date();
			this.responseTime= dateFormat.format(date);
			this.comment = "";

			for(String item:lstFullResponseHeader){
				item = item.toLowerCase();
				if(item.startsWith("content-type: ")){
					String[] temp = item.split("content-type:\\s",2);
					if(temp.length>0)
						this.responseContentType = temp[1];
				}
			}

			tempRequestResponseHttpService = null;
			tempAnalyzedResp = null;
			tempAnalyzedReq = null;

		}

		public String getCSVHeader(boolean isFullLog) {
			StringBuilder result = new StringBuilder();
			for (int i=1; i<loggerTableDetails.length; i++) {
				result.append(loggerTableDetails[i][1]);
				if(i<logTableModel.getColumnCount()-1)
					result.append(",");
			}
			if(isFullLog){
				result.append(",");		    
				result.append("Request");
				result.append(",");
				result.append("Response");
			}
			return result.toString();
		}

		// We need StringEscapeUtils library from http://commons.apache.org/proper/commons-lang/download_lang.cgi
		public String toCSVString(boolean isFullLog) {		
			StringBuilder result = new StringBuilder();
			for (int i=1; i<loggerTableDetails.length; i++) {

				result.append(StringEscapeUtils.escapeCsv(String.valueOf(getValueByName((String) loggerTableDetails[i][0]))));

				if(i<logTableModel.getColumnCount()-1)
					result.append(",");
			}
			if(isFullLog){
				result.append(",");		    
				result.append(StringEscapeUtils.escapeCsv(new String(requestResponse.getRequest())));
				result.append(",");
				result.append(StringEscapeUtils.escapeCsv(new String(requestResponse.getResponse())));
			}
			return result.toString();
		}

		public Object getValueByName(String name){
			switch (name.toLowerCase())
			{
			case "tool":
				return callbacks.getToolName(tool);
			case "url":
				return this.url.toString();
			case "status":
				return this.status;
			case "protocol":
				return this.protocol;
			case "host":
				return this.host;
			case "responsecontenttype_burp":
				return this.responseContentType_burp;
			case "responselength":
				return this.responseLength;
			case "targetport":
				return this.targetPort;
			case "method":
				return this.method;
			case "responsetime":
				return this.responseTime;
			case "comment":
				return this.comment;
			case "requstcontenttype":
				return this.requstContentType;
			case "urlextension":
				return this.urlExtension;
			case "referrerurl":
				return this.referrerURL;
			case "hasquerystringparam":
				return this.hasQueryStringParam;
			case "hasbodyparam":
				return this.hasBodyParam;
			case "hascookieparam":
				return this.hasCookieParam;
			case "requestlength":
				return this.requestLength;
			case "responsecontenttype":
				return this.responseContentType;
			case "responseinferredcontenttype_burp":
				return this.responseInferredContentType_burp;
			case "hassetcookies":
				return this.hasSetCookies;
			default:
				return "";
			}
		}
	}


	public void logTableReset(){
		boolean origState = loggerPreferences.isEnabled();
		loggerPreferences.setEnabled(false);

		log.clear();

		logTableModel.fireTableDataChanged();
		loggerPreferences.setEnabled(origState);	
	}

	public  void deleteData() {
		log.clear();
		int rows = logTableModel.getRowCount();
		if (rows == 0) {
			return;
		}
		logTableModel.fireTableRowsDeleted(0, rows - 1);
	}


	public class LogTableModel extends AbstractTableModel {

		//
		// extend AbstractTableModel
		//

		@Override
		public int getRowCount()
		{
			return log.size();
		}

		@Override
		public int getColumnCount()
		{
			return loggerTableDetails.length;
		}

		@Override
		public String getColumnName(int columnIndex)
		{
			return (String) loggerTableDetails[columnIndex][1];
		}

		@Override
		public boolean isCellEditable(int rowIndex, int columnIndex)
		{
			if(loggerTableDetails[columnIndex][4].equals("editable")){
				return true;
			}else{
				return false;
			}
		}

		@Override
		public void setValueAt(Object value, int rowIndex, int colIndex) {
			LogEntry logEntry = log.get(rowIndex);
			logEntry.comment = (String) value;
			fireTableCellUpdated(rowIndex, colIndex);
		}

		@Override
		public Class<?> getColumnClass(int columnIndex)
		{
			Class clazz;
			switch((String) loggerTableDetails[columnIndex][3]){
			case "int":
				clazz = Integer.class;
				break;
			case "short":
				clazz =  Short.class;
				break;
			case "double":
				clazz =  Double.class;
				break;
			case "long":
				clazz =  Long.class;
				break;
			case "boolean":
				clazz =  Boolean.class;
				break;
			default:
				clazz =  String.class;
				break;
			}
			
			//stdout.println(clazz.getName());
			return clazz;

		}

		@Override
		public Object getValueAt(int rowIndex, int columnIndex)
		{
			if(log.size()-1<rowIndex) return "";

			LogEntry logEntry = log.get(rowIndex);
			//System.out.println(loggerTableDetails[columnIndex][0] +"  --- " +columnIndex);

			if(columnIndex==0){
				return rowIndex+1;
			}else{

				if(loggerTableDetails[columnIndex][3].equals("int"))
					return (int) logEntry.getValueByName((String) loggerTableDetails[columnIndex][0]);
				else if(loggerTableDetails[columnIndex][3].equals("short"))
					return (short) logEntry.getValueByName((String) loggerTableDetails[columnIndex][0]);
				else
					return logEntry.getValueByName((String) loggerTableDetails[columnIndex][0]);
			}

		}

	}



	public static void main(String [] args){
		System.out.println("You have built me! You can play with the jar file now!");
	}


}
