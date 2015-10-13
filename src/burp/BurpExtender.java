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

import java.awt.Component;
import java.awt.Point;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.PrintWriter;
import java.net.URL;
import java.util.*;

import javax.swing.JComponent;
import javax.swing.JMenuItem;
import javax.swing.JPopupMenu;
import javax.swing.JScrollPane;
import javax.swing.JSplitPane;
import javax.swing.JTabbedPane;
import javax.swing.JTable;
import javax.swing.ListSelectionModel;
import javax.swing.ScrollPaneConstants;
import javax.swing.SwingConstants;
import javax.swing.SwingUtilities;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.TableColumnModelEvent;
import javax.swing.event.TableColumnModelListener;
import javax.swing.table.AbstractTableModel;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.TableColumn;
import javax.swing.table.TableModel;

import com.google.gson.Gson;



public class BurpExtender implements IBurpExtender, ITab, IHttpListener, IMessageEditorController, IProxyListener
{
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;
	private PrintWriter stdout;
	private PrintWriter stderr;
	private IMessageEditor requestViewer;
	private IMessageEditor responseViewer;
	private List<LogEntry> log = new ArrayList<LogEntry>();
	private IHttpRequestResponse currentlyDisplayedItem;
	private JTabbedPane topTabs;
	private boolean canSaveCSV = false;
	private LoggerPreferences loggerPreferences;
	private boolean isDebug; // To enabled debugging, it needs to be true in registry
	private TableHelper tableHelper;


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
		callbacks.setExtensionName("Logger++");

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

				// use TableHelper to create ecessary items: tableHeader, logTableModel, logTable
				tableHelper = new TableHelper(loggerPreferences, stdout, stderr,isDebug);

				// preparing columns
				tableHelper.prepareTableColumns();

				// generating the table columns
				tableHelper.generatingTableColumns();

				// main split pane for the View section
				JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT); 

				JScrollPane viewScrollPane = new JScrollPane(tableHelper.getLogTable(),ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS,ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);//View
				// tabs with request/response viewers
				JTabbedPane tabs = new JTabbedPane();
				requestViewer = callbacks.createMessageEditor(BurpExtender.this, false);
				responseViewer = callbacks.createMessageEditor(BurpExtender.this, false);

				tabs.addTab("Request", requestViewer.getComponent());
				tabs.addTab("Response", responseViewer.getComponent());
				splitPane.setLeftComponent(viewScrollPane);
				splitPane.setRightComponent(tabs);

				// Option tab
				LoggerOptionsPanel optionsJPanel = new LoggerOptionsPanel(callbacks, stdout, stderr,tableHelper, log, 
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
						synchronized(log)
						{

							int row = log.size();
							log.add(new LogEntry(toolFlag, messageIsRequest, callbacks.saveBuffersToTempFiles(messageInfo), uUrl, analyzedReq, message, tableHelper, loggerPreferences, stderr, stderr, isValidTool, callbacks));
							tableHelper.getLogTableModel().fireTableRowsInserted(row, row);

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



	//
	// implement IMessageEditorController
	// this allows our request/response viewers to obtain details about the messages being displayed
	//

	@Override
	public byte[] getRequest()
	{
		if(currentlyDisplayedItem==null)
			return "".getBytes();
		return currentlyDisplayedItem.getRequest();
	}

	@Override
	public byte[] getResponse()
	{
		if(currentlyDisplayedItem==null)
			return "".getBytes();
		return currentlyDisplayedItem.getResponse();
	}

	@Override
	public IHttpService getHttpService()
	{
		if(currentlyDisplayedItem==null)
			return null;
		return currentlyDisplayedItem.getHttpService();
	}

	//
	// extend JTable to handle cell selection and column move/resize
	//

	public class Table extends JTable
	{
		private boolean columnWidthChanged;
		private boolean columnMoved;

		public Table(TableModel tableModel)
		{
			super(tableModel);

		}

		@Override
		public void changeSelection(int row, int col, boolean toggle, boolean extend)
		{
			// show the log entry for the selected row
			//MoreHelp.showMessage("row: "+Integer.toString(row)+" - log size: "+Integer.toString(log.size()));
			if(log.size()>=row){
				LogEntry logEntry = log.get(tableHelper.getLogTable().convertRowIndexToModel(row));
				requestViewer.setMessage(logEntry.requestResponse.getRequest(), true);
				if(logEntry.requestResponse.getResponse()!=null)
					responseViewer.setMessage(logEntry.requestResponse.getResponse(), false);
				else
					responseViewer.setMessage(helpers.stringToBytes(""), false);
				currentlyDisplayedItem = logEntry.requestResponse;

				super.changeSelection(row, col, toggle, extend);
			}
		}

		public boolean isColumnMoved() {
			return columnMoved;
		}

		public void setColumnMoved(boolean columnMoved) {
			this.columnMoved = columnMoved;
		}

		public boolean isColumnWidthChanged() {
			return columnWidthChanged;
		}

		public void setColumnWidthChanged(boolean columnWidthChanged) {
			this.columnWidthChanged = columnWidthChanged;
		}


	}

	/* Extending AbstractTableModel to design the table behaviour based on the array list */
	public class LogTableModel extends AbstractTableModel {

		//
		// extend AbstractTableModel
		//

		@Override
		public int getRowCount()
		{
			// To delete the Request/Response table the log section is empty (after deleting the logs when an item is already selected)
			if(currentlyDisplayedItem!=null && log.size() <= 0){
				currentlyDisplayedItem = null;
				requestViewer.setMessage(helpers.stringToBytes(""), true);
				responseViewer.setMessage(helpers.stringToBytes(""), false);
			}
			return log.size();
		}

		@Override
		public int getColumnCount()
		{
			if(tableHelper.getTableHeaderColumnsDetails().getVisibleColumnsDefinitionList()!=null)
				return tableHelper.getTableHeaderColumnsDetails().getVisibleColumnsDefinitionList().size();
			else
				return 0;
		}

		@Override
		public String getColumnName(int columnIndex)
		{
			return (String) tableHelper.getTableHeaderColumnsDetails().getVisibleColumnsDefinitionList().get(columnIndex).getVisibleName();
		}

		@Override
		public boolean isCellEditable(int rowIndex, int columnIndex)
		{
			if(tableHelper.getTableHeaderColumnsDetails().getVisibleColumnsDefinitionList().get(columnIndex).isReadonly()){
				return false;
			}else{
				return true;
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

			// switch((String) tableHelper.getTableHeaderColumnsDetails().getVisibleColumnsDefinitionList().get(columnIndex).getType()){ // this works fine in Java v7

			try{
				String columnClassType = (String) tableHelper.getTableHeaderColumnsDetails().getVisibleColumnsDefinitionList().get(columnIndex).getType();
				switch(columnClassesType.valueOf(columnClassType.toUpperCase())){
				case INT:
					clazz = Integer.class;
					break;
				case SHORT:
					clazz =  Short.class;
					break;
				case DOUBLE:
					clazz =  Double.class;
					break;
				case LONG:
					clazz =  Long.class;
					break;
				case BOOLEAN:
					clazz =  Boolean.class;
					break;
				default:
					clazz =  String.class;
					break;
				}
			}catch(Exception e){
				clazz =  String.class;
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
			String colName = tableHelper.getTableHeaderColumnsDetails().getVisibleColumnsDefinitionList().get(columnIndex).getName();
			if(colName.equals("number")){
				return rowIndex+1;
			}else{
				Object tempValue = logEntry.getValueByName(colName);
				//stderr.println();
				if(tableHelper.getTableHeaderColumnsDetails().getVisibleColumnsDefinitionList().get(columnIndex).getType().equals("int")){
					if (tempValue!=null && !((String) tempValue.toString()).isEmpty())
						return Integer.valueOf(String.valueOf(logEntry.getValueByName((String) tableHelper.getTableHeaderColumnsDetails().getVisibleColumnsDefinitionList().get(columnIndex).getName())));
					else return -1;
				}
				else if(tableHelper.getTableHeaderColumnsDetails().getVisibleColumnsDefinitionList().get(columnIndex).getType().equals("short")){
					if (tempValue!=null && !((String) tempValue.toString()).isEmpty())
						return Short.valueOf(String.valueOf(logEntry.getValueByName((String) tableHelper.getTableHeaderColumnsDetails().getVisibleColumnsDefinitionList().get(columnIndex).getName())));
					else
						return -1;
				}
				else
					return logEntry.getValueByName((String) tableHelper.getTableHeaderColumnsDetails().getVisibleColumnsDefinitionList().get(columnIndex).getName());
			}

		}

	}

	// This has been designed for Java v6 that cannot support String in "switch"
	private enum columnClassesType {
		INT("INT"),
		SHORT("SHORT"),
		DOUBLE("DOUBLE"),
		LONG("LONG"),
		BOOLEAN("BOOLEAN"),
		STRING("STRING");
		private String value;
		private columnClassesType(String value) {
			this.value = value;
		}
		public String getValue() {
			return value;
		}
		@Override
		public String toString() {
			return getValue();
		}
	}

	public class TableHelper  {
		private Table logTable;
		private LogTableModel logTableModel;
		private TableHeaderColumnsDetails tableHeaderColumnsDetails;
		private final boolean isDebug;
		private final PrintWriter stdout;
		private final PrintWriter stderr;

		public TableHelper(LoggerPreferences loggerPreferences, PrintWriter stdout, PrintWriter stderr, boolean isDebug) {
			super();
			this.isDebug = isDebug;
			this.stdout=stdout;
			this.stderr=stderr;
			// creating table header object
			setTableHeaderColumnsDetails(new TableHeaderColumnsDetails(loggerPreferences, stdout, stderr,isDebug));
		}

		public Table getLogTable() {
			return logTable;
		}

		public void setLogTable(Table logTable) {
			this.logTable = logTable;
		}

		public LogTableModel getLogTableModel() {
			return logTableModel;
		}

		public void setLogTableModel(LogTableModel logTableModel) {
			this.logTableModel = logTableModel;
		}

		public TableHeaderColumnsDetails getTableHeaderColumnsDetails() {
			return tableHeaderColumnsDetails;
		}

		public void setTableHeaderColumnsDetails(
				TableHeaderColumnsDetails tableHeaderColumnsDetails) {
			this.tableHeaderColumnsDetails = tableHeaderColumnsDetails;
		}

		public void prepareTableColumns(){
			// table of log entries
			if(getLogTableModel()==null || getLogTable()==null){
				setLogTableModel(new LogTableModel());
				setLogTable(new Table(getLogTableModel()));
			}

			TableHeader tableHeader = new TableHeader (getLogTable().getColumnModel(),getLogTable(),tableHelper,stdout, stderr,isDebug); // This was used to create tool tips
			getLogTable().setTableHeader(tableHeader); // This was used to create tool tips
			getLogTable().setAutoResizeMode(JTable.AUTO_RESIZE_OFF); // to have horizontal scroll bar
			getLogTable().setAutoCreateRowSorter(true); // To fix the sorting
			getLogTable().setSelectionMode(ListSelectionModel.SINGLE_SELECTION); // selecting one row at a time
			getLogTable().setRowHeight(20); // As we are not using Burp customised UI, we have to define the row height to make it more pretty
			((JComponent) getLogTable().getDefaultRenderer(Boolean.class)).setOpaque(true); // to remove the white background of the checkboxes!

			// This will be used in future to develop right click mouse events
			getLogTable().addMouseListener( new MouseAdapter()
			{
				// Detecting right click
				public void mouseReleased( MouseEvent e )
				{
					// Left mouse click
					if ( SwingUtilities.isLeftMouseButton( e ) )
					{
						if(isDebug){
							stdout.println("left click detected on the cells!");
						}
					}
					// Right mouse click
					else if ( SwingUtilities.isRightMouseButton( e ))
					{
						// get the coordinates of the mouse click
						//Point p = e.getPoint();

						// get the row index that contains that coordinate
						//int rowNumber = getLogTable().rowAtPoint( p );

						// Get the ListSelectionModel of the JTable
						//ListSelectionModel model = getLogTable().getSelectionModel();

						// set the selected interval of rows. Using the "rowNumber"
						// variable for the beginning and end selects only that one row.
						//model.setSelectionInterval( rowNumber, rowNumber );
						if(isDebug){
							stdout.println("right click detected on the cells!");
						}

					}
				}

			});

			// another way to detect column dragging to save its settings for next time loading! fooh! seems tricky!
			//			getLogTable().setTableHeader(new JTableHeader(getLogTable().getColumnModel()) {
			//				@Override
			//				public void setDraggedColumn(TableColumn column) {
			//					boolean finished = draggedColumn != null && column == null;
			//					super.setDraggedColumn(column);
			//					if (finished) {
			//						saveOrderTableChange(getLogTable(), getTableHeader());
			//
			//					}
			//				}
			//			});

			getLogTable().getColumnModel().addColumnModelListener(new TableColumnModelListener() {

				public void columnAdded(TableColumnModelEvent e) {
				}

				public void columnRemoved(TableColumnModelEvent e) {
				}

				public void columnMoved(TableColumnModelEvent e) {
					/* columnMoved is called continuously. Therefore, execute code below ONLY if we are not already
	                aware of the column position having changed */
					if(!getLogTable().isColumnMoved())
					{
						/* the condition  below will NOT be true if
	                    the column width is being changed by code. */
						if(getLogTable().getTableHeader().getDraggedColumn() != null)
						{
							// User must have dragged column and changed width
							getLogTable().setColumnMoved(true);
						}
					}
				}

				public void columnMarginChanged(ChangeEvent e) {
					/* columnMarginChanged is called continuously as the column width is changed
	                by dragging. Therefore, execute code below ONLY if we are not already
	                aware of the column width having changed */
					if(!getLogTable().isColumnWidthChanged())
					{
						/* the condition  below will NOT be true if
	                    the column width is being changed by code. */
						if(getLogTable().getTableHeader().getResizingColumn() != null)
						{
							// User must have dragged column and changed width
							getLogTable().setColumnWidthChanged(true);
						}
					}
				}

				public void columnSelectionChanged(ListSelectionEvent e) {
				}
			});

			getLogTable().getTableHeader().addMouseListener(new MouseAdapter(){
				@Override
				public void mouseReleased(MouseEvent e)
				{
					if ( SwingUtilities.isRightMouseButton( e ))
					{
						// get the coordinates of the mouse click
						Point p = e.getPoint();
						int columnID = getLogTable().columnAtPoint(p);
						TableColumn column = getLogTable().getColumnModel().getColumn(columnID);
						TableStructure columnObj = getTableHeaderColumnsDetails().getAllColumnsDefinitionList().get((Integer) column.getIdentifier());
						if(isDebug){
							stdout.println("right click detected on the header!");
							stdout.println("right click on item number " + String.valueOf(columnID) + " ("+getLogTable().getColumnName(columnID)+") was detected");
						}
						
						//TODO
						
						TableHeaderMenu tblHeaderMenu = new TableHeaderMenu(columnObj, tableHelper,stdout, stderr,isDebug);
						tblHeaderMenu.showMenu(e);
					}

					if(getLogTable().isColumnWidthChanged()){
						/* On mouse release, check if column width has changed */
						if(isDebug) {
							stdout.println("Column has been resized!");
						}


						// Reset the flag on the table.
						getLogTable().setColumnWidthChanged(false);

						saveColumnResizeTableChange();
					}else if(getLogTable().isColumnMoved()){
						/* On mouse release, check if column has moved */

						if(isDebug) {
							stdout.println("Column has been moved!");
						}


						// Reset the flag on the table.
						getLogTable().setColumnMoved(false);

						saveOrderTableChange();
					}else{
						//TODO - Nothing for now!
					}
				}
			});
		}
		
		// generate the table columns!
		public void generatingTableColumns(){
			for (int i=0; i<getLogTableModel().getColumnCount(); i++) {
				TableColumn column = getLogTable().getColumnModel().getColumn(i);
				column.setMinWidth(50);
				column.setIdentifier(getTableHeaderColumnsDetails ().getVisibleColumnsDefinitionList().get(i).getId()); // to be able to point to a column directly later
				column.setPreferredWidth((int) getTableHeaderColumnsDetails().getVisibleColumnsDefinitionList().get(i).getWidth());
				
				// to align the numerical fields to left - can't do it for all as it corrupts the boolean ones
				if(getTableHeaderColumnsDetails().getVisibleColumnsDefinitionList().get(i).getType().equals("int") || getTableHeaderColumnsDetails().getVisibleColumnsDefinitionList().get(i).getType().equals("short") ||
						getTableHeaderColumnsDetails().getVisibleColumnsDefinitionList().get(i).getType().equals("double")) 
					column.setCellRenderer(new LeftTableCellRenderer()); 
			}
		}
		
		// to save the order after dragging a column
		private void saveOrderTableChange(){
			// check to see if the table column order has changed or it was just a click!
			String tempTableIDsStringByOrder = "";
			Enumeration<TableColumn> tblCols = getLogTable().getColumnModel().getColumns();
			for (; tblCols.hasMoreElements(); ) {
				tempTableIDsStringByOrder += tblCols.nextElement().getIdentifier() + getTableHeaderColumnsDetails().getIdCanaryParam();
			}

			if(isDebug){
				stdout.println("tempTableIDsStringByOrder: " + tempTableIDsStringByOrder +" -- tableIDsStringByOrder: " + getTableHeaderColumnsDetails().getTableIDsStringByOrder());
			}

			if(!getTableHeaderColumnsDetails().getTableIDsStringByOrder().equals(tempTableIDsStringByOrder)){
				if(isDebug){
					stdout.println("Table has been re-ordered and needs to be saved!");
				}
				// Order of columns has changed! we have to save it now!
				int counter = 1;
				tblCols = getLogTable().getColumnModel().getColumns();
				for (; tblCols.hasMoreElements(); ) {				
					int columnNumber = (Integer) tblCols.nextElement().getIdentifier();
					getTableHeaderColumnsDetails().getAllColumnsDefinitionList().get(columnNumber).setOrder(counter);
					counter++;
				}

				
				getTableHeaderColumnsDetails().setTableIDsStringByOrder(tempTableIDsStringByOrder);
				
				saveTableChanges();
				
				

			}


		}


		// to save the column widths after changes
		private void saveColumnResizeTableChange(){
			Enumeration<TableColumn> tblCols = getLogTable().getColumnModel().getColumns();
			for (; tblCols.hasMoreElements(); ) {	
				TableColumn currentTblCol = tblCols.nextElement();
				int columnNumber = (Integer) currentTblCol.getIdentifier();
				getTableHeaderColumnsDetails().getAllColumnsDefinitionList().get(columnNumber).setWidth(currentTblCol.getWidth());
			}
			saveTableChanges();
		}
		
		// to save the new table changes
		public void saveTableChanges(){
			// save it to the relevant variables and preferences
			getTableHeaderColumnsDetails().setLoggerTableDetailsCurrentJSONString(new Gson().toJson(getTableHeaderColumnsDetails().getAllColumnsDefinitionList()), true);
		}
			
		
	}

	class LeftTableCellRenderer extends DefaultTableCellRenderer { 
		protected  LeftTableCellRenderer() {
			setHorizontalAlignment(SwingConstants.LEFT);  } 
	} 

	public static void main(String [] args){
		System.out.println("You have built the Logger++. You shall play with the jar file now!");
	}


}
