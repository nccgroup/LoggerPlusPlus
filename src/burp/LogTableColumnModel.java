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

import burp.filter.Filter;
import burp.filter.FilterCompiler;
import com.google.gson.*;
import com.google.gson.reflect.TypeToken;

import javax.swing.event.TableColumnModelEvent;
import javax.swing.table.DefaultTableColumnModel;
import javax.swing.table.TableColumn;
import java.io.PrintWriter;
import java.lang.reflect.Type;
import java.util.*;
import java.util.List;


// To keep the header descriptor JSON objects and to converts them to list objects

public class LogTableColumnModel extends DefaultTableColumnModel {
	private final String defaultLogTableColumnsJson = "["
			+ "{'id':0,'name':'number','enabled':true,'defaultVisibleName':'#','visibleName':'#','width':50,'type':'int','readonly':true,'order':1,'visible':true,'description':'Item index number','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':0,'name':'tool','enabled':true,'defaultVisibleName':'Tool','visibleName':'Tool','width':70,'type':'string','readonly':true,'order':2,'visible':true,'description':'Tool name','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':0,'name':'host','enabled':true,'defaultVisibleName':'Host','visibleName':'Host','width':150,'type':'string','readonly':true,'order':3,'visible':true,'description':'Host and Protocol (similar to the Proxy tab)','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':0,'name':'method','enabled':true,'defaultVisibleName':'Method','visibleName':'Method','width':100,'type':'string','readonly':true,'order':4,'visible':true,'description':'HTTP request method','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':0,'name':'url','enabled':true,'defaultVisibleName':'URL','visibleName':'URL','width':250,'type':'string','readonly':true,'order':5,'visible':true,'description':'Destination relative URL','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':0,'name':'params','enabled':true,'defaultVisibleName':'Params','visibleName':'Params','width':100,'type':'boolean','readonly':true,'order':6,'visible':true,'description':'Indicates whether or not the request has GET or POST parameter(s)','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':0,'name':'status','enabled':true,'defaultVisibleName':'Status','visibleName':'Status','width':70,'type':'short','readonly':true,'order':7,'visible':true,'description':'Response status header','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':0,'name':'responseLength','enabled':true,'defaultVisibleName':'Response Length','visibleName':'Response Length','width':150,'type':'int','readonly':true,'order':8,'visible':true,'description':'Length of response','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':0,'name':'responseContentType_burp','enabled':true,'defaultVisibleName':'MIME type','visibleName':'MIME type','width':150,'type':'string','readonly':true,'order':9,'visible':true,'description':'Response content type using Burp API','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':0,'name':'urlExtension','enabled':true,'defaultVisibleName':'Extension','visibleName':'Extension','width':70,'type':'string','readonly':true,'order':10,'visible':true,'description':'Target page extension','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':0, 'name':'comment','enabled':true,'defaultVisibleName':'Comment','visibleName':'Comment','width':200,'type':'string','readonly':false,'order':11,'visible':true,'description':'Editable comment','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':0,'name':'isSSL','enabled':true,'defaultVisibleName':'SSL','visibleName':'SSL','width':100,'type':'boolean','readonly':true,'order':12,'visible':true,'description':'Indicates whether or not the HTTP protocol is HTTPS','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':0,'name':'newCookies','enabled':true,'defaultVisibleName':'New Cookies','visibleName':'New Cookies','width':150,'type':'string','readonly':true,'order':13,'visible':true,'description':'Shows any new cookies in the response','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':0,'name':'responseTime','enabled':true,'defaultVisibleName':'Response Time','visibleName':'Response Time','width':150,'type':'string','readonly':true,'order':14,'visible':true,'description':'Shows date and time of receiving the response in this extension','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':0,'name':'listenerInterface','enabled':true,'defaultVisibleName':'Proxy Listener interface','visibleName':'Proxy Listener interface','width':150,'type':'string','readonly':true,'order':15,'visible':true,'description':'Shows the proxy listener interface for proxied requests','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			/*below field should not be visible by default when users can customise them*/
			+ "{'id':0,'name':'clientIP','enabled':true,'defaultVisibleName':'Proxy Client IP','visibleName':'Proxy Client IP','width':150,'type':'string','readonly':true,'order':16,'visible':false,'description':'Shows the client IP address when using the Proxy tab','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':0,'name':'responseContentType','enabled':true,'defaultVisibleName':'Response Content-Type','visibleName':'Response Content-Type','width':150,'type':'string','readonly':true,'order':17,'visible':false,'description':'Shows the content-type header in the response','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':0,'name':'responseInferredContentType_burp','enabled':true,'defaultVisibleName':'Inferred Type','visibleName':'Inferred Type','width':150,'type':'string','readonly':true,'order':18,'visible':false,'description':'Shows the content type which was inferred by Burp','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':0,'name':'hasQueryStringParam','enabled':true,'defaultVisibleName':'QueryString?','visibleName':'QueryString?','width':100,'type':'boolean','readonly':true,'order':19,'visible':false,'description':'Indicates whether or not the request has any querystring parameters','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':0,'name':'hasBodyParam','enabled':true,'defaultVisibleName':'Body Params?','visibleName':'Body Params?','width':100,'type':'boolean','readonly':true,'order':20,'visible':false,'description':'Indicates whether or not the request contains any POST parameters','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':0,'name':'hasCookieParam','enabled':true,'defaultVisibleName':'Sent Cookie?','visibleName':'Sent Cookie?','width':100,'type':'boolean','readonly':true,'order':21,'visible':false,'description':'Indicates whether or not the request has any Cookie parameters','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':0,'name':'sentCookies','enabled':true,'defaultVisibleName':'Sent Cookies','visibleName':'Sent Cookies','width':150,'type':'string','readonly':true,'order':22,'visible':false,'description':'Shows the cookies which was sent in the request','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':0,'name':'usesCookieJar','enabled':true,'defaultVisibleName':'Contains cookie jar?','visibleName':'Contains cookie jar?','width':150,'type':'string','readonly':true,'order':22,'visible':false,'description':'Compares the cookies with the cookie jar ones to see if any of them in use','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':0,'name':'protocol','enabled':true,'defaultVisibleName':'Protocol','visibleName':'Protocol','width':80,'type':'string','readonly':true,'order':23,'visible':false,'description':'Shows the request protocol','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':0,'name':'hostname','enabled':true,'defaultVisibleName':'Host Name','visibleName':'Host Name','width':150,'type':'string','readonly':true,'order':24,'visible':false,'description':'Shows the request host name','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':0,'name':'targetPort','enabled':true,'defaultVisibleName':'Port','visibleName':'Port','width':50,'type':'int','readonly':true,'order':25,'visible':false,'description':'Shows the target port number','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':0,'name':'requestContentType','enabled':true,'defaultVisibleName':'Request Type','visibleName':'Request Type','width':150,'type':'string','readonly':true,'order':26,'visible':false,'description':'Shows the request content-type header','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':0,'name':'referrerURL','enabled':true,'defaultVisibleName':'Referred','visibleName':'Referred','width':250,'type':'string','readonly':true,'order':27,'visible':false,'description':'Shows the referer header','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':0,'name':'requestLength','enabled':true,'defaultVisibleName':'Request Length','visibleName':'Request Length','width':150,'type':'int','readonly':true,'order':28,'visible':false,'description':'Shows the request body length','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':0,'name':'hasSetCookies','enabled':true,'defaultVisibleName':'Set-Cookie?','visibleName':'Set-Cookie?','width':100,'type':'boolean','readonly':true,'order':29,'visible':false,'description':'Indicates whether or not the response contains the set-cookie header','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':0,'name':'isCompleted','enabled':false,'defaultVisibleName':'Is Completed?','visibleName':'Is Completed?','width':100,'type':'boolean','readonly':true,'order':30,'visible':true,'description':'DONTUSE: Indicates whether or not the request has a response (currently does not work due to Burp extension limitations)','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':0,'name':'uniqueIdentifier','enabled':false,'defaultVisibleName':'UID','visibleName':'UID','width':100,'type':'string','readonly':true,'order':31,'visible':true,'description':'DONTUSE: Shows a unique identifier for request/response','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':0,'name':'regex1Req','enabled':true,'defaultVisibleName':'Request RegEx 1','visibleName':'Request RegEx 1','width':150,'type':'string','readonly':true,'order':32,'visible':true,'description':'Custom regular expression for request header/body','isRegEx':true,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':0,'name':'regex2Req','enabled':false,'defaultVisibleName':'Request RegEx 2','visibleName':'Request RegEx 2','width':150,'type':'string','readonly':true,'order':32,'visible':true,'description':'Custom regular expression for request header/body','isRegEx':true,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':0,'name':'regex3Req','enabled':false,'defaultVisibleName':'Request RegEx 3','visibleName':'Request RegEx 3','width':150,'type':'string','readonly':true,'order':32,'visible':true,'description':'Custom regular expression for request header/body','isRegEx':true,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':0,'name':'regex4Req','enabled':false,'defaultVisibleName':'Request RegEx 4','visibleName':'Request RegEx 4','width':150,'type':'string','readonly':true,'order':32,'visible':true,'description':'Custom regular expression for request header/body','isRegEx':true,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':0,'name':'regex5Req','enabled':false,'defaultVisibleName':'Request RegEx 5','visibleName':'Request RegEx 5','width':150,'type':'string','readonly':true,'order':32,'visible':true,'description':'Custom regular expression for request header/body','isRegEx':true,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':0,'name':'regex1Resp','enabled':true,'defaultVisibleName':'Response RegEx 1','visibleName':'Response RegEx 1 - Title','width':220,'type':'string','readonly':true,'order':32,'visible':true,'description':'Custom regular expression for response header/body','isRegEx':true,'regExData':{'regExString':'(?<=\\<title\\>)(.)+(?=\\<\\/title\\>)','regExCaseSensitive':false}},"
			+ "{'id':0,'name':'regex2Resp','enabled':false,'defaultVisibleName':'Response RegEx 2','visibleName':'Response RegEx 2','width':150,'type':'string','readonly':true,'order':32,'visible':true,'description':'Custom regular expression for response header/body','isRegEx':true,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':0,'name':'regex3Resp','enabled':false,'defaultVisibleName':'Response RegEx 3','visibleName':'Response RegEx 3','width':150,'type':'string','readonly':true,'order':32,'visible':true,'description':'Custom regular expression for response header/body','isRegEx':true,'regExData':{'regExString':'','regExCaseSensitive':true}},"
			+ "{'id':0,'name':'regex4Resp','enabled':false,'defaultVisibleName':'Response RegEx 4','visibleName':'Response RegEx 4','width':150,'type':'string','readonly':true,'order':32,'visible':true,'description':'Custom regular expression for response header/body','isRegEx':true,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':0,'name':'regex5Resp','enabled':false,'defaultVisibleName':'Response RegEx 5','visibleName':'Response RegEx 5','width':150,'type':'string','readonly':true,'order':32,'visible':true,'description':'Custom regular expression for response header/body','isRegEx':true,'regExData':{'regExString':'','regExCaseSensitive':false}}"
			+ "]";

	private Map<Integer, LogTableColumn> columnMap;
	private Map<String, Integer> nameToModelIndexMap;
	private ArrayList<Integer> viewToModelMap;
	private PrintWriter stdout, stderr;
	private boolean isDebug;
	private final String idCanaryParam = ",";

	public LogTableColumnModel(PrintWriter stdout, PrintWriter stderr, boolean isDebug) {
		super();
		this.stdout = stdout;
		this.stderr = stderr;
		this.isDebug = isDebug;
		populateHeaders();
	}

	private void populateHeaders(){
		String logTableColumnsJSON = BurpExtender.getInstance().getLoggerPreferences().getTableDetailsJSONString();
		if(logTableColumnsJSON.isEmpty()) {
			// we have to start fresh! nothing was saved so the default string will be used.
			saveColumnJSON(defaultLogTableColumnsJson);
		}

		Type listType = new TypeToken<List<LogTableColumn>>() {}.getType();

		List<LogTableColumn> tempColumnDefList;
		Gson gson = new GsonBuilder().registerTypeAdapter(LogTableColumn.class, new ColumnSerializer()).create();
		try{
			tempColumnDefList = gson.fromJson(logTableColumnsJSON, listType);
		}catch(Exception e){
			// if there was an error in saved table configuration JSON object we have to use the default JSON object
			stderr.println("Error in parsing the table structure JSON object. The default configuration will be used.");
			logTableColumnsJSON = defaultLogTableColumnsJson;
			tempColumnDefList = gson.fromJson(logTableColumnsJSON, listType);
		}

		// Sorting based on order number
		Collections.sort(tempColumnDefList);

		columnMap = new HashMap<Integer, LogTableColumn>();
		nameToModelIndexMap = new HashMap<String, Integer>();
		viewToModelMap = new ArrayList<>();
		for(LogTableColumn column : tempColumnDefList){
			column.setIdentifier(columnMap.size());
			column.setModelIndex(columnMap.size());
			columnMap.put(column.getIdentifier(), column);
			nameToModelIndexMap.put(column.getName().toUpperCase(), column.getIdentifier());
			if(column.isEnabled() && column.isVisible()){
				viewToModelMap.add(column.getIdentifier());
			}
			if(column.getType().equals("int")
					|| column.getType().equals("short")
					|| column.getType().equals("double"))
				column.setCellRenderer(new LogTable.LeftTableCellRenderer());
		}

		if(isDebug){
			stdout.println("columnMap.size(): " + columnMap.size());
		}
	}

	public void resetToDefaultVariables() {
		saveColumnJSON(defaultLogTableColumnsJson);
		populateHeaders();
	}

	public void saveColumnJSON() {
		ArrayList<LogTableColumn> columns = new ArrayList<LogTableColumn>(columnMap.values());
		Gson gson = new GsonBuilder().registerTypeAdapter(LogTableColumn.class, new ColumnSerializer()).create();
		saveColumnJSON(gson.toJson(columns));
	}

	public void saveColumnJSON(String logTableColumnsJSON) {
		BurpExtender.getInstance().getLoggerPreferences().setTableDetailsJSONString(logTableColumnsJSON);
	}

	public String getIdCanaryParam() {
		return idCanaryParam;
	}

	public LogTableColumn getColumnByName(String colName){
		return columnMap.get(nameToModelIndexMap.get(colName.toUpperCase()));
	}

	public Integer getColumnIndexByName(String colName){
		return nameToModelIndexMap.get(colName.toUpperCase());
	}

	public boolean isColumnEnabled(String colName){
		Integer modelColumnIndex = nameToModelIndexMap.get(colName.toUpperCase());
		if(modelColumnIndex == null){
			stderr.write("Column Enabled check on nonexistent column! Corrupted column set? \"" + colName + "\"");
			return false;
		}else {
			return columnMap.get(modelColumnIndex).isEnabled();
		}
	}

	@Override
	public void addColumn(TableColumn tableColumn) {
		addColumnToViewMap((Integer) tableColumn.getIdentifier());
		super.addColumn(tableColumn);
	}

	private void removeColumnFromViewMap(int viewColumn){
		viewToModelMap.remove(viewColumn);
		reorderViewColumns();
	}

	private void addColumnToViewMap(int modelColumn){
		viewToModelMap.add(modelColumn);
		reorderViewColumns();
	}

	@Override
	public void removeColumn(TableColumn tableColumn) {
		int viewLoc = getColumnViewLocation(tableColumn.getModelIndex());
		removeColumnFromViewMap(viewLoc);
		super.removeColumn(tableColumn);
	}

	@Override
	public int getColumnCount() {
		return viewToModelMap.size();
	}

	@Override
	public Enumeration<TableColumn> getColumns() {
		ArrayList<TableColumn> columns = new ArrayList<>();
		for (Integer colIndex : viewToModelMap) {
			columns.add(columnMap.get(colIndex));
		}
		return Collections.enumeration(columns);
	}

	public ArrayList<LogTableColumn> getAllColumns(){
		return new ArrayList<>(columnMap.values());
	}

	@Override
	public int getColumnIndex(Object o) {
		if(o instanceof LogTableColumn){
			return ((LogTableColumn) o).getIdentifier();
		}
		return -1;
	}

	@Override
	public LogTableColumn getColumn(int viewColumn) {
		//Suggests param is viewcolumn - BasicTableHeaderUI:259
		return columnMap.get(viewToModelMap.get(viewColumn));
	}

	public LogTableColumn getModelColumn(int modelColumn) {
		return columnMap.get(modelColumn);
	}

	public int getColumnViewLocation(int modelColumnIndex) {
		return viewToModelMap.indexOf((Integer) modelColumnIndex);
	}

	public String getTableIDsStringByOrder() {
		String st = "";
		for(Integer modelIndex : viewToModelMap){
			st += columnMap.get(modelIndex).getName() + getIdCanaryParam();
		}
		return st;
	}

	private void reorderViewColumns(){
		Collections.sort(viewToModelMap, new Comparator<Integer>() {
			@Override
			public int compare(Integer colModelId, Integer otherColModelId) {
				return columnMap.get(colModelId).compareTo(columnMap.get(otherColModelId));
			}
		});
		System.out.println("Saving columns...");
	}

	@Override
	public void moveColumn(int viewFrom, int viewTo) {
//		viewToModelMap
		columnMap.get(viewToModelMap.get(viewFrom)).setOrder(viewTo);
		if(viewFrom < viewTo) {
			for (int i = viewFrom + 1; i <= viewTo; i++) {
				columnMap.get(viewToModelMap.get(i)).setOrder(i-1);
			}
			reorderViewColumns();
		}else if(viewFrom > viewTo){
			for (int i = viewFrom-1; i >= viewTo; i--) {
				columnMap.get(viewToModelMap.get(i)).setOrder(i+1);
			}
			reorderViewColumns();
		}else{
			//no change
		}
		this.fireColumnMoved(new TableColumnModelEvent(this, viewFrom, viewTo));
	}

	public void toggleDisabled(LogTableColumn logTableColumn) {
		logTableColumn.setEnabled(!logTableColumn.isEnabled());
		if(logTableColumn.isEnabled()){
			logTableColumn.setVisible(true); // when a field is enabled, then it becomes visible automatically
			//Add column to view
			addColumn(logTableColumn);
		}else{
			//Remove column from view
			removeColumn(logTableColumn);
		}
	}

	public void toggleHidden(LogTableColumn logTableColumn) {
		logTableColumn.setVisible(!logTableColumn.isVisible());
		if(logTableColumn.isVisible() && logTableColumn.isEnabled()){
			//Add the column to the view
			addColumn(logTableColumn);
		}else{
			//Remove the column from the view and adjust others to fit.
			removeColumn(logTableColumn);
		}
	}

	public TableColumn getColumnByViewLocation(int viewColumn) {
		return columnMap.get(viewToModelMap.get(viewColumn));
	}

	private class ColumnSerializer implements JsonDeserializer<LogTableColumn>, JsonSerializer<LogTableColumn> {
		//id, name, enabled, defaultVisibleName, visibleName, width, type, readonly, order, visible, description, isRegEx, regExData
		@Override
		public JsonElement serialize(LogTableColumn column, Type type, JsonSerializationContext jsonSerializationContext) {
			JsonObject object = new JsonObject();
			object.addProperty("id", column.getIdentifier());
			object.addProperty("name", column.getName());
			object.addProperty("enabled", column.isEnabled());
			object.addProperty("defaultVisibleName", column.getDefaultVisibleName());
			object.addProperty("visibleName", column.getVisibleName());
			object.addProperty("width", column.getWidth());
			object.addProperty("type", column.getType());
			object.addProperty("readonly", column.isReadonly());
			object.addProperty("order", column.getOrder());
			object.addProperty("visible", column.isVisible());
			object.addProperty("description", column.getDescription());
			object.addProperty("isRegEx", column.isRegEx());
			object.addProperty("regExString", column.getRegExData().getRegExString());
			object.addProperty("regExCaseSensitive", column.getRegExData().isRegExCaseSensitive());
			return object;
		}

		@Override
		public LogTableColumn deserialize(JsonElement jsonElement, Type type, JsonDeserializationContext jsonDeserializationContext) throws JsonParseException {
			LogTableColumn column = null;
			column = new LogTableColumn();
			JsonObject object = jsonElement.getAsJsonObject();
			column.setIdentifier(object.get("id"));
			column.setName(object.get("name").getAsString());
			column.setEnabled(object.get("enabled").getAsBoolean());
			column.setDefaultVisibleName(object.get("defaultVisibleName").getAsString());
			column.setVisibleName(object.get("visibleName").getAsString());
			column.setWidth(object.get("width").getAsInt());
			column.setType(object.get("type").getAsString());
			column.setReadonly(object.get("readonly").getAsBoolean());
			column.setOrder(object.get("order").getAsInt());
			column.setVisible(object.get("visible").getAsBoolean());
			column.setDescription(object.get("description").getAsString());
			column.setIsRegEx(object.get("isRegEx").getAsBoolean());
			LogTableColumn.RegExData regExData = new LogTableColumn.RegExData();
			regExData.setRegExString(object.getAsJsonObject("regExData").get("regExString").getAsString());
			regExData.setRegExCaseSensitive(object.getAsJsonObject("regExData").get("regExCaseSensitive").getAsBoolean());
			column.setRegExData(regExData);
			return column;
		}
	}
}
