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

package loggerplusplus.userinterface;

import com.google.gson.*;
import com.google.gson.reflect.TypeToken;
import loggerplusplus.LoggerPlusPlus;
import loggerplusplus.userinterface.renderer.LeftTableCellRenderer;

import javax.swing.event.TableColumnModelEvent;
import javax.swing.table.DefaultTableColumnModel;
import javax.swing.table.TableColumn;
import java.beans.PropertyChangeEvent;
import java.lang.reflect.Type;
import java.util.*;


// To keep the header descriptor JSON objects and to converts them to list objects

public class LogTableColumnModel extends DefaultTableColumnModel {
	private final String defaultLogTableColumnsJson = "["
			+ "{'id':0,'name':'Number','enabled':true,'defaultVisibleName':'#','visibleName':'#','preferredWidth':35,'type':'int','readonly':true,'order':0,'visible':true,'description':'Item index number','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
			+ "{'id':1,'name':'Tool','enabled':true,'defaultVisibleName':'Tool','visibleName':'Tool','preferredWidth':70,'type':'string','readonly':true,'order':2,'visible':true,'description':'Tool name','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
			+ "{'id':2,'name':'Host','enabled':true,'defaultVisibleName':'Host','visibleName':'Host','preferredWidth':150,'type':'string','readonly':true,'order':3,'visible':true,'description':'Host and Protocol (similar to the Proxy tab)','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
			+ "{'id':3,'name':'Method','enabled':true,'defaultVisibleName':'Method','visibleName':'Method','preferredWidth':65,'type':'string','readonly':true,'order':4,'visible':true,'description':'HTTP request method','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
			+ "{'id':4,'name':'Url','enabled':true,'defaultVisibleName':'URL','visibleName':'URL','preferredWidth':250,'type':'string','readonly':true,'order':5,'visible':false,'description':'Complete URL','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
			+ "{'id':5,'name':'Path','enabled':true,'defaultVisibleName':'Path','visibleName':'Path','preferredWidth':250,'type':'string','readonly':true,'order':6,'visible':true,'description':'Request Path','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
			+ "{'id':6,'name':'Query','enabled':true,'defaultVisibleName':'Query','visibleName':'Query','preferredWidth':250,'type':'string','readonly':true,'order':7,'visible':true,'description':'Query Parameters','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
			+ "{'id':7,'name':'Params','enabled':true,'defaultVisibleName':'Params','visibleName':'Params','preferredWidth':65,'type':'boolean','readonly':true,'order':7,'visible':true,'description':'Indicates whether or not the request has GET or POST parameter(s)','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
			+ "{'id':8,'name':'Status','enabled':true,'defaultVisibleName':'Status','visibleName':'Status','preferredWidth':55,'type':'short','readonly':true,'order':8,'visible':true,'description':'Response status header','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
			+ "{'id':9,'name':'ResponseLength','enabled':true,'defaultVisibleName':'Response Length','visibleName':'Response Length','preferredWidth':100,'type':'int','readonly':true,'order':9,'visible':true,'description':'Length of response','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
			+ "{'id':10,'name':'MimeType','enabled':true,'defaultVisibleName':'MIME type','visibleName':'MIME type','preferredWidth':100,'type':'string','readonly':true,'order':10,'visible':true,'description':'Response content type using Burp API','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
			+ "{'id':11,'name':'UrlExtension','enabled':true,'defaultVisibleName':'Extension','visibleName':'Extension','preferredWidth':70,'type':'string','readonly':true,'order':11,'visible':true,'description':'Target page extension','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
			+ "{'id':12, 'name':'Comment','enabled':true,'defaultVisibleName':'Comment','visibleName':'Comment','preferredWidth':200,'type':'string','readonly':false,'order':12,'visible':true,'description':'Editable comment','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
			+ "{'id':13,'name':'IsSSL','enabled':true,'defaultVisibleName':'SSL','visibleName':'SSL','preferredWidth':50,'type':'boolean','readonly':true,'order':13,'visible':true,'description':'Indicates whether or not the HTTP protocol is HTTPS','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
			+ "{'id':14,'name':'NewCookies','enabled':true,'defaultVisibleName':'New Cookies','visibleName':'New Cookies','preferredWidth':150,'type':'string','readonly':true,'order':14,'visible':true,'description':'Shows any new cookies in the response','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
			+ "{'id':15,'name':'RequestTime','enabled':true,'defaultVisibleName':'Request Time','visibleName':'Request Time','preferredWidth':150,'type':'string','readonly':true,'order':15,'visible':true,'description':'Shows date and time of making the request in this extension','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
			+ "{'id':16,'name':'ListenerInterface','enabled':true,'defaultVisibleName':'Proxy Listener interface','visibleName':'Proxy Listener interface','preferredWidth':150,'type':'string','readonly':true,'order':16,'visible':true,'description':'Shows the proxy listener interface for proxied requests','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
			+ "{'id':17,'name':'ClientIP','enabled':true,'defaultVisibleName':'Proxy Client IP','visibleName':'Proxy Client IP','preferredWidth':150,'type':'string','readonly':true,'order':17,'visible':false,'description':'Shows the client IP address when using the Proxy tab','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
			+ "{'id':18,'name':'ResponseContentType','enabled':true,'defaultVisibleName':'Response Content-Type','visibleName':'Response Content-Type','preferredWidth':150,'type':'string','readonly':true,'order':18,'visible':false,'description':'Shows the content-type header in the response','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
			+ "{'id':19,'name':'InferredType','enabled':true,'defaultVisibleName':'Inferred Type','visibleName':'Inferred Type','preferredWidth':150,'type':'string','readonly':true,'order':19,'visible':false,'description':'Shows the content type which was inferred by Burp','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
			+ "{'id':20,'name':'HasQueryStringParam','enabled':true,'defaultVisibleName':'QueryString?','visibleName':'QueryString?','preferredWidth':50,'type':'boolean','readonly':true,'order':20,'visible':false,'description':'Indicates whether or not the request has any querystring parameters','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
			+ "{'id':21,'name':'HasBodyParam','enabled':true,'defaultVisibleName':'Body Params?','visibleName':'Body Params?','preferredWidth':50,'type':'boolean','readonly':true,'order':21,'visible':false,'description':'Indicates whether or not the request contains any POST parameters','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
			+ "{'id':22,'name':'HasCookieParam','enabled':true,'defaultVisibleName':'Sent Cookie?','visibleName':'Sent Cookie?','preferredWidth':50,'type':'boolean','readonly':true,'order':22,'visible':false,'description':'Indicates whether or not the request has any Cookie parameters','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
			+ "{'id':23,'name':'SentCookies','enabled':true,'defaultVisibleName':'Sent Cookies','visibleName':'Sent Cookies','preferredWidth':150,'type':'string','readonly':true,'order':23,'visible':false,'description':'Shows the cookies which was sent in the request','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
			+ "{'id':24,'name':'UsesCookieJar','enabled':true,'defaultVisibleName':'Contains cookie jar?','visibleName':'Contains cookie jar?','preferredWidth':150,'type':'string','readonly':true,'order':24,'visible':false,'description':'Compares the cookies with the cookie jar ones to see if any of them in use','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
			+ "{'id':25,'name':'Protocol','enabled':true,'defaultVisibleName':'Protocol','visibleName':'Protocol','preferredWidth':80,'type':'string','readonly':true,'order':25,'visible':false,'description':'Shows the request protocol','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
			+ "{'id':26,'name':'Hostname','enabled':true,'defaultVisibleName':'Host Name','visibleName':'Host Name','preferredWidth':150,'type':'string','readonly':true,'order':26,'visible':false,'description':'Shows the request host name','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
			+ "{'id':27,'name':'TargetPort','enabled':true,'defaultVisibleName':'Port','visibleName':'Port','preferredWidth':50,'type':'int','readonly':true,'order':27,'visible':false,'description':'Shows the target port number','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
			+ "{'id':28,'name':'RequestContentType','enabled':true,'defaultVisibleName':'Request Content Type','visibleName':'Request Type','preferredWidth':150,'type':'string','readonly':true,'order':28,'visible':false,'description':'Shows the request content-type header','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
			+ "{'id':29,'name':'Referrer','enabled':true,'defaultVisibleName':'Referrer','visibleName':'Referrer','preferredWidth':250,'type':'string','readonly':true,'order':29,'visible':false,'description':'Shows the referer header','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
			+ "{'id':30,'name':'RequestLength','enabled':true,'defaultVisibleName':'Request Length','visibleName':'Request Length','preferredWidth':150,'type':'int','readonly':true,'order':30,'visible':false,'description':'Shows the request body length','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
			+ "{'id':31,'name':'HasSetCookies','enabled':true,'defaultVisibleName':'Set-Cookie?','visibleName':'Set-Cookie?','preferredWidth':50,'type':'boolean','readonly':true,'order':31,'visible':false,'description':'Indicates whether or not the response contains the set-cookie header','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
			+ "{'id':32,'name':'Complete','enabled':true,'defaultVisibleName':'Complete','visibleName':'Complete','preferredWidth':80,'type':'boolean','readonly':true,'order':1,'visible':true,'description':'Indicates if a response has been received.','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
			+ "{'id':33,'name':'Regex1Req','enabled':true,'defaultVisibleName':'Request RegEx 1','visibleName':'Request RegEx 1','preferredWidth':150,'type':'string','readonly':true,'order':34,'visible':true,'description':'Custom regular expression for request header/body','isRegEx':true,'regExString':'','regExCaseSensitive':false},"
			+ "{'id':34,'name':'Regex2Req','enabled':false,'defaultVisibleName':'Request RegEx 2','visibleName':'Request RegEx 2','preferredWidth':150,'type':'string','readonly':true,'order':35,'visible':true,'description':'Custom regular expression for request header/body','isRegEx':true,'regExString':'','regExCaseSensitive':false},"
			+ "{'id':35,'name':'Regex3Req','enabled':false,'defaultVisibleName':'Request RegEx 3','visibleName':'Request RegEx 3','preferredWidth':150,'type':'string','readonly':true,'order':36,'visible':true,'description':'Custom regular expression for request header/body','isRegEx':true,'regExString':'','regExCaseSensitive':false},"
			+ "{'id':36,'name':'Regex4Req','enabled':false,'defaultVisibleName':'Request RegEx 4','visibleName':'Request RegEx 4','preferredWidth':150,'type':'string','readonly':true,'order':37,'visible':true,'description':'Custom regular expression for request header/body','isRegEx':true,'regExString':'','regExCaseSensitive':false},"
			+ "{'id':37,'name':'Regex5Req','enabled':false,'defaultVisibleName':'Request RegEx 5','visibleName':'Request RegEx 5','preferredWidth':150,'type':'string','readonly':true,'order':38,'visible':true,'description':'Custom regular expression for request header/body','isRegEx':true,'regExString':'','regExCaseSensitive':false},"
			+ "{'id':38,'name':'Regex1Resp','enabled':true,'defaultVisibleName':'Response RegEx 1','visibleName':'Response RegEx 1 - Title','preferredWidth':220,'type':'string','readonly':true,'order':39,'visible':true,'description':'Custom regular expression for response header/body','isRegEx':true,'regExString':'(?<=\\<title\\>)(.)+(?=\\<\\/title\\>)','regExCaseSensitive':false},"
			+ "{'id':39,'name':'Regex2Resp','enabled':false,'defaultVisibleName':'Response RegEx 2','visibleName':'Response RegEx 2','preferredWidth':150,'type':'string','readonly':true,'order':40,'visible':true,'description':'Custom regular expression for response header/body','isRegEx':true,'regExString':'','regExCaseSensitive':false},"
			+ "{'id':40,'name':'Regex3Resp','enabled':false,'defaultVisibleName':'Response RegEx 3','visibleName':'Response RegEx 3','preferredWidth':150,'type':'string','readonly':true,'order':41,'visible':true,'description':'Custom regular expression for response header/body','isRegEx':true,'regExString':'','regExCaseSensitive':true},"
			+ "{'id':41,'name':'Regex4Resp','enabled':false,'defaultVisibleName':'Response RegEx 4','visibleName':'Response RegEx 4','preferredWidth':150,'type':'string','readonly':true,'order':42,'visible':true,'description':'Custom regular expression for response header/body','isRegEx':true,'regExString':'','regExCaseSensitive':false},"
			+ "{'id':42,'name':'Regex5Resp','enabled':false,'defaultVisibleName':'Response RegEx 5','visibleName':'Response RegEx 5','preferredWidth':150,'type':'string','readonly':true,'order':43,'visible':true,'description':'Custom regular expression for response header/body','isRegEx':true,'regExString':'','regExCaseSensitive':false},"
			+ "{'id':43,'name':'Request','enabled':true,'defaultVisibleName':'Request Body','visibleName':'Request Body','preferredWidth':150,'type':'string','readonly':true,'order':44,'visible':false,'description':'Full Request Body','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
			+ "{'id':47,'name':'RequestHeaders','enabled':true,'defaultVisibleName':'Request Headers','visibleName':'Request Headers','preferredWidth':150,'type':'string','readonly':true,'order':44,'visible':false,'description':'Comma Delimited Request Headers','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
			+ "{'id':44,'name':'Response','enabled':true,'defaultVisibleName':'Response Body','visibleName':'Response Body','preferredWidth':150,'type':'string','readonly':true,'order':45,'visible':false,'description':'Full Response Body','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
			+ "{'id':48,'name':'ResponseHeaders','enabled':true,'defaultVisibleName':'Response Headers','visibleName':'Response Headers','preferredWidth':150,'type':'string','readonly':true,'order':45,'visible':false,'description':'Comma Delimited Response Headers','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
			+ "{'id':45,'name':'ResponseTime','enabled':true,'defaultVisibleName':'Response Time','visibleName':'Response Time','preferredWidth':150,'type':'string','readonly':true,'order':15,'visible':true,'description':'Shows date and time of receiving the response in this extension','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
			+ "{'id':46,'name':'ResponseDelay','enabled':true,'defaultVisibleName':'Response Delay','visibleName':'Response Delay','preferredWidth':100,'type':'string','readonly':true,'order':15,'visible':true,'description':'Shows delay between making the request, and receiving the response.','isRegEx':false,'regExString':'','regExCaseSensitive':false}"
			+ "]";

	private Map<Integer, LogTableColumn> columnMap;
	private Map<String, Integer> nameToModelIndexMap;
	private ArrayList<Integer> viewToModelMap;

	public LogTableColumnModel() {
		super();
		populateHeaders();
	}

	private void populateHeaders(){
		String logTableColumnsJSON = LoggerPlusPlus.getInstance().getLoggerPreferences().getTableDetailsJSONString();
		if(logTableColumnsJSON.isEmpty()) {
			// we have to start fresh! nothing was saved so the default string will be used.
			saveColumnJSON(defaultLogTableColumnsJson);
			logTableColumnsJSON = defaultLogTableColumnsJson;
		}

		Type listType = new TypeToken<List<LogTableColumn>>() {}.getType();

		List<LogTableColumn> tempColumnDefList;
		Gson gson = new GsonBuilder().registerTypeAdapter(LogTableColumn.class, new ColumnSerializer()).create();
		try{
			tempColumnDefList = gson.fromJson(logTableColumnsJSON, listType);
		}catch(Exception e){
			// if there was an error in saved grepTable configuration JSON object we have to use the default JSON object
			LoggerPlusPlus.getCallbacks().printError("Error in parsing the grepTable structure JSON object. The default configuration will be used.");
			logTableColumnsJSON = defaultLogTableColumnsJson;
			tempColumnDefList = gson.fromJson(logTableColumnsJSON, listType);
		}

		// Sorting based on order number
		Collections.sort(tempColumnDefList);

		columnMap = new HashMap<Integer, LogTableColumn>();
		nameToModelIndexMap = new HashMap<String, Integer>();
		viewToModelMap = new ArrayList<Integer>();
		for(LogTableColumn column : tempColumnDefList){
			column.setModelIndex(columnMap.size());
			columnMap.put(column.getIdentifier(), column);
			nameToModelIndexMap.put(column.getName().toUpperCase(), column.getIdentifier());
			if(column.isEnabled() && column.isVisible()){
				super.addColumn(column);
				addColumnToViewMap(column.getIdentifier(), false);
			}
			if(column.getType().equals("int")
					|| column.getType().equals("short")
					|| column.getType().equals("double"))
				column.setCellRenderer(new LeftTableCellRenderer());
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
		LoggerPlusPlus.getInstance().getLoggerPreferences().setTableDetailsJSONString(logTableColumnsJSON);
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
			LoggerPlusPlus.getCallbacks().printError("Column Enabled check on nonexistent column! Corrupted column set? \"" + colName + "\"");
			return false;
		}else {
			return columnMap.get(modelColumnIndex).isEnabled();
		}
	}

	@Override
	public void addColumn(TableColumn tableColumn) {
		super.addColumn(tableColumn);
		addColumnToViewMap((Integer) tableColumn.getIdentifier(), true);
	}

	private void removeColumnFromViewMap(int viewColumn, boolean saveToPrefs){
		viewToModelMap.remove(viewColumn);
		reorderViewColumns(saveToPrefs);
	}

	private void addColumnToViewMap(int modelColumn, boolean saveToPrefs){
		viewToModelMap.add(modelColumn);
		reorderViewColumns(saveToPrefs);
	}

	@Override
	public void removeColumn(TableColumn tableColumn) {
		int viewLoc = getColumnViewLocation(tableColumn.getModelIndex());
		removeColumnFromViewMap(viewLoc, true);
		super.removeColumn(tableColumn);
	}

	@Override
	public int getColumnCount() {
		//DefaultRowSorter implies this is model column count but causes errors if so.
		return viewToModelMap.size();
//		return columnMap.size();
	}

	@Override
	public Enumeration<TableColumn> getColumns() {
		ArrayList<TableColumn> columns = new ArrayList<TableColumn>();
		for (Integer colIndex : viewToModelMap) {
			columns.add(columnMap.get(colIndex));
		}
		return Collections.enumeration(columns);
	}

	public ArrayList<LogTableColumn> getAllColumns(){
		return new ArrayList<LogTableColumn>(columnMap.values());
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
		return columnMap.get(viewToModelMap.get(viewColumn));
	}

	public LogTableColumn getModelColumn(int modelColumn) {
		return columnMap.get(modelColumn);
	}

	public int getColumnViewLocation(int modelColumnIndex) {
		return viewToModelMap.indexOf(modelColumnIndex);
	}

//	public String getTableIDsStringByOrder() {
//		String st = "";
//		for(Integer modelIndex : viewToModelMap){
//			st += columnMap.get(modelIndex).getName() + getIdCanaryParam();
//		}
//		return st;
//	}

	private void reorderViewColumns(boolean saveToPrefs){
		Collections.sort(viewToModelMap, new Comparator<Integer>() {
			@Override
			public int compare(Integer colModelId, Integer otherColModelId) {
				return columnMap.get(colModelId).compareTo(columnMap.get(otherColModelId));
			}
		});
		if(saveToPrefs) {
			saveColumnJSON();
		}
	}

	@Override
	public void propertyChange(PropertyChangeEvent propertyChangeEvent) {
		super.propertyChange(propertyChangeEvent);
	}

	@Override
	public void moveColumn(int viewFrom, int viewTo) {
//		viewToModelMap
		columnMap.get(viewToModelMap.get(viewFrom)).setOrder(viewTo);
		if(viewFrom < viewTo) {
			for (int i = viewFrom + 1; i <= viewTo; i++) {
				columnMap.get(viewToModelMap.get(i)).setOrder(i-1);
			}
			reorderViewColumns(true);
		}else if(viewFrom > viewTo){
			for (int i = viewFrom-1; i >= viewTo; i--) {
				columnMap.get(viewToModelMap.get(i)).setOrder(i+1);
			}
			reorderViewColumns(true);
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

	public int getModelColumnCount() {
		return columnMap.size();
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
			object.addProperty("preferredWidth", column.getPreferredWidth());
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
			column.setIdentifier(object.get("id").getAsInt());
			column.setName(object.get("name").getAsString());
			column.setEnabled(object.get("enabled").getAsBoolean());
			column.setDefaultVisibleName(object.get("defaultVisibleName").getAsString());
			column.setVisibleName(object.get("visibleName").getAsString());
			column.setWidth(object.get("preferredWidth").getAsInt());
			column.setType(object.get("type").getAsString());
			column.setReadonly(object.get("readonly").getAsBoolean());
			column.setOrder(object.get("order").getAsInt());
			column.setVisible(object.get("visible").getAsBoolean());
			column.setDescription(object.get("description").getAsString());
			column.setIsRegEx(object.get("isRegEx").getAsBoolean());
			LogTableColumn.RegExData regExData = new LogTableColumn.RegExData();
			if(object.has("regExData")) {
				regExData.setRegExString(object.getAsJsonObject("regExData").get("regExString").getAsString());
				regExData.setRegExCaseSensitive(object.getAsJsonObject("regExData").get("regExCaseSensitive").getAsBoolean());
			}else{
				regExData.setRegExString(object.get("regExString").getAsString());
				regExData.setRegExCaseSensitive(object.get("regExCaseSensitive").getAsBoolean());
			}
			column.setRegExData(regExData);
			return column;
		}
	}
}
