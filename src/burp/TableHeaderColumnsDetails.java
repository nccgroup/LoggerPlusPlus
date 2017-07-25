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

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import java.io.PrintWriter;
import java.lang.reflect.Type;
import java.util.*;


// To keep the header descriptor JSON objects and to converts them to list objects

public class TableHeaderColumnsDetails  {
	private final String loggerTableDetailsDefaultJSONString = "["
			+ "{'id':0,'name':'number','enabled':true,'defaultVisibleName':'#','visibleName':'#','width':50,'type':'int','readonly':true,'order':1,'visible':true,'description':'Item index number','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':1,'name':'tool','enabled':true,'defaultVisibleName':'Tool','visibleName':'Tool','width':70,'type':'string','readonly':true,'order':2,'visible':true,'description':'Tool name','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':2,'name':'host','enabled':true,'defaultVisibleName':'Host','visibleName':'Host','width':150,'type':'string','readonly':true,'order':3,'visible':true,'description':'Host and Protocol (similar to the Proxy tab)','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':3,'name':'method','enabled':true,'defaultVisibleName':'Method','visibleName':'Method','width':100,'type':'string','readonly':true,'order':4,'visible':true,'description':'HTTP request method','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':4,'name':'url','enabled':true,'defaultVisibleName':'URL','visibleName':'URL','width':250,'type':'string','readonly':true,'order':5,'visible':true,'description':'Destination relative URL','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':5,'name':'params','enabled':true,'defaultVisibleName':'Params','visibleName':'Params','width':100,'type':'boolean','readonly':true,'order':6,'visible':true,'description':'Indicates whether or not the request has GET or POST parameter(s)','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':6,'name':'status','enabled':true,'defaultVisibleName':'Status','visibleName':'Status','width':70,'type':'short','readonly':true,'order':7,'visible':true,'description':'Response status header','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':7,'name':'responseLength','enabled':true,'defaultVisibleName':'Response Length','visibleName':'Response Length','width':150,'type':'int','readonly':true,'order':8,'visible':true,'description':'Length of response','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':8,'name':'responseContentType_burp','enabled':true,'defaultVisibleName':'MIME type','visibleName':'MIME type','width':150,'type':'string','readonly':true,'order':9,'visible':true,'description':'Response content type using Burp API','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':9,'name':'urlExtension','enabled':true,'defaultVisibleName':'Extension','visibleName':'Extension','width':70,'type':'string','readonly':true,'order':10,'visible':true,'description':'Target page extension','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':10, 'name':'comment','enabled':true,'defaultVisibleName':'Comment','visibleName':'Comment','width':200,'type':'string','readonly':false,'order':11,'visible':true,'description':'Editable comment','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':11,'name':'isSSL','enabled':true,'defaultVisibleName':'SSL','visibleName':'SSL','width':100,'type':'boolean','readonly':true,'order':12,'visible':true,'description':'Indicates whether or not the HTTP protocol is HTTPS','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':12,'name':'newCookies','enabled':true,'defaultVisibleName':'New Cookies','visibleName':'New Cookies','width':150,'type':'string','readonly':true,'order':13,'visible':true,'description':'Shows any new cookies in the response','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':13,'name':'responseTime','enabled':true,'defaultVisibleName':'Response Time','visibleName':'Response Time','width':150,'type':'string','readonly':true,'order':14,'visible':true,'description':'Shows date and time of receiving the response in this extension','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':14,'name':'listenerInterface','enabled':true,'defaultVisibleName':'Proxy Listener interface','visibleName':'Proxy Listener interface','width':150,'type':'string','readonly':true,'order':15,'visible':true,'description':'Shows the proxy listener interface for proxied requests','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			/*below field should not be visible by default when users can customise them*/
			+ "{'id':15,'name':'clientIP','enabled':true,'defaultVisibleName':'Proxy Client IP','visibleName':'Proxy Client IP','width':150,'type':'string','readonly':true,'order':16,'visible':false,'description':'Shows the client IP address when using the Proxy tab','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':16,'name':'responseContentType','enabled':true,'defaultVisibleName':'Response Content-Type','visibleName':'Response Content-Type','width':150,'type':'string','readonly':true,'order':17,'visible':false,'description':'Shows the content-type header in the response','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':17,'name':'responseInferredContentType_burp','enabled':true,'defaultVisibleName':'Inferred Type','visibleName':'Inferred Type','width':150,'type':'string','readonly':true,'order':18,'visible':false,'description':'Shows the content type which was inferred by Burp','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':18,'name':'hasQueryStringParam','enabled':true,'defaultVisibleName':'QueryString?','visibleName':'QueryString?','width':100,'type':'boolean','readonly':true,'order':19,'visible':false,'description':'Indicates whether or not the request has any querystring parameters','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':19,'name':'hasBodyParam','enabled':true,'defaultVisibleName':'Body Params?','visibleName':'Body Params?','width':100,'type':'boolean','readonly':true,'order':20,'visible':false,'description':'Indicates whether or not the request contains any POST parameters','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':20,'name':'hasCookieParam','enabled':true,'defaultVisibleName':'Sent Cookie?','visibleName':'Sent Cookie?','width':100,'type':'boolean','readonly':true,'order':21,'visible':false,'description':'Indicates whether or not the request has any Cookie parameters','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':21,'name':'sentCookies','enabled':true,'defaultVisibleName':'Sent Cookies','visibleName':'Sent Cookies','width':150,'type':'string','readonly':true,'order':22,'visible':false,'description':'Shows the cookies which was sent in the request','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':22,'name':'usesCookieJar','enabled':true,'defaultVisibleName':'Contains cookie jar?','visibleName':'Contains cookie jar?','width':150,'type':'string','readonly':true,'order':22,'visible':false,'description':'Compares the cookies with the cookie jar ones to see if any of them in use','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':23,'name':'protocol','enabled':true,'defaultVisibleName':'Protocol','visibleName':'Protocol','width':80,'type':'string','readonly':true,'order':23,'visible':false,'description':'Shows the request protocol','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':24,'name':'hostname','enabled':true,'defaultVisibleName':'Host Name','visibleName':'Host Name','width':150,'type':'string','readonly':true,'order':24,'visible':false,'description':'Shows the request host name','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':25,'name':'targetPort','enabled':true,'defaultVisibleName':'Port','visibleName':'Port','width':50,'type':'int','readonly':true,'order':25,'visible':false,'description':'Shows the target port number','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':26,'name':'requestContentType','enabled':true,'defaultVisibleName':'Request Type','visibleName':'Request Type','width':150,'type':'string','readonly':true,'order':26,'visible':false,'description':'Shows the request content-type header','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':27,'name':'referrerURL','enabled':true,'defaultVisibleName':'Referred','visibleName':'Referred','width':250,'type':'string','readonly':true,'order':27,'visible':false,'description':'Shows the referer header','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':28,'name':'requestLength','enabled':true,'defaultVisibleName':'Request Length','visibleName':'Request Length','width':150,'type':'int','readonly':true,'order':28,'visible':false,'description':'Shows the request body length','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':29,'name':'hasSetCookies','enabled':true,'defaultVisibleName':'Set-Cookie?','visibleName':'Set-Cookie?','width':100,'type':'boolean','readonly':true,'order':29,'visible':false,'description':'Indicates whether or not the response contains the set-cookie header','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':30,'name':'isCompleted','enabled':false,'defaultVisibleName':'Is Completed?','visibleName':'Is Completed?','width':100,'type':'boolean','readonly':true,'order':30,'visible':true,'description':'DONTUSE: Indicates whether or not the request has a response (currently does not work due to Burp extension limitations)','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':31,'name':'uniqueIdentifier','enabled':false,'defaultVisibleName':'UID','visibleName':'UID','width':100,'type':'string','readonly':true,'order':31,'visible':true,'description':'DONTUSE: Shows a unique identifier for request/response','isRegEx':false,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':32,'name':'regex1Req','enabled':true,'defaultVisibleName':'Request RegEx 1','visibleName':'Request RegEx 1','width':150,'type':'string','readonly':true,'order':32,'visible':true,'description':'Custom regular expression for request header/body','isRegEx':true,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':33,'name':'regex2Req','enabled':false,'defaultVisibleName':'Request RegEx 2','visibleName':'Request RegEx 2','width':150,'type':'string','readonly':true,'order':32,'visible':true,'description':'Custom regular expression for request header/body','isRegEx':true,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':34,'name':'regex3Req','enabled':false,'defaultVisibleName':'Request RegEx 3','visibleName':'Request RegEx 3','width':150,'type':'string','readonly':true,'order':32,'visible':true,'description':'Custom regular expression for request header/body','isRegEx':true,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':35,'name':'regex4Req','enabled':false,'defaultVisibleName':'Request RegEx 4','visibleName':'Request RegEx 4','width':150,'type':'string','readonly':true,'order':32,'visible':true,'description':'Custom regular expression for request header/body','isRegEx':true,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':36,'name':'regex5Req','enabled':false,'defaultVisibleName':'Request RegEx 5','visibleName':'Request RegEx 5','width':150,'type':'string','readonly':true,'order':32,'visible':true,'description':'Custom regular expression for request header/body','isRegEx':true,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':37,'name':'regex1Resp','enabled':true,'defaultVisibleName':'Response RegEx 1','visibleName':'Response RegEx 1 - Title','width':220,'type':'string','readonly':true,'order':32,'visible':true,'description':'Custom regular expression for response header/body','isRegEx':true,'regExData':{'regExString':'(?<=\\<title\\>)(.)+(?=\\<\\/title\\>)','regExCaseSensitive':false}},"
			+ "{'id':38,'name':'regex2Resp','enabled':false,'defaultVisibleName':'Response RegEx 2','visibleName':'Response RegEx 2','width':150,'type':'string','readonly':true,'order':32,'visible':true,'description':'Custom regular expression for response header/body','isRegEx':true,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':39,'name':'regex3Resp','enabled':false,'defaultVisibleName':'Response RegEx 3','visibleName':'Response RegEx 3','width':150,'type':'string','readonly':true,'order':32,'visible':true,'description':'Custom regular expression for response header/body','isRegEx':true,'regExData':{'regExString':'','regExCaseSensitive':true}},"
			+ "{'id':30,'name':'regex4Resp','enabled':false,'defaultVisibleName':'Response RegEx 4','visibleName':'Response RegEx 4','width':150,'type':'string','readonly':true,'order':32,'visible':true,'description':'Custom regular expression for response header/body','isRegEx':true,'regExData':{'regExString':'','regExCaseSensitive':false}},"
			+ "{'id':41,'name':'regex5Resp','enabled':false,'defaultVisibleName':'Response RegEx 5','visibleName':'Response RegEx 5','width':150,'type':'string','readonly':true,'order':32,'visible':true,'description':'Custom regular expression for response header/body','isRegEx':true,'regExData':{'regExString':'','regExCaseSensitive':false}}"
			+ "]";
	
	private String loggerTableDetailsCurrentJSONString;
	private List<TableStructure> allColumnsDefinitionList;
	private List<TableStructure> visibleColumnsDefinitionList = new ArrayList<TableStructure>();
	private PrintWriter stdout, stderr;
	private boolean isDebug;
	private final String idCanaryParam = ",";
	private String tableIDsStringByOrder;
	private List<String> enabledItems;
	
	public TableHeaderColumnsDetails(PrintWriter stdout, PrintWriter stderr, boolean isDebug) {
		super();
		this.stdout = stdout;
		this.stderr = stderr;
		this.isDebug = isDebug;
		populateHeaders();
	}
	
	private void populateHeaders(){
		if(getLoggerTableDetailsCurrentJSONString().isEmpty()){
			if(BurpExtender.getInstance().getLoggerPreferences().getTableDetailsJSONString().isEmpty()){
				// we have to start fresh! nothing was saved so the default string will be used.
				setLoggerTableDetailsCurrentJSONString(getLoggerTableDetailsDefaultJSONString(), true);
			}else{
				//retrieve data from the preferences
				setLoggerTableDetailsCurrentJSONString(BurpExtender.getInstance().getLoggerPreferences().getTableDetailsJSONString(),false);
			}
		}
		
		Type listType = new TypeToken<List<TableStructure>>() {}.getType();
		
		List<TableStructure> tempAllDefList;
		
		try{
			tempAllDefList = new Gson().fromJson(getLoggerTableDetailsCurrentJSONString(), listType);
		}catch(Exception e){
			// if there was an error in saved table configuration JSON object we have to use the default JSON object
			stderr.println("Error in parsing the table structure JSON object. The default configuration will be used.");
			setLoggerTableDetailsCurrentJSONString(getLoggerTableDetailsDefaultJSONString(), true);
			tempAllDefList = new Gson().fromJson(getLoggerTableDetailsCurrentJSONString(), listType);
		}
		
		// logging disabled items to speedup this search in the future
		enabledItems = new ArrayList<String>();
		for (Iterator<TableStructure> iterator = tempAllDefList.iterator(); iterator.hasNext(); ) {
			TableStructure columnDefinition = iterator.next();
			if (columnDefinition.isEnabled()) {
				enabledItems.add(columnDefinition.getName());
			}
		}
		
		// Sorting based on order number
		Collections.sort(tempAllDefList, new Comparator<TableStructure>() {
			public int compare(TableStructure o1, TableStructure o2) {
				return o1.getOrder().compareTo(o2.getOrder());
			}
		});
		
		// copying the list to a new list
		List<TableStructure> tempVisibleDefList = new ArrayList<TableStructure>(tempAllDefList);

		// removing invisible or disabled items!
		int counter = 0;
		String tempTableIDsStringByOrder = "";
		for (Iterator<TableStructure> iterator = tempVisibleDefList.iterator(); iterator.hasNext(); ) {
			TableStructure columnDefinition = iterator.next();
			tempAllDefList.get(counter).setOrder(counter+1);
			tempAllDefList.get(counter).setId(counter);
			columnDefinition.setOrder(counter+1);
			columnDefinition.setId(counter);
			if (!columnDefinition.isVisible() || !columnDefinition.isEnabled()) {
				iterator.remove();
			}else{
				tempTableIDsStringByOrder += counter + getIdCanaryParam();
			}
			counter++;
		}
		
		setAllColumnsDefinitionList(tempAllDefList);
		setVisibleColumnsDefinitionList(tempVisibleDefList);
		setTableIDsStringByOrder(tempTableIDsStringByOrder);
		setLoggerTableDetailsCurrentJSONString(new Gson().toJson(tempAllDefList), true);
		
		if(isDebug){
	    	stdout.println(getLoggerTableDetailsCurrentJSONString());
			stdout.println("allColumnsDefinitionList.size(): " + getAllColumnsDefinitionList().size());
			stdout.println("visibleColumnsDefinitionList.size(): " + getVisibleColumnsDefinitionList().size());
		}
	}

	public void resetToDefaultVariables() {
		setLoggerTableDetailsCurrentJSONString(getLoggerTableDetailsDefaultJSONString(), true);
		populateHeaders();
	}
	
	public void resetToCurrentVariables() {
		populateHeaders();
	}
	
	public String getLoggerTableDetailsCurrentJSONString() {
		if(this.loggerTableDetailsCurrentJSONString==null)
			setLoggerTableDetailsCurrentJSONString("",false);
		
		return loggerTableDetailsCurrentJSONString;
	}
	
	public void setLoggerTableDetailsCurrentJSONString(String loggerTableDetailsCurrentJSONString) {
		setLoggerTableDetailsCurrentJSONString(loggerTableDetailsCurrentJSONString,false);
	}	
	
	public void setLoggerTableDetailsCurrentJSONString(
			String loggerTableDetailsCurrentJSONString, boolean saveToPrefs) {
		
		if(loggerTableDetailsCurrentJSONString==null)
			loggerTableDetailsCurrentJSONString="";
		
		// Saving data in preferences
		if(saveToPrefs)
			BurpExtender.getInstance().getLoggerPreferences().setTableDetailsJSONString(loggerTableDetailsCurrentJSONString);
		
		this.loggerTableDetailsCurrentJSONString = loggerTableDetailsCurrentJSONString;
	}
	
	public List<TableStructure> getAllColumnsDefinitionList() {
		return allColumnsDefinitionList;
	}
	
	public void setAllColumnsDefinitionList(
			List<TableStructure> allColumnsDefinitionList) {
		this.allColumnsDefinitionList = allColumnsDefinitionList;
	}
	
	public List<TableStructure> getVisibleColumnsDefinitionList() {
		return visibleColumnsDefinitionList;
	}
	
	public void setVisibleColumnsDefinitionList(
			List<TableStructure> visibleColumnsDefinitionList) {
		this.visibleColumnsDefinitionList = visibleColumnsDefinitionList;
	}
	
	public String getLoggerTableDetailsDefaultJSONString() {
		return loggerTableDetailsDefaultJSONString;
	}
	
	public String getTableIDsStringByOrder() {
		return tableIDsStringByOrder;
	}

	public void setTableIDsStringByOrder(String tableIDsStringByOrder) {
		this.tableIDsStringByOrder = tableIDsStringByOrder;
	}

	public String getIdCanaryParam() {
		return idCanaryParam;
	}
	
	public TableStructure getEnabledTableHeader_byName(String colName){
		TableStructure selectedItem = null;
		for(TableStructure colItem : getAllColumnsDefinitionList()){
			if(colItem.getName().equalsIgnoreCase(colName)){
				selectedItem = colItem;
				break;
			}
		}
		return selectedItem;
	}
	
	public boolean isTableHeaderEnabled_byName(String colName){
		boolean isItEnabled = false;
		if(enabledItems.contains(colName))
		{
			isItEnabled = true;
		}
		return isItEnabled;
	}
	
	


}
