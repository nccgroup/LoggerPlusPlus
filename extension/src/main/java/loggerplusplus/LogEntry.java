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

package loggerplusplus;

import burp.*;
import loggerplusplus.filter.ColorFilter;
import loggerplusplus.userinterface.LogTable;
import loggerplusplus.userinterface.LogTableColumn;
import loggerplusplus.userinterface.LogTableColumnModel;
import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.commons.lang3.StringUtils;

import javax.swing.table.TableColumn;
import java.net.URL;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

//
// class to hold details of each log entry
//
//TODO Better column to value mapping.
public class LogEntry
{

	public boolean isImported;
	public UUID uuid;
	public IHttpRequestResponse requestResponse;
	public int tool;
	public String host="";
	public String method="";
	public URL url;
	public String relativeURL="";
	public boolean params=false;
	public Short status=-1;
	public boolean hasBodyParam=false;
	public boolean hasCookieParam=false;
	public String targetIP=""; // Burp Suite API does not give it to me!
	public String title="";
	public String newCookies="";
	public String sentCookies="";
	public String listenerInterface="";
	public boolean isSSL=false;
	public String urlExtension="";
	public String referrerURL = "";
	public String requestContentType = "";
	public String protocol="";
	public int targetPort=-1;
	public int requestLength=-1;
	public String clientIP="";
	public boolean hasSetCookies=false;
	public String responseTime="";
	public String responseMimeType ="";
	public String responseInferredMimeType ="";
	public int responseLength=-1;
	public String responseContentType="";
	public boolean complete = false;
	public cookieJarStatus usesCookieJar = cookieJarStatus.NO;
	// public User Relatedpublic 
	public String comment="";
	// public RegEx Variablespublic 
	public String[] regexAllReq = {"","","","",""};
	public String[] regexAllResp = {"","","","",""};

	public ArrayList<UUID> matchingColorFilters;
	public int requestBodyOffset;
	public int responseBodyOffset;
	public String requestTime;
	public Date responseDateTime;
	public Date requestDateTime;
	public int requestResponseDelay;
	public String responseHeaders;
	public String requestHeaders;

	private boolean requestProcessed;
	private boolean responseProcessed;

	protected LogEntry(Date arrivalTime){
		this.uuid = UUID.randomUUID();
		this.matchingColorFilters = new ArrayList<UUID>();
		this.setReqestTime(arrivalTime);
	}

	protected LogEntry(boolean isImported){
		this(null);
		this.isImported = isImported;
		if(isImported) {
			this.requestTime = "NA";
			this.responseTime = "NA";
			this.requestResponseDelay = -1;
		}
	}

	public static LogEntry createEntry(Date arrivalTime){
		return new LogEntry(arrivalTime);
	}

	public static LogEntry createImportedEntry(){
		return new LogEntry(true);
	}

	public void processRequest(int tool, IHttpRequestResponse requestResponse, URL url, IRequestInfo tempAnalyzedReq, IInterceptedProxyMessage message){
		IHttpService tempRequestResponseHttpService = requestResponse.getHttpService();
		String strFullRequest = new String(requestResponse.getRequest());
		List<String> lstFullRequestHeader = tempAnalyzedReq.getHeaders();
		requestHeaders = StringUtils.join(lstFullRequestHeader, ", ");
		LogTable logTable = LoggerPlusPlus.instance.getLogTable();

		this.tool = tool;
		this.requestResponse = requestResponse;
		this.url = url;
		this.relativeURL = url.getPath();
		this.host = tempRequestResponseHttpService.getHost();
		this.protocol = tempRequestResponseHttpService.getProtocol();
		this.isSSL= this.protocol.equals("https");
		this.targetPort = tempRequestResponseHttpService.getPort();
		this.method = tempAnalyzedReq.getMethod();
		try{
			// I don't want to delete special characters such as ; or : from the extension as it may really be part of the extension! (burp proxy log ignores them)
			String tempPath = url.getPath().replaceAll("\\\\", "/");
			tempPath = tempPath.substring(tempPath.lastIndexOf("/"));
			int tempPathDotLocation = tempPath.lastIndexOf(".");
			if(tempPathDotLocation>=0)
				this.urlExtension = tempPath.substring(tempPathDotLocation+1);
		}catch(Exception e){
			this.urlExtension = "";
		}

		this.comment = requestResponse.getComment();

		if(message!=null){
			this.listenerInterface=message.getListenerInterface();
			this.clientIP=message.getClientIpAddress().toString();
		}
		requestBodyOffset = tempAnalyzedReq.getBodyOffset();
		this.requestLength = requestResponse.getRequest().length - requestBodyOffset;
		this.hasBodyParam = requestLength > 0;
		this.params = this.url.getQuery() != null || this.hasBodyParam;
		this.hasCookieParam = false;

		// reading request headers like a boss!
		for(String item:lstFullRequestHeader){
			if(item.indexOf(":")>=0){
				String[] headerItem = item.split(":\\s",2);
				headerItem[0] = headerItem[0].toLowerCase();
				if(headerItem[0].equals("cookie")){
					this.sentCookies = headerItem[1];
					if(!this.sentCookies.isEmpty()){
						this.hasCookieParam = true;
						this.sentCookies += ";"; // we need to ad this to search it in cookie Jar!

						// Check to see if it uses cookie Jars!
						List<ICookie> cookieJars = LoggerPlusPlus.callbacks.getCookieJarContents();
						boolean oneNotMatched = false;
						boolean anyParamMatched = false;

						for(ICookie cookieItem : cookieJars){
							if(cookieItem.getDomain().equals(this.host)){
								// now we want to see if any of these cookies have been set here!
								String currentCookieJarParam = cookieItem.getName()+"="+cookieItem.getValue()+";";
								if(this.sentCookies.contains(currentCookieJarParam)){
									anyParamMatched = true;
								}else{
									oneNotMatched = true;
								}
							}
							if(anyParamMatched && oneNotMatched){
								break; // we do not need to analyse it more!
							}
						}
						if(oneNotMatched && anyParamMatched){
							this.usesCookieJar=cookieJarStatus.PARTIALLY;
						}else if(!oneNotMatched && anyParamMatched){
							this.usesCookieJar=cookieJarStatus.YES;
						}
					}
				}else if(headerItem[0].equals("referer")){
					this.referrerURL = headerItem[1];
				}else if(headerItem[0].equals("content-type")){
					this.requestContentType = headerItem[1];
				}
			}
		}

		// RegEx processing for requests - should be available only when we have a RegEx rule!
		// There are 5 RegEx rule for requests
//		LogTableColumn.ColumnIdentifier[] regexReqColumns = new LogTableColumn.ColumnIdentifier[]{
//				REGEX1REQ, REGEX2REQ, REGEX3REQ, REGEX4REQ, REGEX5REQ
//		};
//
//		for (LogTableColumn.ColumnIdentifier regexReqColumn : regexReqColumns) {
//			int columnIndex = logTable.getColumnModel().getColumnIndex(regexReqColumn);
//			if(columnIndex == -1){
//				continue;
//			}
//			LogTableColumn column = (LogTableColumn) logTable.getColumnModel().getColumn(columnIndex);
//			String regexString = regexColumn.getRegExData().getRegExString();
//			if(!regexString.isEmpty()){
//				// now we can process it safely!
//				Pattern p = null;
//				try{
//					if(regexColumn.getRegExData().isRegExCaseSensitive())
//						p = Pattern.compile(regexString);
//					else
//						p = Pattern.compile(regexString, Pattern.CASE_INSENSITIVE);
//
//					Matcher m = p.matcher(strFullRequest);
//					StringBuilder allMatches = new StringBuilder();
//					int counter = 1;
//					while (m.find()) {
//						if(counter==2){
//							allMatches.insert(0, "�");
//							allMatches.append("�");
//						}
//						if(counter > 1){
//							allMatches.append("�"+m.group()+"�");
//						}else{
//							allMatches.append(m.group());
//						}
//						counter++;
//
//					}
//
//					//TODO Fix storage of regex result
////					this.regexAllReq[i] = allMatches.toString();
//
//				}catch(Exception e){
//					LoggerPlusPlus.callbacks.printError("Error in regular expression: " + regexString);
//				}
//
//			}
//		}

		this.requestProcessed = true;
	}

	public void processResponse(IHttpRequestResponse requestResponse) {
		if(this.responseDateTime == null){
			this.responseDateTime = new Date();
		}
		if(!isImported) {
			this.responseTime = LogManager.sdf.format(responseDateTime);
			this.requestResponseDelay = (int) (responseDateTime.getTime() - requestDateTime.getTime());
			this.requestDateTime = null; //Save a bit of ram!
			this.responseDateTime = null; //Here too!
		}

		//Finalise request,response by saving to temp file and clearing from memory.
		if (requestResponse instanceof IHttpRequestResponsePersisted){
			this.requestResponse = requestResponse;
		}else {
			this.requestResponse = LoggerPlusPlus.callbacks.saveBuffersToTempFiles(requestResponse);
		}

		IResponseInfo tempAnalyzedResp = LoggerPlusPlus.callbacks.getHelpers().analyzeResponse(requestResponse.getResponse());
		String strFullResponse = new String(requestResponse.getResponse());
		this.responseBodyOffset = tempAnalyzedResp.getBodyOffset();
		this.responseLength= requestResponse.getResponse().length - responseBodyOffset;

		LogTable logTable = LoggerPlusPlus.instance.getLogTable();
		List<String> lstFullResponseHeader = tempAnalyzedResp.getHeaders();
		responseHeaders =  StringUtils.join(lstFullResponseHeader, ", ");
		this.status= tempAnalyzedResp.getStatusCode();
		this.responseMimeType =tempAnalyzedResp.getStatedMimeType();
		this.responseInferredMimeType = tempAnalyzedResp.getInferredMimeType();
		for(ICookie cookieItem : tempAnalyzedResp.getCookies()){
			this.newCookies += cookieItem.getName()+"="+cookieItem.getValue()+"; ";
		}
		this.hasSetCookies = !newCookies.isEmpty();

		for(String item:lstFullResponseHeader){
			item = item.toLowerCase();
			if(item.startsWith("content-type: ")){
				String[] temp = item.split("content-type:\\s",2);
				if(temp.length>0)
					this.responseContentType = temp[1];
			}
		}

		this.comment = requestResponse.getComment();

		Pattern titlePattern = Pattern.compile("(?<=<title>)(.)+(?=</title>)");
		Matcher titleMatcher = titlePattern.matcher(strFullResponse);
		if(titleMatcher.find()){
			this.title = titleMatcher.group(1);
		}

		// RegEx processing for responses - should be available only when we have a RegEx rule!
		// There are 5 RegEx rule for requests
//		for(int i=0;i<5;i++){
//			String regexVarName = "regex"+(i+1)+"Resp";
//			if(logTable.getColumnModel().isColumnEnabled(regexVarName)){
//				// so this rule is enabled!
//				// check to see if the RegEx is not empty
//				LogTableColumn regexColumn = logTable.getColumnModel().getColumnByName(regexVarName);
//				String regexString = regexColumn.getRegExData().getRegExString();
//				if(!regexString.isEmpty()){
//					// now we can process it safely!
//					Pattern p = null;
//					try{
//						if(regexColumn.getRegExData().isRegExCaseSensitive())
//							p = Pattern.compile(regexString);
//						else
//							p = Pattern.compile(regexString, Pattern.CASE_INSENSITIVE);
//
//						Matcher m = p.matcher(strFullResponse);
//						StringBuilder allMatches = new StringBuilder();
//
//						int counter = 1;
//						while (m.find()) {
//							if(counter==2){
//								allMatches.insert(0, "�");
//								allMatches.append("�");
//							}
//							if(counter > 1){
//								allMatches.append("�"+m.group()+"�");
//							}else{
//								allMatches.append(m.group());
//							}
//							counter++;
//
//						}
//
//						this.regexAllResp[i] = allMatches.toString();
//
//					}catch(Exception e){
//						LoggerPlusPlus.callbacks.printError("Error in regular expression: " + regexString);
//					}
//
//				}
//			}
//		}

//		if(!logTable.getColumnModel().isColumnEnabled("response") && !logTable.getColumnModel().isColumnEnabled("request")){
//			this.requestResponse = null;
//		}

		this.responseProcessed = true;
		this.complete = true;
	}

	public void setReqestTime(Date requestTime){
		if(requestTime == null) return;
		this.requestDateTime = requestTime;
		this.requestTime = LogManager.sdf.format(this.requestDateTime);
	}

	public void setResponseTime(Date responseTime) {
		this.responseDateTime = responseTime;
	}

	public static String getCSVHeader(LogTable table, boolean isFullLog) {
		return getCSVHeader(table, isFullLog, isFullLog);
	}

	public static String getCSVHeader(LogTable table, boolean includeRequest, boolean includeResponse) {
		StringBuilder result = new StringBuilder();

		boolean firstDone = false;
		ArrayList<LogTableColumn> columns = new ArrayList<>();
		Enumeration<TableColumn> columnEnumeration = table.getColumnModel().getColumns();
		while(columnEnumeration.hasMoreElements()){
			columns.add((LogTableColumn) columnEnumeration.nextElement());
		}

		Collections.sort(columns);
		for (LogTableColumn logTableColumn : columns) {
			if(logTableColumn.isVisible()) {
				if(firstDone) {
					result.append(",");
				}else{
					firstDone = true;
				}
				result.append(logTableColumn.getName());
			}
		}			

		if(includeRequest) {
			result.append(",");
			result.append("Request");
		}
		if(includeResponse) {
			result.append(",");
			result.append("Response");
		}
		return result.toString();
	}

	// We need StringEscapeUtils library from http://commons.apache.org/proper/commons-lang/download_lang.cgi
	public String toCSVString(boolean isFullLog) {		
		return toCSVString(isFullLog, isFullLog);
	}

	private String sanitize(String string){
		if(string == null) return null;
		if(string.length() == 0) return "";
		char first = string.toCharArray()[0];
		switch (first){
			case '=':
			case '-':
			case '+':
			case '@': {
				return "'" + string;
			}
		}
		return string;
	}

	public String toCSVString(boolean includeRequests, boolean includeResponses) {
		StringBuilder result = new StringBuilder();

		LogTableColumnModel columnModel = LoggerPlusPlus.instance.getLogTable().getColumnModel();
		ArrayList<LogTableColumn> columns = new ArrayList<>();
		Enumeration<TableColumn> columnEnumeration = columnModel.getColumns();
		while(columnEnumeration.hasMoreElements()){
			columns.add((LogTableColumn) columnEnumeration.nextElement());
		}

		Collections.sort(columns);
		boolean firstDone = false;
		for (LogTableColumn logTableColumn : columns) {
			if(logTableColumn.isVisible()){
				if(firstDone){
					result.append(",");
				}else{
					firstDone = true;
				}
				result.append(StringEscapeUtils.escapeCsv(sanitize(
						getValueByKey(logTableColumn.getIdentifier()).toString())));
			}
		}

		if(includeRequests) {
			result.append(",");
			if (requestResponse != null && requestResponse.getRequest() != null)
				result.append(StringEscapeUtils.escapeCsv(sanitize(new String(requestResponse.getRequest()))));
		}
		if(includeResponses) {
			result.append(",");
			if(requestResponse != null && requestResponse.getResponse() != null)
				result.append(StringEscapeUtils.escapeCsv(sanitize(new String(requestResponse.getResponse()))));
		}
		return result.toString();
	}

	public Object getValueByKey(LogTableColumn.ColumnIdentifier columnName){

		try{
			switch(columnName)
			{
				case TOOL:
					return LoggerPlusPlus.callbacks.getToolName(tool);
				case URL:
					return this.url;
				case PATH:
					return this.relativeURL;
				case QUERY:
					return this.url.getQuery();
				case STATUS:
					return this.status;
				case PROTOCOL:
					return this.protocol;
				case HOSTNAME:
					return this.host;
				case HOST:
					return this.protocol+"://"+this.host;
				case MIMETYPE:
					return this.responseMimeType;
				case RESPONSELENGTH:
					return this.responseLength;
				case TARGETPORT:
					return this.targetPort;
				case METHOD:
					return this.method;
				case RESPONSETIME:
					return this.responseTime;
				case COMMENT:
					return this.comment;
				case REQUESTCONTENTTYPE:
					return this.requestContentType;
				case URLEXTENSION:
					return this.urlExtension;
				case REFERRER:
					return this.referrerURL;
				case HASQUERYSTRINGPARAM:
					return this.url.getQuery() != null;
				case HASBODYPARAM:
					return this.hasBodyParam;
				case HASCOOKIEPARAM:
					return this.hasCookieParam;
				case REQUESTLENGTH:
					return this.requestLength;
				case RESPONSECONTENTTYPE:
					return this.responseContentType;
				case INFERREDTYPE:
					return this.responseInferredMimeType;
				case HASSETCOOKIES:
					return this.hasSetCookies;
				case PARAMS:
					return this.params;
				case TITLE:
					return this.title;
				case ISSSL:
					return this.isSSL;
				case TARGETIP:
					return this.targetIP;
				case NEWCOOKIES:
					return this.newCookies;
				case LISTENERINTERFACE:
					return this.listenerInterface;
				case CLIENTIP:
					return this.clientIP;
				case COMPLETE:
					return this.complete;
				case SENTCOOKIES:
					return this.sentCookies;
				case USESCOOKIEJAR:
					return this.usesCookieJar.toString();
				case REGEX1REQ:
					return this.regexAllReq[0];
				case REGEX2REQ:
					return this.regexAllReq[1];
				case REGEX3REQ:
					return this.regexAllReq[2];
				case REGEX4REQ:
					return this.regexAllReq[3];
				case REGEX5REQ:
					return this.regexAllReq[4];
				case REGEX1RESP:
					return this.regexAllResp[0];
				case REGEX2RESP:
					return this.regexAllResp[1];
				case REGEX3RESP:
					return this.regexAllResp[2];
				case REGEX4RESP:
					return this.regexAllResp[3];
				case REGEX5RESP:
					return this.regexAllResp[4];
				case REQUEST: //request
					return new String(requestResponse.getRequest()).substring(requestResponse.getRequest().length - requestLength);
				case RESPONSE: //response
					return new String(requestResponse.getResponse()).substring(requestResponse.getResponse().length - responseLength);
				case REQUESTTIME: //requestTime
					return requestTime;
				case RTT:
					return requestResponseDelay;
				case REQUESTHEADERS:
					return requestHeaders != null ? requestHeaders : "";
				case RESPONSEHEADERS:
					return responseHeaders != null ? responseHeaders : "";
				default:
					return "";
			}
		}catch(Exception e){
			return "";
		}
	}

	public ArrayList<UUID> getMatchingColorFilters(){return matchingColorFilters;}

	public enum cookieJarStatus {
		YES("Yes"),
		NO("No"),
		PARTIALLY("Partially");
		private String value;
		cookieJarStatus(String value) {
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

	public synchronized boolean testColorFilter(ColorFilter colorFilter, boolean retest){
		if(!colorFilter.isEnabled() || colorFilter.getFilter() == null){
			return this.getMatchingColorFilters().remove(colorFilter.getUid());
		}
		if(!this.matchingColorFilters.contains(colorFilter.getUid())) {
			if (colorFilter.getFilter().matches(this)) {
				this.matchingColorFilters.add(colorFilter.getUid());
				return true;
			}else{
				return false;
			}
		}else if(retest){
			if (!colorFilter.getFilter().matches(this)) {
				this.matchingColorFilters.remove(colorFilter.getUid());
			}
			return true;
		}else{
			return false;
		}
	}

	@Override
	public String toString() {
		return super.toString();
		//return this.url.toString();
	}
}
