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
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.commons.lang3.StringUtils;

import javax.swing.*;
import java.net.URL;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

//
// class to hold details of each log entry
//
//TODO Better column to value mapping.
public class LogEntry extends RowFilter.Entry
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
	public String requestResponseDelay;
	public String responseHeaders;
	public String requestHeaders;

	// Defining necessary parameters from the caller

	public LogEntry()
	{
		this.uuid = UUID.randomUUID();
		this.matchingColorFilters = new ArrayList<UUID>();
		this.comment = "";
		this.requestTime = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss").format(new Date());
	}

	public LogEntry(boolean isImported){
		this();
		this.isImported = isImported;
		if(isImported) {
			this.requestTime = "NA";
			this.responseTime = "NA";
			this.requestResponseDelay = "NA";
		}
	}

	public void processRequest(int tool, IHttpRequestResponse requestResponse, URL url, IRequestInfo tempAnalyzedReq, IInterceptedProxyMessage message){
		IHttpService tempRequestResponseHttpService = requestResponse.getHttpService();
		String strFullRequest = new String(requestResponse.getRequest());
		List<String> lstFullRequestHeader = tempAnalyzedReq.getHeaders();
		requestHeaders = StringUtils.join(lstFullRequestHeader, ", ");
		LogTable logTable = LoggerPlusPlus.getInstance().getLogTable();

		this.tool = tool;
		this.requestResponse = requestResponse;

		this.url = url;
		if(logTable.getColumnModel().isColumnEnabled("path")) // This is good to increase the speed when it is time consuming
			this.relativeURL = url.getPath();
		this.host = tempRequestResponseHttpService.getHost();
		this.protocol = tempRequestResponseHttpService.getProtocol();
		this.isSSL= this.protocol.equals("https");

		if(logTable.getColumnModel().isColumnEnabled("targetPort")) // This is good to increase the speed when it is time consuming
			this.targetPort = tempRequestResponseHttpService.getPort();

		if(logTable.getColumnModel().isColumnEnabled("method")) // This is good to increase the speed when it is time consuming
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

		if(message!=null){
			if(logTable.getColumnModel().isColumnEnabled("listenerInterface")) // This is good to increase the speed when it is time consuming
				this.listenerInterface=message.getListenerInterface();

			if(logTable.getColumnModel().isColumnEnabled("clientIP")) // This is good to increase the speed when it is time consuming
				this.clientIP=message.getClientIpAddress().toString();
		}
		requestBodyOffset = tempAnalyzedReq.getBodyOffset();
		this.requestLength = requestResponse.getRequest().length - requestBodyOffset;
		this.hasBodyParam = requestLength > 0;
		this.params = this.url.getQuery() != null || this.hasBodyParam;
		this.hasCookieParam = false;

		// reading request headers like a boss!
		if(logTable.getColumnModel().isColumnEnabled("sentCookies") ||
				logTable.getColumnModel().isColumnEnabled("hasCookieParam") ||
				logTable.getColumnModel().isColumnEnabled("usesCookieJar") ||
				logTable.getColumnModel().isColumnEnabled("referrer") ||
				logTable.getColumnModel().isColumnEnabled("requestContentType")){ // This is good to increase the speed when it is time consuming
			for(String item:lstFullRequestHeader){
				if(item.indexOf(":")>=0){
					String[] headerItem = item.split(":\\s",2);
					headerItem[0] = headerItem[0].toLowerCase();
					if(headerItem[0].equals("cookie")){
						this.sentCookies = headerItem[1];
						if(!this.sentCookies.isEmpty()){
							this.hasCookieParam = true;
							this.sentCookies += ";"; // we need to ad this to search it in cookie Jar!

							// to ensure it is enabled as it is process consuming
							if(logTable.getColumnModel().isColumnEnabled("usesCookieJar")){
								// Check to see if it uses cookie Jars!
								List<ICookie> cookieJars = LoggerPlusPlus.getCallbacks().getCookieJarContents();
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
						}
					}else if(headerItem[0].equals("referer")){
						this.referrerURL = headerItem[1];
					}else if(headerItem[0].equals("content-type")){
						this.requestContentType = headerItem[1];
					}
				}
			}
		}

		// RegEx processing for requests - should be available only when we have a RegEx rule!
		// There are 5 RegEx rule for requests
		for(int i=1;i<5;i++){
			String regexVarName = "regex"+(i+1)+"Req";
			if(logTable.getColumnModel().isColumnEnabled(regexVarName)){
				// so this rule is enabled!
				// check to see if the RegEx is not empty
				LogTableColumn regexColumn = logTable.getColumnModel().getColumnByName(regexVarName);
				String regexString = regexColumn.getRegExData().getRegExString();
				if(!regexString.isEmpty()){
					// now we can process it safely!
					Pattern p = null;
					try{
						if(regexColumn.getRegExData().isRegExCaseSensitive())
							p = Pattern.compile(regexString);
						else
							p = Pattern.compile(regexString, Pattern.CASE_INSENSITIVE);

						Matcher m = p.matcher(strFullRequest);
						StringBuilder allMatches = new StringBuilder();
						int counter = 1;
						while (m.find()) {
							if(counter==2){
								allMatches.insert(0, "�");
								allMatches.append("�");
							}
							if(counter > 1){
								allMatches.append("�"+m.group()+"�");
							}else{
								allMatches.append(m.group());
							}
							counter++;

						}


						this.regexAllReq[i] = allMatches.toString();

					}catch(Exception e){
						LoggerPlusPlus.getCallbacks().printError("Error in regular expression: " + regexString);
					}

				}
			}
		}
	}

	public void processResponse(IHttpRequestResponse requestResponse) {
		if(!isImported) {
			SimpleDateFormat sdf = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
			Date responseDate = new Date();
			this.responseTime = sdf.format(responseDate);
			try {
				Date requestDate = sdf.parse(this.requestTime);
				this.requestResponseDelay = formatDelay(responseDate.getTime() - requestDate.getTime());
			} catch (ParseException e) {
			}
		}

		//Finalise request,response by saving to temp file and clearing from memory.
		if (requestResponse instanceof IHttpRequestResponsePersisted){
			this.requestResponse = requestResponse;
		}else {
			this.requestResponse = LoggerPlusPlus.getCallbacks().saveBuffersToTempFiles(requestResponse);
		}

		IResponseInfo tempAnalyzedResp = LoggerPlusPlus.getCallbacks().getHelpers().analyzeResponse(requestResponse.getResponse());
		String strFullResponse = new String(requestResponse.getResponse());
		this.responseBodyOffset = tempAnalyzedResp.getBodyOffset();
		this.responseLength= requestResponse.getResponse().length - responseBodyOffset;

		LogTable logTable = LoggerPlusPlus.getInstance().getLogTable();
		List<String> lstFullResponseHeader = tempAnalyzedResp.getHeaders();
		responseHeaders =  StringUtils.join(lstFullResponseHeader, ", ");
		this.status= tempAnalyzedResp.getStatusCode();
		if(logTable.getColumnModel().isColumnEnabled("MimeType")) // This is good to increase the speed when it is time consuming
			this.responseMimeType =tempAnalyzedResp.getStatedMimeType();
		if(logTable.getColumnModel().isColumnEnabled("InferredType")) // This is good to increase the speed when it is time consuming
			this.responseInferredMimeType = tempAnalyzedResp.getInferredMimeType();

		if(logTable.getColumnModel().isColumnEnabled("newCookies")) // This is good to increase the speed when it is time consuming
			for(ICookie cookieItem : tempAnalyzedResp.getCookies()){
				this.newCookies += cookieItem.getName()+"="+cookieItem.getValue()+"; ";
			}
		this.hasSetCookies = !newCookies.isEmpty();

		if(logTable.getColumnModel().isColumnEnabled("responseContentType")){ // This is good to increase the speed when it is time consuming
			for(String item:lstFullResponseHeader){
				item = item.toLowerCase();
				if(item.startsWith("content-type: ")){
					String[] temp = item.split("content-type:\\s",2);
					if(temp.length>0)
						this.responseContentType = temp[1];
				}
			}
		}

		Pattern titlePattern = Pattern.compile("(?<=<title>)(.)+(?=</title>)");
		Matcher titleMatcher = titlePattern.matcher(strFullResponse);
		if(titleMatcher.find()){
			this.title = titleMatcher.group(1);
		}

		// RegEx processing for responses - should be available only when we have a RegEx rule!
		// There are 5 RegEx rule for requests
		for(int i=0;i<5;i++){
			String regexVarName = "regex"+(i+1)+"Resp";
			if(logTable.getColumnModel().isColumnEnabled(regexVarName)){
				// so this rule is enabled!
				// check to see if the RegEx is not empty
				LogTableColumn regexColumn = logTable.getColumnModel().getColumnByName(regexVarName);
				String regexString = regexColumn.getRegExData().getRegExString();
				if(!regexString.isEmpty()){
					// now we can process it safely!
					Pattern p = null;
					try{
						if(regexColumn.getRegExData().isRegExCaseSensitive())
							p = Pattern.compile(regexString);
						else
							p = Pattern.compile(regexString, Pattern.CASE_INSENSITIVE);

						Matcher m = p.matcher(strFullResponse);
						StringBuilder allMatches = new StringBuilder();

						int counter = 1;
						while (m.find()) {
							if(counter==2){
								allMatches.insert(0, "�");
								allMatches.append("�");
							}
							if(counter > 1){
								allMatches.append("�"+m.group()+"�");
							}else{
								allMatches.append(m.group());
							}
							counter++;

						}

						this.regexAllResp[i] = allMatches.toString();

					}catch(Exception e){
						LoggerPlusPlus.getCallbacks().printError("Error in regular expression: " + regexString);
					}

				}
			}
		}
		if(!logTable.getColumnModel().isColumnEnabled("response") && !logTable.getColumnModel().isColumnEnabled("request")){
			this.requestResponse = null;
		}

		this.complete = true;
	}

	private String formatDelay(long l) {
		if(l < 1000)
			return String.format("%dms", l);
		if(l < 60000){
			return String.format("%ds %dms", TimeUnit.MILLISECONDS.toSeconds(l),
					l - TimeUnit.SECONDS.toMillis(TimeUnit.MILLISECONDS.toSeconds(l)));
		}else
			return String.format("%dmin %ds", TimeUnit.MILLISECONDS.toMinutes(l),
					TimeUnit.MILLISECONDS.toSeconds(l) - TimeUnit.MINUTES.toSeconds(TimeUnit.MILLISECONDS.toMinutes(l)));
	}

	@Override
	public Object getModel() {
		return null;
	}

	@Override
	public int getValueCount() {
		return 42;
	}

	@Override
	public Object getValue(int i) {
		switch (i) {
			case 0://number
				return 0;
			case 1://tool
				return LoggerPlusPlus.getCallbacks().getToolName(tool);
			case 2://host
				return this.protocol + "://" + this.host;
			case 3://method
				return method;
			case 4: //url
				return url;
			case 5: //path
				return this.relativeURL;
			case 6: //query
				return this.url != null ? (this.url.getQuery() == null ? "" : this.url.getQuery()) : "";
			case 7: //params
				return params;
			case 8: //status
				return status;
			case 9: //responseLength
				return responseLength;
			case 10: //responseMimeType
				return responseMimeType;
			case 11: //urlExtension
				return urlExtension;
			case 12: //comment
				return comment;
			case 13: //isSSL
				return isSSL;
			case 14: //newCookies
				return newCookies;
			case 15: //requestTime
				return requestTime;
			case 16: //listenerInterface
				return listenerInterface;
			case 17: //clientIP
				return clientIP;
			case 18: //responseContentType
				return responseContentType;
			case 19: //responseInferredMimeType
				return responseInferredMimeType;
			case 20: //hasQueryStringParam
				return this.url.getQuery() != null;
			case 21: //hasBodyParam
				return hasBodyParam;
			case 22: //hasCookieParam
				return hasCookieParam;
			case 23: //sentCookies
				return sentCookies;
			case 24: //usesCookieJar
				return usesCookieJar.toString();
			case 25: //protocol
				return protocol;
			case 26: //hostname
				return this.host;
			case 27: //targetPort
				return targetPort;
			case 28: //requestContentType
				return requestContentType;
			case 29: //referrerURL
				return referrerURL;
			case 30: //requestLength
				return requestLength;
			case 31: //hasSetCookies
				return hasSetCookies;
			case 32: //complete
				return complete;
			case 33: //regex1Req
				return regexAllReq[0];
			case 34: //regex2Req
				return regexAllReq[1];
			case 35: //regex3Req
				return regexAllReq[2];
			case 36: //regex4Req
				return regexAllReq[3];
			case 37: //regex5Req
				return regexAllReq[4];
			case 38: //regex1Resp
				return regexAllResp[0];
			case 39: //regex2Resp
				return regexAllResp[1];
			case 40: //regex3Resp
				return regexAllResp[2];
			case 41: //regex4Resp
				return regexAllResp[3];
			case 42: //regex5Resp
				return regexAllResp[4];
			case 43: //request
				return requestResponse != null && requestResponse.getRequest() != null ? new String(ArrayUtils.subarray(requestResponse.getRequest(), requestBodyOffset, requestResponse.getRequest().length)) : "";
			case 44: //response
				return requestResponse != null && requestResponse.getResponse() != null ? new String(ArrayUtils.subarray(requestResponse.getResponse(), responseBodyOffset, requestResponse.getResponse().length)) : "";
			case 45: //responseTime
				return responseTime != null ? responseTime : "";
			case 46: //requestResponseDelay
				return requestResponseDelay != null ? requestResponseDelay : "";
			case 47: //requestHeaders
				return requestHeaders != null ? requestHeaders : "";
			case 48: //requestHeaders
				return responseHeaders != null ? responseHeaders : "";
			default:
				return null;
		}
	}

	@Override
	public Object getIdentifier() {
		return null;
	}


	public static String getCSVHeader(LogTable table, boolean isFullLog) {
		StringBuilder result = new StringBuilder();

		short count = 0;
		ArrayList<LogTableColumn> columns = table.getColumnModel().getAllColumns();
		Collections.sort(columns);
		for (LogTableColumn logTableColumn : columns) {
			if(logTableColumn.isVisible() && logTableColumn.isEnabled()) {
				result.append(logTableColumn.getName());
				if(count < columns.size()-1)
					result.append(",");
			}
			count++;
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
		//			for (int i=1; i<loggerTableDetails.length; i++) {
		//
		//				result.append(StringEscapeUtils.escapeCsv(String.valueOf(getValueByName((String) loggerTableDetails[i][0]))));
		//
		//				if(i<tableHelper.getLogTableModel().getColumnCount()-1)
		//					result.append(",");
		//			}

		LogTableColumnModel columnModel = LoggerPlusPlus.getInstance().getLogTable().getColumnModel();
		ArrayList<LogTableColumn> columns = columnModel.getAllColumns();
		Collections.sort(columns);
		short count = 0;
		for (LogTableColumn logTableColumn : columns) {
			if(logTableColumn.isVisible() && logTableColumn.isEnabled()){
				result.append(StringEscapeUtils.escapeCsv(getValue(logTableColumn.getIdentifier()).toString()));
				if (count < columnModel.getColumnCount() - 1)
					result.append(",");
			}
			count++;
		}

		if(isFullLog){
			result.append(",");
			if(requestResponse != null && requestResponse.getRequest() != null)
				result.append(StringEscapeUtils.escapeCsv(new String(requestResponse.getRequest())));
			result.append(",");
			if(requestResponse != null && requestResponse.getResponse() != null)
				result.append(StringEscapeUtils.escapeCsv(new String(requestResponse.getResponse())));
		}
		return result.toString();
	}

	public Object getValueByKey(columnNamesType columnName){

		// switch (name.toLowerCase()) // this works fine in Java v7
		try{
			switch(columnName)
			{
				case TOOL:
					return LoggerPlusPlus.getCallbacks().getToolName(tool);
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
				case RESPONSEDELAY:
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

	// This has been designed for Java v6 that cannot support String in "switch"
	public enum columnNamesType {
		TOOL("TOOL"),
		URL("URL"),
		PATH("PATH"),
		QUERY("QUERY"),
		STATUS("STATUS"),
		PROTOCOL("PROTOCOL"),
		HOSTNAME("HOSTNAME"),
		HOST("HOST"),
		MIMETYPE("MIMETYPE"),
		RESPONSELENGTH("RESPONSELENGTH"),
		TARGETPORT("TARGETPORT"),
		METHOD("METHOD"),
		RESPONSETIME("RESPONSETIME"),
		REQUESTTIME("REQUESTTIME"),
		RESPONSEDELAY("RESPONSEDELAY"),
		COMMENT("COMMENT"),
		REQUESTCONTENTTYPE("REQUESTCONTENTTYPE"),
		URLEXTENSION("URLEXTENSION"),
		REFERRER("REFERRER"),
		HASQUERYSTRINGPARAM("HASQUERYSTRINGPARAM"),
		HASBODYPARAM("HASBODYPARAM"),
		HASCOOKIEPARAM("HASCOOKIEPARAM"),
		REQUESTLENGTH("REQUESTLENGTH"),
		RESPONSECONTENTTYPE("RESPONSECONTENTTYPE"),
		INFERREDTYPE("INFERREDTYPE"),
		HASSETCOOKIES("HASSETCOOKIES"),
		PARAMS("PARAMS"),
		TITLE("TITLE"),
		ISSSL("ISSSL"),
		TARGETIP("TARGETIP"),
		NEWCOOKIES("NEWCOOKIES"),
		LISTENERINTERFACE("LISTENERINTERFACE"),
		CLIENTIP("CLIENTIP"),
		COMPLETE("COMPLETE"),
		SENTCOOKIES("SENTCOOKIES"),
		USESCOOKIEJAR("USESCOOKIEJAR"),
		REGEX1REQ("REGEX1REQ"),
		REGEX2REQ("REGEX2REQ"),
		REGEX3REQ("REGEX3REQ"),
		REGEX4REQ("REGEX4REQ"),
		REGEX5REQ("REGEX5REQ"),
		REGEX1RESP("REGEX1RESP"),
		REGEX2RESP("REGEX2RESP"),
		REGEX3RESP("REGEX3RESP"),
		REGEX4RESP("REGEX4RESP"),
		REGEX5RESP("REGEX5RESP"),
		REQUEST("REQUEST"),
		RESPONSE("RESPONSE"),
		REQUESTHEADERS("REQUESTHEADERS"),
		RESPONSEHEADERS("RESPONSEHEADERS");
		private String value;
		columnNamesType(String value) {
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
		return this.url.toString();
	}

	public static class PendingRequestEntry extends LogEntry {
		private int logRow;
		public PendingRequestEntry() {
			super();
		}

		public int getLogRow() {
			return logRow;
		}

		public void setLogRow(int logRow) {
			this.logRow = logRow;
		}
	}
}
