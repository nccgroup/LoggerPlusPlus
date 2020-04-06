//
// Burp Suite Logger++
// 
// Released as open source by NCC Group Plc - https://www.nccgroup.trust/
// 
// Originally Developed by Soroush Dalili (@irsdl)
// Maintained by Corey Arthur (@CoreyD97)
//
// Project link: http://www.github.com/nccgroup/BurpSuiteLoggerPlusPlus
//
// Released under AGPL see LICENSE for more information
//

package com.nccgroup.loggerplusplus.logentry;

import burp.*;
import com.nccgroup.loggerplusplus.util.Globals;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.filter.colorfilter.ColorFilter;
import com.nccgroup.loggerplusplus.logview.logtable.LogTable;
import com.nccgroup.loggerplusplus.logview.logtable.LogTableColumn;
import com.nccgroup.loggerplusplus.logview.logtable.LogTableColumnModel;
import org.apache.commons.text.StringEscapeUtils;
import org.apache.commons.lang3.StringUtils;

import javax.swing.table.TableColumn;
import java.net.URL;
import java.text.ParseException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.stream.Collectors;

public class LogEntry
{
	enum Status {UNPROCESSED, AWAITING_RESPONSE, PROCESSED, IGNORED}
	Status previousStatus;
	Status status = Status.UNPROCESSED;
	public transient IHttpRequestResponse requestResponse;

	public UUID identifier;
	public int tool;
	public String toolName;
	public String hostname ="";
	public String host = ""; //TODO better name?
	public String method="";
	public URL url;
	public boolean params=false;
	public Short responseStatus =-1;
	public boolean hasBodyParam=false;
	public boolean hasCookieParam=false;
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
	public String formattedResponseTime ="";
	public String responseMimeType ="";
	public String responseInferredMimeType ="";
	public int responseLength=-1;
	public String responseContentType="";
	public boolean complete = false;
	public CookieJarStatus usesCookieJar = CookieJarStatus.NO;
	public String comment="";
//	public String[] regexAllReq = {"","","","",""};
//	public String[] regexAllResp = {"","","","",""};

	public List<UUID> matchingColorFilters;
	public int requestBodyOffset;
	public int responseBodyOffset;
	public String formattedRequestTime;
	public Date responseDateTime;
	public Date requestDateTime;
	public int requestResponseDelay = -1;
	public String responseHeaders;
	public String requestHeaders;

	private LogEntry(){
		this.identifier = UUID.randomUUID();
		this.matchingColorFilters = Collections.synchronizedList(new ArrayList<UUID>());
	}

	public LogEntry(int tool, IHttpRequestResponse requestResponse){
		this();
		this.tool = tool;
		this.toolName = LoggerPlusPlus.callbacks.getToolName(tool);
		this.requestResponse = requestResponse;
	}

	/**
	 * Create new entry and specify arrival time.
	 * @param tool
	 * @param formattedRequestTime
	 * @param requestResponse
	 */
	public LogEntry(int tool, Date formattedRequestTime, IHttpRequestResponse requestResponse){
		this(tool, requestResponse);
		this.setReqestTime(formattedRequestTime);
	}

	public void process(){
		previousStatus = this.status;
		switch (this.status){
			case UNPROCESSED: {
				this.status = processRequest();
				//If the entry should be ignored, break here.
				if(this.status == Status.IGNORED) break;

				//Else continue, fall through to process response
			}
			case AWAITING_RESPONSE: {
				if(this.requestResponse.getResponse() == null){
					this.status = Status.AWAITING_RESPONSE;
					break;
				}
				processResponse();
				this.status = Status.PROCESSED;
			}

			case IGNORED:
			case PROCESSED: {
				//Nothing to do, we're done!
				break;
			}
		}
	}

	public Status getStatus() {
		return status;
	}

	public Status getPreviousStatus() {
		return previousStatus;
	}

	private Status processRequest(){
		IRequestInfo tempAnalyzedReq = LoggerPlusPlus.callbacks.getHelpers().analyzeRequest(this.requestResponse);
		URL uUrl = tempAnalyzedReq.getUrl();
		if (!LoggerPlusPlus.isUrlInScope(uUrl)) return Status.IGNORED;

		IHttpService tempRequestResponseHttpService = requestResponse.getHttpService();
		List<String> lstFullRequestHeader = tempAnalyzedReq.getHeaders();
		requestHeaders = StringUtils.join(lstFullRequestHeader, ", ");

		this.url = tempAnalyzedReq.getUrl();
		this.hostname = tempRequestResponseHttpService.getHost();
		this.protocol = tempRequestResponseHttpService.getProtocol();
		this.isSSL= this.protocol.equals("https");
		this.targetPort = tempRequestResponseHttpService.getPort();

		boolean isDefaultPort = (this.protocol.equals("https") && this.targetPort == 443)
				|| (this.protocol.equals("http") && this.targetPort == 80);

		this.host = this.protocol+"://"+this.hostname+(isDefaultPort ? "" : this.targetPort);


		this.method = tempAnalyzedReq.getMethod();
		try{
			// I don't want to delete special characters such as ; or : from the extension as it may really be part of the extension! (burp proxy log ignores them)
			String tempPath = this.url.getPath().replaceAll("\\\\", "/");
			tempPath = tempPath.substring(tempPath.lastIndexOf("/"));
			int tempPathDotLocation = tempPath.lastIndexOf(".");
			if(tempPathDotLocation>=0)
				this.urlExtension = tempPath.substring(tempPathDotLocation+1);
		}catch(Exception e){
			this.urlExtension = "";
		}

		this.comment = requestResponse.getComment();
		this.requestBodyOffset = tempAnalyzedReq.getBodyOffset();
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
							if(cookieItem.getDomain().equals(this.hostname)){
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
							this.usesCookieJar= CookieJarStatus.PARTIALLY;
						}else if(!oneNotMatched && anyParamMatched){
							this.usesCookieJar= CookieJarStatus.YES;
						}
					}
				}else if(headerItem[0].equals("referer")){
					this.referrerURL = headerItem[1];
				}else if(headerItem[0].equals("content-type")){
					this.requestContentType = headerItem[1];
				}
			}
		}

		return Status.AWAITING_RESPONSE;

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
	}

	/**
	 * Update entry with response object and arrival time.
	 * @param requestResponse
	 * @param arrivalTime
	 */
	public void addResponse(IHttpRequestResponse requestResponse, Date arrivalTime){
		this.responseDateTime = arrivalTime;
		this.requestResponse = requestResponse;
	}

	private Status processResponse() {
		IResponseInfo tempAnalyzedResp = LoggerPlusPlus.callbacks.getHelpers().analyzeResponse(requestResponse.getResponse());
		String strFullResponse = new String(requestResponse.getResponse());
		this.responseBodyOffset = tempAnalyzedResp.getBodyOffset();
		this.responseLength= requestResponse.getResponse().length - responseBodyOffset;

		Map<String, List<String>> headers = tempAnalyzedResp.getHeaders().stream().filter(s -> s.contains(":")).collect(Collectors.toMap(
				s -> {
					String[] split = s.split(": ", 2);
					return split.length > 0 ? split[0] : "";
				},s -> {
					List<String> values = new ArrayList<>();
					String[] split = s.split(": ", 2);
					if(split.length > 1) {
						values.add(split[1]);
					}
					return values;
				}, (s, s2) -> {
					s.addAll(s2);
					return s;
				}, () -> new TreeMap<>(String.CASE_INSENSITIVE_ORDER)
		));

		responseHeaders =  tempAnalyzedResp.getHeaders().stream().collect(Collectors.joining(", "));
		this.responseStatus = tempAnalyzedResp.getStatusCode();
		this.responseMimeType =tempAnalyzedResp.getStatedMimeType();
		this.responseInferredMimeType = tempAnalyzedResp.getInferredMimeType();
		for(ICookie cookieItem : tempAnalyzedResp.getCookies()){
			this.newCookies += cookieItem.getName()+"="+cookieItem.getValue()+"; ";
		}
		this.hasSetCookies = !newCookies.isEmpty();

		if(headers.containsKey("content-type")){
			this.responseContentType = headers.get("content-type").get(0);
		}

		this.comment = requestResponse.getComment();

		Matcher titleMatcher = Globals.HTML_TITLE_PATTERN.matcher(strFullResponse);
		if(titleMatcher.find()){
			this.title = titleMatcher.group(1);
		}

		if(this.responseDateTime == null){
			//If it didn't have an arrival time set, parse the response for it.
			if(headers.get("date") != null && headers.get("date").size() > 0){
				try {
					synchronized (LogProcessor.SERVER_DATE_FORMAT) {
						this.responseDateTime = LogProcessor.SERVER_DATE_FORMAT.parse(headers.get("date").get(0));
					}
				} catch (ParseException e) {
					this.responseDateTime = null;
				}
			}else{
				//No date header...
				this.responseDateTime = null;
			}
		}
		if(responseDateTime != null) {
			this.formattedResponseTime = LogProcessor.LOGGER_DATE_FORMAT.format(responseDateTime);
		}else{
			this.formattedResponseTime = "";
		}

		if(requestDateTime != null && responseDateTime != null) {
			this.requestResponseDelay = (int) (responseDateTime.getTime() - requestDateTime.getTime());
		}

		this.complete = true;

		return Status.PROCESSED;

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
	}

	public IHttpRequestResponse getRequestResponse() {
		return requestResponse;
	}

	public UUID getIdentifier() {
		return this.identifier;
	}

	public void setReqestTime(Date requestTime){
		this.requestDateTime = requestTime;
		this.formattedRequestTime = LogProcessor.LOGGER_DATE_FORMAT.format(this.requestDateTime);
	}

	public void setResponseTime(Date responseTime) {
		this.responseDateTime = responseTime;
		this.formattedResponseTime = LogProcessor.LOGGER_DATE_FORMAT.format(this.responseDateTime);
	}

	public Object getValueByKey(LogEntryField columnName){

		try{
			switch(columnName)
			{
				case PROXY_TOOL:
				case REQUEST_TOOL:
					return toolName;
				case URL:
					return this.url;
				case PATH:
					return this.url.getPath();
				case QUERY:
					return this.url.getQuery();
				case STATUS:
					return this.responseStatus;
				case PROTOCOL:
					return this.protocol;
				case HOSTNAME:
					return this.hostname;
				case HOST:
					return this.host;
				case MIME_TYPE:
					return this.responseMimeType;
				case RESPONSE_LENGTH:
					return this.responseLength;
				case PORT:
					return this.targetPort;
				case METHOD:
					return this.method;
				case REQUEST_TIME:
					return this.requestDateTime;
				case RESPONSE_TIME:
					return this.responseDateTime;
				case COMMENT:
					return this.requestResponse.getComment();
				case REQUEST_CONTENT_TYPE:
					return this.requestContentType;
				case EXTENSION:
					return this.urlExtension;
				case REFERRER:
					return this.referrerURL;
				case HASGETPARAM:
					return this.url.getQuery() != null;
				case HASPOSTPARAM:
					return this.hasBodyParam;
				case HASCOOKIEPARAM:
					return this.hasCookieParam;
				case REQUEST_LENGTH:
					return this.requestLength;
				case RESPONSE_CONTENT_TYPE:
					return this.responseContentType;
				case INFERRED_TYPE:
					return this.responseInferredMimeType;
				case HAS_SET_COOKIES:
					return this.hasSetCookies;
				case HASPARAMS:
					return this.params;
				case TITLE:
					return this.title;
				case ISSSL:
					return this.isSSL;
				case NEW_COOKIES:
					return this.newCookies;
				case LISTENER_INTERFACE:
					return this.listenerInterface;
				case CLIENT_IP:
					return this.clientIP;
				case COMPLETE:
					return this.complete;
				case SENTCOOKIES:
					return this.sentCookies;
				case REQUEST_USES_COOKIE_JAR:
				case USES_COOKIE_JAR_PROXY:
					return this.usesCookieJar.toString();
//				case REGEX1REQ:
//					return this.regexAllReq[0];
//				case REGEX2REQ:
//					return this.regexAllReq[1];
//				case REGEX3REQ:
//					return this.regexAllReq[2];
//				case REGEX4REQ:
//					return this.regexAllReq[3];
//				case REGEX5REQ:
//					return this.regexAllReq[4];
//				case REGEX1RESP:
//					return this.regexAllResp[0];
//				case REGEX2RESP:
//					return this.regexAllResp[1];
//				case REGEX3RESP:
//					return this.regexAllResp[2];
//				case REGEX4RESP:
//					return this.regexAllResp[3];
//				case REGEX5RESP:
//					return this.regexAllResp[4];
				case REQUEST_BODY: //request
					return new String(requestResponse.getRequest()).substring(requestResponse.getRequest().length - requestLength);
				case RESPONSE_BODY: //response
					return new String(requestResponse.getResponse()).substring(requestResponse.getResponse().length - responseLength);
				case RTT:
					return requestResponseDelay;
				case REQUEST_HEADERS:
					return requestHeaders != null ? requestHeaders : "";
				case RESPONSE_HEADERS:
					return responseHeaders != null ? responseHeaders : "";
				default:
					return "";
			}
		}catch(Exception e){
			return "";
		}
	}

	public List<UUID> getMatchingColorFilters(){return matchingColorFilters;}

	public enum CookieJarStatus {
		YES("Yes"),
		NO("No"),
		PARTIALLY("Partially");
		private String value;
		CookieJarStatus(String value) {
			this.value = value;
		}
		@Override
		public String toString() {
			return this.value;
		}
	}

	/**
	 * TODO CLEAN UP
	 * @param colorFilter
	 * @param retest
	 * @return If the list of matching color filters was updated
	 */
	public boolean testColorFilter(ColorFilter colorFilter, boolean retest){
		if(!colorFilter.isEnabled() || colorFilter.getFilter() == null){
			return this.getMatchingColorFilters().remove(colorFilter.getUUID());
		}

		//If we don't already know if the color filter matches (e.g. haven't checked it before)
		if(!this.matchingColorFilters.contains(colorFilter.getUUID())) {
			if (colorFilter.getFilter().matches(this)) {
				this.matchingColorFilters.add(colorFilter.getUUID());
				return true;
			}else{
				return false;
			}
		}else if(retest){ //Or if we are forcing a retest (e.g. filter was updated)
			if (!colorFilter.getFilter().matches(this)) {
				this.matchingColorFilters.remove(colorFilter.getUUID());
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
}
