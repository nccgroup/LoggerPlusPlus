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

import java.io.PrintWriter;
import java.net.URL;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.lang3.StringEscapeUtils;

import burp.BurpExtender.TableHelper;

//
// class to hold details of each log entry
//

public class LogEntry
{
	// Request Related
	final int tool;
	final IHttpRequestResponsePersisted requestResponse;
	final URL url;
	String uniqueIdentifier="NA";
	String relativeURL="";
	String host="";
	boolean params=false;
	boolean hasQueryStringParam=false;
	boolean hasBodyParam=false;
	boolean hasCookieParam=false;
	String targetIP=""; // Burp Suite API does not give it to me!
	String title="";
	String newCookies="";
	String sentCookies="";
	String listenerInterface="";
	boolean isSSL=false;
	String urlExtension="";
	String referrerURL = "";
	String requstContentType = "";
	String protocol="";
	int targetPort=-1;
	int requestLength=-1;
	String method="";
	String clientIP="";
	// Response Related
	Short status=-1;
	boolean hasSetCookies=false;
	String responseTime="";
	String responseContentType_burp="";
	String responseInferredContentType_burp="";
	int responseLength=-1;
	String responseContentType="";
	boolean isCompleted = false; // Currently it is true unless I use requests too
	cookieJarStatus usesCookieJar = cookieJarStatus.NO;
	// User Related
	String comment="";
	// RegEx Variables
	String[] regexAllReq = {"","","","",""};
	String[] regexAllResp = {"","","","",""};


	// Future Implementation
	//		final String requestTime; // I can get this only on request
	//		final String requestResponseDelay; // I can get this only on request
	//		final String requestUID; // I need something like this when I want to get the requests to match them with their responses

	// Defining necessary parameters from the caller
	private LoggerPreferences loggerPreferences;
	private TableHelper tableHelper;
	private PrintWriter stdout, stderr;
	private boolean isDebug;
	private IBurpExtenderCallbacks callbacks;
	private IExtensionHelpers helpers;

	LogEntry(int tool, boolean messageIsRequest, IHttpRequestResponsePersisted requestResponse, URL url, IRequestInfo tempAnalyzedReq, IInterceptedProxyMessage message, TableHelper tableHelper, LoggerPreferences loggerPreferences, PrintWriter stdout, PrintWriter stderr, boolean isDebug, IBurpExtenderCallbacks callbacks)
	{
		this.stdout = stdout;
		this.stderr = stderr;
		this.isDebug = isDebug;
		this.loggerPreferences = loggerPreferences;
		this.callbacks = callbacks;
		this.tableHelper= tableHelper;
		this.callbacks = callbacks;
		this.helpers = callbacks.getHelpers();

		IHttpService tempRequestResponseHttpService = requestResponse.getHttpService();


		String strFullRequest = new String(requestResponse.getRequest());
		List<String> lstFullRequestHeader = tempAnalyzedReq.getHeaders();

		if(tableHelper.getTableHeaderColumnsDetails().isTableHeaderEnabled_byName("uniqueIdentifier")) // This is good to increase the speed when it is time consuming
			this.uniqueIdentifier=java.util.UUID.randomUUID().toString();

		this.tool = tool;
		this.requestResponse = requestResponse;

		this.url = url;
		if(tableHelper.getTableHeaderColumnsDetails().isTableHeaderEnabled_byName("url")) // This is good to increase the speed when it is time consuming
			this.relativeURL = url.getFile();
		this.host = tempRequestResponseHttpService.getHost();
		this.protocol = tempRequestResponseHttpService.getProtocol();
		this.isSSL=(this.protocol.equals("https"))? true: false;

		if(tableHelper.getTableHeaderColumnsDetails().isTableHeaderEnabled_byName("targetPort")) // This is good to increase the speed when it is time consuming
			this.targetPort = tempRequestResponseHttpService.getPort();

		if(tableHelper.getTableHeaderColumnsDetails().isTableHeaderEnabled_byName("method")) // This is good to increase the speed when it is time consuming
			this.method = tempAnalyzedReq.getMethod();
		try{
			// I don't want to delete special characters such as ; or : from the extension as it may really be part of the extension! (burp proxy log ignores them)
			String tempPath = url.getPath().replaceAll("\\\\", "/");
			tempPath = tempPath.substring(tempPath.lastIndexOf("/"));
			int tempPathDotLocation = tempPath.lastIndexOf(".");
			if(tempPathDotLocation>=0)
				this.urlExtension = tempPath.substring(tempPathDotLocation+1);
		}catch(Exception e){
			if(isDebug)
				stderr.println(e.getMessage());
			this.urlExtension = "";
		}

		if(message!=null){
			if(isDebug){
				//stdout.println("I have a message from proxy!");
			}
			if(tableHelper.getTableHeaderColumnsDetails().isTableHeaderEnabled_byName("listenerInterface")) // This is good to increase the speed when it is time consuming
				this.listenerInterface=message.getListenerInterface();

			if(tableHelper.getTableHeaderColumnsDetails().isTableHeaderEnabled_byName("clientIP")) // This is good to increase the speed when it is time consuming
				this.clientIP=message.getClientIpAddress().toString();

			if(tableHelper.getTableHeaderColumnsDetails().isTableHeaderEnabled_byName("uniqueIdentifier")) // This is good to increase the speed when it is time consuming
				this.uniqueIdentifier = "P"+String.valueOf(message.getMessageReference());


		}
		this.requestLength = strFullRequest.length() - tempAnalyzedReq.getBodyOffset();


		this.hasQueryStringParam = (url.getQuery()!=null) ? true : false;
		this.hasBodyParam = (requestLength>0) ? true : false;
		this.params = (this.hasQueryStringParam || this.hasBodyParam) ? true : false;
		this.hasCookieParam = false;

		// reading request headers like a boss!
		if(tableHelper.getTableHeaderColumnsDetails().isTableHeaderEnabled_byName("sentCookies") ||
				tableHelper.getTableHeaderColumnsDetails().isTableHeaderEnabled_byName("hasCookieParam") ||
				tableHelper.getTableHeaderColumnsDetails().isTableHeaderEnabled_byName("usesCookieJar") ||
				tableHelper.getTableHeaderColumnsDetails().isTableHeaderEnabled_byName("referrerURL") ||
				tableHelper.getTableHeaderColumnsDetails().isTableHeaderEnabled_byName("requstContentType")){ // This is good to increase the speed when it is time consuming
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
							if(tableHelper.getTableHeaderColumnsDetails().isTableHeaderEnabled_byName("usesCookieJar")){
								// Check to see if it uses cookie Jars!
								List<ICookie> cookieJars = callbacks.getCookieJarContents();
								boolean atLeastOneDidNotMatched = false;
								boolean anyParamMatched = false;

								for(ICookie cookieItem : cookieJars){
									if(cookieItem.getDomain().equals(this.host)){
										// now we want to see if any of these cookies have been set here!
										String currentCookieJarParam = cookieItem.getName()+"="+cookieItem.getValue()+";";
										if(this.sentCookies.contains(currentCookieJarParam)){
											anyParamMatched = true;
										}else{
											atLeastOneDidNotMatched = true;
										}
									}
									if(anyParamMatched && atLeastOneDidNotMatched){
										break; // we do not need to analyse it more!
									}
								}
								if(atLeastOneDidNotMatched && anyParamMatched){
									this.usesCookieJar=cookieJarStatus.PARTIALLY;
								}else if(!atLeastOneDidNotMatched && anyParamMatched){
									this.usesCookieJar=cookieJarStatus.YES;
								}
							}
						}
					}else if(headerItem[0].equals("referer")){
						this.referrerURL = headerItem[1];
					}else if(headerItem[0].equals("content-type")){
						this.requstContentType = headerItem[1];
					}
				}
			}
		}

		// RegEx processing for requests - should be available only when we have a RegEx rule!
		// There are 5 RegEx rule for requests
		for(int i=0;i<=5;i++){
			String regexVarName = "regex"+String.valueOf(i+1)+"Req";
			if(tableHelper.getTableHeaderColumnsDetails().isTableHeaderEnabled_byName(regexVarName)){
				// so this rule is enabled!
				// check to see if the RegEx is not empty
				TableStructure regexColumn = tableHelper.getTableHeaderColumnsDetails().getEnabledTableHeader_byName(regexVarName);
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
						stderr.println("Error in regular expression: " + regexString);
					}

				}
			}
		}


		if(!messageIsRequest){
			IResponseInfo tempAnalyzedResp = helpers.analyzeResponse(requestResponse.getResponse());
			String strFullResponse = new String(requestResponse.getResponse());
			List<String> lstFullResponseHeader = tempAnalyzedResp.getHeaders();
			this.status= tempAnalyzedResp.getStatusCode();
			if(tableHelper.getTableHeaderColumnsDetails().isTableHeaderEnabled_byName("responseContentType_burp")) // This is good to increase the speed when it is time consuming
				this.responseContentType_burp=tempAnalyzedResp.getStatedMimeType();
			if(tableHelper.getTableHeaderColumnsDetails().isTableHeaderEnabled_byName("responseInferredContentType_burp")) // This is good to increase the speed when it is time consuming
				this.responseInferredContentType_burp = tempAnalyzedResp.getInferredMimeType();
			this.responseLength= strFullResponse.length() - tempAnalyzedResp.getBodyOffset();
			if(tableHelper.getTableHeaderColumnsDetails().isTableHeaderEnabled_byName("newCookies")) // This is good to increase the speed when it is time consuming
				for(ICookie cookieItem : tempAnalyzedResp.getCookies()){
					this.newCookies += cookieItem.getName()+"="+cookieItem.getValue()+"; ";
				}
			this.hasSetCookies = (!newCookies.isEmpty()) ? true : false;
			DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
			Date date = new Date();
			this.responseTime= dateFormat.format(date);

			if(tableHelper.getTableHeaderColumnsDetails().isTableHeaderEnabled_byName("responseContentType")){ // This is good to increase the speed when it is time consuming
				for(String item:lstFullResponseHeader){
					item = item.toLowerCase();
					if(item.startsWith("content-type: ")){
						String[] temp = item.split("content-type:\\s",2);
						if(temp.length>0)
							this.responseContentType = temp[1];
					}
				}
			}

			// RegEx processing for responses - should be available only when we have a RegEx rule!
			// There are 5 RegEx rule for requests
			for(int i=0;i<=5;i++){
				String regexVarName = "regex"+String.valueOf(i+1)+"Resp";
				if(tableHelper.getTableHeaderColumnsDetails().isTableHeaderEnabled_byName(regexVarName)){
					// so this rule is enabled!
					// check to see if the RegEx is not empty
					TableStructure regexColumn = tableHelper.getTableHeaderColumnsDetails().getEnabledTableHeader_byName(regexVarName);
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
							stderr.println("Error in regular expression: " + regexString);
						}

					}
				}
			}
			this.isCompleted = true;
			tempAnalyzedResp = null;
		}

		this.comment = "";

		tempRequestResponseHttpService = null;

		tempAnalyzedReq = null;

	}

	@Override 
	public boolean equals(Object other) {
		boolean result = false;
		if (other instanceof LogEntry) {
			LogEntry that = (LogEntry) other;
			result = (this.uniqueIdentifier.equals(that.uniqueIdentifier));
			if(isDebug){
				stderr.println("this.uniqueIdentifier: " + this.uniqueIdentifier + " that.uniqueIdentifier: "+that.uniqueIdentifier + " result: "+result);
			}

		}
		return result;
	}

	public String getCSVHeader(boolean isFullLog) {
		StringBuilder result = new StringBuilder();
		//			for (int i=1; i<loggerTableDetails.length; i++) {
		//				result.append(loggerTableDetails[i][1]);
		//				if(i<tableHelper.getLogTableModel().getColumnCount()-1)
		//					result.append(",");
		//			}

		for (int i=1; i<tableHelper.getTableHeaderColumnsDetails().getVisibleColumnsDefinitionList().size(); i++) {
			result.append(tableHelper.getTableHeaderColumnsDetails().getVisibleColumnsDefinitionList().get(i).getVisibleName());
			if(i<tableHelper.getLogTableModel().getColumnCount()-1)
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
		//			for (int i=1; i<loggerTableDetails.length; i++) {
		//
		//				result.append(StringEscapeUtils.escapeCsv(String.valueOf(getValueByName((String) loggerTableDetails[i][0]))));
		//
		//				if(i<tableHelper.getLogTableModel().getColumnCount()-1)
		//					result.append(",");
		//			}

		for (int i=1; i<tableHelper.getTableHeaderColumnsDetails().getVisibleColumnsDefinitionList().size(); i++) {

			result.append(StringEscapeUtils.escapeCsv(String.valueOf(getValueByName((String) tableHelper.getTableHeaderColumnsDetails().getVisibleColumnsDefinitionList().get(i).getName()))));

			if(i<tableHelper.getLogTableModel().getColumnCount()-1)
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
		if(isDebug){
			//stdout.println(name);
		}

		// switch (name.toLowerCase()) // this works fine in Java v7
		try{
			switch(columnNamesType.valueOf(name.toUpperCase()))
			{
			case TOOL:
				return callbacks.getToolName(tool);
			case URL:
				return this.relativeURL;
			case STATUS:
				return this.status;
			case PROTOCOL:
				return this.protocol;
			case HOSTNAME:
				return this.host;
			case HOST:
				return this.protocol+"://"+this.host;
			case RESPONSECONTENTTYPE_BURP:
				return this.responseContentType_burp;
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
			case REQUSTCONTENTTYPE:
				return this.requstContentType;
			case URLEXTENSION:
				return this.urlExtension;
			case REFERRERURL:
				return this.referrerURL;
			case HASQUERYSTRINGPARAM:
				return this.hasQueryStringParam;
			case HASBODYPARAM:
				return this.hasBodyParam;
			case HASCOOKIEPARAM:
				return this.hasCookieParam;
			case REQUESTLENGTH:
				return this.requestLength;
			case RESPONSECONTENTTYPE:
				return this.responseContentType;
			case RESPONSEINFERREDCONTENTTYPE_BURP:
				return this.responseInferredContentType_burp;
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
			case ISCOMPLETED:
				return this.isCompleted;
			case UNIQUEIDENTIFIER:
				return this.uniqueIdentifier;
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
			default:
				return "";
			}
		}catch(Exception e){
			return "";
		}
	}

	private enum cookieJarStatus {
		YES("Yes"),
		NO("No"),
		PARTIALLY("Partially");
		private String value;
		private cookieJarStatus(String value) {
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
	private enum columnNamesType {
		TOOL("TOOL"),
		URL("URL"),
		STATUS("STATUS"),
		PROTOCOL("PROTOCOL"),
		HOSTNAME("HOSTNAME"),
		HOST("HOST"),
		RESPONSECONTENTTYPE_BURP("RESPONSECONTENTTYPE_BURP"),
		RESPONSELENGTH("RESPONSELENGTH"),
		TARGETPORT("TARGETPORT"),
		METHOD("METHOD"),
		RESPONSETIME("RESPONSETIME"),
		COMMENT("COMMENT"),
		REQUSTCONTENTTYPE("REQUSTCONTENTTYPE"),
		URLEXTENSION("URLEXTENSION"),
		REFERRERURL("REFERRERURL"),
		HASQUERYSTRINGPARAM("HASQUERYSTRINGPARAM"),
		HASBODYPARAM("HASBODYPARAM"),
		HASCOOKIEPARAM("HASCOOKIEPARAM"),
		REQUESTLENGTH("REQUESTLENGTH"),
		RESPONSECONTENTTYPE("RESPONSECONTENTTYPE"),
		RESPONSEINFERREDCONTENTTYPE_BURP("RESPONSEINFERREDCONTENTTYPE_BURP"),
		HASSETCOOKIES("HASSETCOOKIES"),
		PARAMS("PARAMS"),
		TITLE("TITLE"),
		ISSSL("ISSSL"),
		TARGETIP("TARGETIP"),
		NEWCOOKIES("NEWCOOKIES"),
		LISTENERINTERFACE("LISTENERINTERFACE"),
		CLIENTIP("CLIENTIP"),
		ISCOMPLETED("ISCOMPLETED"),
		UNIQUEIDENTIFIER("UNIQUEIDENTIFIER"),
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
		REGEX5RESP("REGEX5RESP");
		private String value;
		private columnNamesType(String value) {
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
}
