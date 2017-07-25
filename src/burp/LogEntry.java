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

import burp.filter.ColorFilter;
import org.apache.commons.lang3.StringEscapeUtils;

import javax.swing.*;
import java.net.URL;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

//
// class to hold details of each log entry
//

public class LogEntry extends RowFilter.Entry
{
	final IHttpRequestResponsePersisted requestResponse;
	String uniqueIdentifier="NA";
	final int tool;
	String host="";
	String method="";
	final URL url;
	String relativeURL="";
	boolean params=false;
	Short status=-1;
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
	String requestContentType = "";
	String protocol="";
	int targetPort=-1;
	int requestLength=-1;
	String clientIP="";
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

	ArrayList<UUID> matchingColorFilters;

	// Future Implementation
	//		final String requestTime; // I can get this only on request
	//		final String requestResponseDelay; // I can get this only on request
	//		final String requestUID; // I need something like this when I want to get the requests to match them with their responses

	// Defining necessary parameters from the caller
	private IExtensionHelpers helpers;

	LogEntry(int tool, boolean messageIsRequest, IHttpRequestResponsePersisted requestResponse, URL url, IRequestInfo tempAnalyzedReq, IInterceptedProxyMessage message)
	{
		this.matchingColorFilters = new ArrayList<UUID>();
		IHttpService tempRequestResponseHttpService = requestResponse.getHttpService();


		String strFullRequest = new String(requestResponse.getRequest());
		List<String> lstFullRequestHeader = tempAnalyzedReq.getHeaders();
		LogTable logTable = BurpExtender.getInstance().getLogTable();
		if(logTable.getModel().getTableHeaderColumnsDetails().isTableHeaderEnabled_byName("uniqueIdentifier")) // This is good to increase the speed when it is time consuming
			this.uniqueIdentifier=java.util.UUID.randomUUID().toString();

		this.tool = tool;
		this.requestResponse = requestResponse;

		this.url = url;
		if(logTable.getModel().getTableHeaderColumnsDetails().isTableHeaderEnabled_byName("url")) // This is good to increase the speed when it is time consuming
			this.relativeURL = url.getFile();
		this.host = tempRequestResponseHttpService.getHost();
		this.protocol = tempRequestResponseHttpService.getProtocol();
		this.isSSL= this.protocol.equals("https");

		if(logTable.getModel().getTableHeaderColumnsDetails().isTableHeaderEnabled_byName("targetPort")) // This is good to increase the speed when it is time consuming
			this.targetPort = tempRequestResponseHttpService.getPort();

		if(logTable.getModel().getTableHeaderColumnsDetails().isTableHeaderEnabled_byName("method")) // This is good to increase the speed when it is time consuming
			this.method = tempAnalyzedReq.getMethod();
		try{
			// I don't want to delete special characters such as ; or : from the extension as it may really be part of the extension! (burp proxy log ignores them)
			String tempPath = url.getPath().replaceAll("\\\\", "/");
			tempPath = tempPath.substring(tempPath.lastIndexOf("/"));
			int tempPathDotLocation = tempPath.lastIndexOf(".");
			if(tempPathDotLocation>=0)
				this.urlExtension = tempPath.substring(tempPathDotLocation+1);
		}catch(Exception e){
			if(BurpExtender.getInstance().isDebug())
				BurpExtender.getInstance().getStderr().println(e.getMessage());
			this.urlExtension = "";
		}

		if(message!=null){
			if(logTable.getModel().getTableHeaderColumnsDetails().isTableHeaderEnabled_byName("listenerInterface")) // This is good to increase the speed when it is time consuming
				this.listenerInterface=message.getListenerInterface();

			if(logTable.getModel().getTableHeaderColumnsDetails().isTableHeaderEnabled_byName("clientIP")) // This is good to increase the speed when it is time consuming
				this.clientIP=message.getClientIpAddress().toString();

			if(logTable.getModel().getTableHeaderColumnsDetails().isTableHeaderEnabled_byName("uniqueIdentifier")) // This is good to increase the speed when it is time consuming
				this.uniqueIdentifier = "P"+String.valueOf(message.getMessageReference());


		}
		this.requestLength = strFullRequest.length() - tempAnalyzedReq.getBodyOffset();


		this.hasQueryStringParam = (url.getQuery()!=null) ? true : false;
		this.hasBodyParam = (requestLength>0) ? true : false;
		this.params = (this.hasQueryStringParam || this.hasBodyParam) ? true : false;
		this.hasCookieParam = false;

		// reading request headers like a boss!
		if(logTable.getModel().getTableHeaderColumnsDetails().isTableHeaderEnabled_byName("sentCookies") ||
				logTable.getModel().getTableHeaderColumnsDetails().isTableHeaderEnabled_byName("hasCookieParam") ||
				logTable.getModel().getTableHeaderColumnsDetails().isTableHeaderEnabled_byName("usesCookieJar") ||
				logTable.getModel().getTableHeaderColumnsDetails().isTableHeaderEnabled_byName("referrerURL") ||
				logTable.getModel().getTableHeaderColumnsDetails().isTableHeaderEnabled_byName("requestContentType")){ // This is good to increase the speed when it is time consuming
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
							if(logTable.getModel().getTableHeaderColumnsDetails().isTableHeaderEnabled_byName("usesCookieJar")){
								// Check to see if it uses cookie Jars!
								List<ICookie> cookieJars = BurpExtender.getInstance().getCallbacks().getCookieJarContents();
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
						this.requestContentType = headerItem[1];
					}
				}
			}
		}

		// RegEx processing for requests - should be available only when we have a RegEx rule!
		// There are 5 RegEx rule for requests
		for(int i=0;i<=5;i++){
			String regexVarName = "regex"+String.valueOf(i+1)+"Req";
			if(logTable.getModel().getTableHeaderColumnsDetails().isTableHeaderEnabled_byName(regexVarName)){
				// so this rule is enabled!
				// check to see if the RegEx is not empty
				TableStructure regexColumn = logTable.getModel().getTableHeaderColumnsDetails().getEnabledTableHeader_byName(regexVarName);
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
						BurpExtender.getInstance().getStderr().println("Error in regular expression: " + regexString);
					}

				}
			}
		}


		if(!messageIsRequest){
			IResponseInfo tempAnalyzedResp = helpers.analyzeResponse(requestResponse.getResponse());
			String strFullResponse = new String(requestResponse.getResponse());
			List<String> lstFullResponseHeader = tempAnalyzedResp.getHeaders();
			this.status= tempAnalyzedResp.getStatusCode();
			if(logTable.getModel().getTableHeaderColumnsDetails().isTableHeaderEnabled_byName("responseContentType_burp")) // This is good to increase the speed when it is time consuming
				this.responseContentType_burp=tempAnalyzedResp.getStatedMimeType();
			if(logTable.getModel().getTableHeaderColumnsDetails().isTableHeaderEnabled_byName("responseInferredContentType_burp")) // This is good to increase the speed when it is time consuming
				this.responseInferredContentType_burp = tempAnalyzedResp.getInferredMimeType();
			this.responseLength= strFullResponse.length() - tempAnalyzedResp.getBodyOffset();
			if(logTable.getModel().getTableHeaderColumnsDetails().isTableHeaderEnabled_byName("newCookies")) // This is good to increase the speed when it is time consuming
				for(ICookie cookieItem : tempAnalyzedResp.getCookies()){
					this.newCookies += cookieItem.getName()+"="+cookieItem.getValue()+"; ";
				}
			this.hasSetCookies = (!newCookies.isEmpty()) ? true : false;
			DateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
			Date date = new Date();
			this.responseTime= dateFormat.format(date);

			if(logTable.getModel().getTableHeaderColumnsDetails().isTableHeaderEnabled_byName("responseContentType")){ // This is good to increase the speed when it is time consuming
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
				if(logTable.getModel().getTableHeaderColumnsDetails().isTableHeaderEnabled_byName(regexVarName)){
					// so this rule is enabled!
					// check to see if the RegEx is not empty
					TableStructure regexColumn = logTable.getModel().getTableHeaderColumnsDetails().getEnabledTableHeader_byName(regexVarName);
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
							BurpExtender.getInstance().getStderr().println("Error in regular expression: " + regexString);
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
	public Object getModel() {
		return this;
	}

	@Override
	public int getValueCount() {
		return 42;
	}

	@Override
	public Object getValue(int i) {
		switch (i) {
			case 0://number
				return uniqueIdentifier;
			case 1://tool
				return tool;
			case 2://host
				return host;
			case 3://method
				return method;
			case 4: //url
				return url;
			case 5: //params
				return params;
			case 6: //status
				return status;
			case 7: //responseLength
				return responseLength;
			case 8: //responseContentType_burp
				return responseContentType_burp;
			case 9: //urlExtension
				return urlExtension;
			case 10: //comment
				return comment;
			case 11: //isSSL
				return isSSL;
			case 12: //newCookies
				return newCookies;
			case 13: //responseTime
				return responseTime;
			case 14: //listenerInterface
				return listenerInterface;
			case 15: //clientIP
				return clientIP;
			case 16: //responseContentType
				return responseContentType;
			case 17: //responseInferredContentType_burp
				return responseInferredContentType_burp;
			case 18: //hasQueryStringParam
				return hasQueryStringParam;
			case 19: //hasBodyParam
				return hasBodyParam;
			case 20: //hasCookieParam
				return hasCookieParam;
			case 21: //sentCookies
				return sentCookies;
			case 22: //usesCookieJar
				return usesCookieJar.toString();
			case 23: //protocol
				return protocol;
			case 24: //hostname
				return this.protocol + "://" + this.host;
			case 25: //targetPort
				return targetPort;
			case 26: //requestContentType
				return requestContentType;
			case 27: //referrerURL
				return referrerURL;
			case 28: //requestLength
				return requestLength;
			case 29: //hasSetCookies
				return hasSetCookies;
			case 30: //isCompleted
				return isCompleted;
			case 31: //uniqueIdentifier
				return uniqueIdentifier;
			case 32: //regex1Req
				return regexAllReq[0];
			case 33: //regex2Req
				return regexAllReq[1];
			case 34: //regex3Req
				return regexAllReq[2];
			case 35: //regex4Req
				return regexAllReq[3];
			case 36: //regex5Req
				return regexAllReq[4];
			case 37: //regex1Resp
				return regexAllResp[0];
			case 38: //regex2Resp
				return regexAllResp[1];
			case 39: //regex3Resp
				return regexAllResp[2];
			case 40: //regex4Resp
				return regexAllResp[3];
			case 41: //regex5Resp
				return regexAllResp[4];
			default:
				return null;
		}
	}

	@Override
	public Object getIdentifier() {
		return this.uniqueIdentifier;
	}


	public static String getCSVHeader(LogTableModel model, boolean isFullLog) {
		StringBuilder result = new StringBuilder();

		for (int i=1; i<model.getTableHeaderColumnsDetails().getVisibleColumnsDefinitionList().size(); i++) {
			result.append(model.getTableHeaderColumnsDetails().getVisibleColumnsDefinitionList().get(i).getVisibleName());
			if(i<model.getColumnCount()-1)
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

		LogTableModel logTableModel = BurpExtender.getInstance().getLogTable().getModel();
		for (int i = 1; i< logTableModel.getTableHeaderColumnsDetails().getVisibleColumnsDefinitionList().size(); i++) {

			result.append(StringEscapeUtils.escapeCsv(String.valueOf(getValueByName((String) logTableModel.getTableHeaderColumnsDetails().getVisibleColumnsDefinitionList().get(i).getName()))));

			if(i< logTableModel.getColumnCount()-1)
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

	public Object getValueByKey(columnNamesType columnName){

		// switch (name.toLowerCase()) // this works fine in Java v7
		try{
			switch(columnName)
			{
				case TOOL:
					return BurpExtender.getInstance().getCallbacks().getToolName(tool);
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
				case REQUESTCONTENTTYPE:
					return this.requestContentType;
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

	public Object getValueByName(String name){
		return getValueByKey(columnNamesType.valueOf(name.toUpperCase()));
	}

	public ArrayList<UUID> getMatchingColorFilters(){return matchingColorFilters;}

	public enum cookieJarStatus {
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
	public enum columnNamesType {
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
		REQUESTCONTENTTYPE("REQUESTCONTENTTYPE"),
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

	public boolean testColorFilter(ColorFilter colorFilter, boolean retest){
		if(!colorFilter.isEnabled() || colorFilter.getFilter() == null) return false;
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
}
