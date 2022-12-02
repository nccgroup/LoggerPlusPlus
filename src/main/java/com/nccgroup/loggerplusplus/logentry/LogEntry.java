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
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.filter.colorfilter.ColorFilter;
import com.nccgroup.loggerplusplus.filter.tag.Tag;
import com.nccgroup.loggerplusplus.logview.processor.LogProcessor;
import com.nccgroup.loggerplusplus.logview.processor.LogProcessorHelper;
import com.nccgroup.loggerplusplus.reflection.ReflectionController;
import com.nccgroup.loggerplusplus.util.Globals;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;

import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.stream.Collectors;

@Getter
@Setter
public class LogEntry {

	Status previousStatus;
	Status status = Status.UNPROCESSED;

	@Getter(AccessLevel.NONE)
	@Setter(AccessLevel.NONE)
	private IHttpRequestResponse requestResponse; //Only used for request, comment and HTTP Service.
	private byte[] response;

	private Integer identifier;
	private int tool;
	private String toolName;
	private String hostname = "";
	private String host = ""; // TODO better name?
	private String method = "";
	private URL url;
	private boolean params = false;
	private Short responseStatus = -1;
	private String responseStatusText = "";
	private String responseHttpVersion = "";
	private boolean hasBodyParam = false;
	private boolean hasCookieParam = false;
	private String title = "";
	private String newCookies = "";
	private String sentCookies = "";
	private String listenerInterface = "";
	private boolean isSSL = false;
	private String urlExtension = "";
	private String referrerURL = "";
	private String requestHttpVersion = "";
	private String requestContentType = "";
	private String protocol = "";
	private int targetPort = -1;
	private int requestBodyLength = -1;
	private String clientIP = "";
	private boolean hasSetCookies = false;
	private String formattedResponseTime = "";
	private String responseMimeType = "";
	private String responseInferredMimeType = "";
	private int responseBodyLength = -1;
	private String responseContentType = "";
	private boolean complete = false;
	private CookieJarStatus usesCookieJar = CookieJarStatus.NO;
	private String responseHash;
	private String redirectURL;
	private String origin = "";
	// private String[] regexAllReq = {"","","","",""};
	// private String[] regexAllResp = {"","","","",""};

	private List<UUID> matchingColorFilters;
	private List<Tag> matchingTags;
	private String formattedRequestTime;
	private Date responseDateTime = new Date(0); //Zero epoch dates to prevent null. Response date pulled from response headers
	private Date requestDateTime = new Date(0); //Zero epoch dates to prevent null. Response date pulled from response headers
	private int requestResponseDelay = -1;
	private List<String> responseHeaders;
	private List<String> requestHeaders;
	private List<IParameter> tempParameters;
	private List<String> parameters;
	private List<String> reflectedParameters;

	private LogEntry() {
		this.matchingColorFilters = Collections.synchronizedList(new ArrayList<UUID>());
		this.matchingTags = Collections.synchronizedList(new ArrayList<Tag>());
	}

	public LogEntry(int tool, IHttpRequestResponse requestResponse) {
		this();
		this.tool = tool;
		this.toolName = LoggerPlusPlus.callbacks.getToolName(tool);
		this.requestResponse = requestResponse;
		this.response = requestResponse.getResponse();
	}

	/**
	 * Create new entry and specify arrival time.
	 * 
	 * @param tool
	 * @param formattedRequestTime
	 * @param requestResponse
	 */
	public LogEntry(int tool, Date formattedRequestTime, IHttpRequestResponse requestResponse) {
		this(tool, requestResponse);
		this.setReqestTime(formattedRequestTime);
	}

	public void process() {
		// TODO Move into separate processing class
		previousStatus = this.status;
		switch (this.status) {
			case UNPROCESSED: {
				this.status = processRequest();
				// If the entry should be ignored, break here.
				if (this.status == Status.IGNORED)
					break;

				// Else continue, fall through to process response
			}
			case AWAITING_RESPONSE: {
				if (this.response == null) {
					this.status = Status.AWAITING_RESPONSE;
					break;
				}
				processResponse();
				this.status = Status.PROCESSED;
			}

			case IGNORED:
			case PROCESSED: {
				// Nothing to do, we're done!
				break;
			}
		}
	}

	public void reprocess() {
		this.status = Status.UNPROCESSED;
		process();
	}

	public Status getStatus() {
		return status;
	}

	public Status getPreviousStatus() {
		return previousStatus;
	}

	private Status processRequest() {
		IRequestInfo tempAnalyzedReq = LoggerPlusPlus.callbacks.getHelpers().analyzeRequest(this.requestResponse);
		URL uUrl = tempAnalyzedReq.getUrl();
		if (!LoggerPlusPlus.isUrlInScope(uUrl))
			return Status.IGNORED;

		requestHeaders = tempAnalyzedReq.getHeaders();

		// Get HTTP Version, which would be the last token in "GET /admin/login/?next\u003d/admin/ HTTP/1.1"
		String[] httpRequestTokens = requestHeaders.get(0).split(" ");
		this.requestHttpVersion = httpRequestTokens[httpRequestTokens.length - 1];

		this.tempParameters = tempAnalyzedReq.getParameters().stream()
				.filter(iParameter -> iParameter.getType() != IParameter.PARAM_COOKIE).collect(Collectors.toList());
		this.parameters = tempParameters.stream().map(IParameter::getName).collect(Collectors.toList());

		this.url = tempAnalyzedReq.getUrl();
		this.hostname = this.requestResponse.getHttpService().getHost();
		this.protocol = this.requestResponse.getHttpService().getProtocol();
		this.isSSL = this.protocol.equals("https");
		this.targetPort = this.requestResponse.getHttpService().getPort();

		boolean isDefaultPort = (this.protocol.equals("https") && this.targetPort == 443)
				|| (this.protocol.equals("http") && this.targetPort == 80);

		this.host = this.protocol + "://" + this.hostname + (isDefaultPort ? "" : ":" + this.targetPort);

		this.method = tempAnalyzedReq.getMethod();
		try {
			// I don't want to delete special characters such as ; or : from the extension
			// as it may really be part of the extension! (burp proxy log ignores them)
			String tempPath = this.url.getPath().replaceAll("\\\\", "/");
			tempPath = tempPath.substring(tempPath.lastIndexOf("/"));
			int tempPathDotLocation = tempPath.lastIndexOf(".");
			if (tempPathDotLocation >= 0)
				this.urlExtension = tempPath.substring(tempPathDotLocation + 1);
		} catch (Exception e) {
			this.urlExtension = "";
		}

		this.requestBodyLength = this.getRequest().length - tempAnalyzedReq.getBodyOffset();
		this.hasBodyParam = requestBodyLength > 0;
		this.params = this.url.getQuery() != null || this.hasBodyParam;
		this.hasCookieParam = false;

		// reading request headers like a boss!
		for (String item : requestHeaders) {
			if (item.contains(":")) {
				String[] headerItem = item.split(":\\s", 2);
				if (headerItem[0].equalsIgnoreCase("cookie")) {
					this.sentCookies = headerItem[1];
					if (!this.sentCookies.isEmpty()) {
						this.hasCookieParam = true;
						this.sentCookies += ";"; // we need to ad this to search it in cookie Jar!

						// Check to see if it uses cookie Jars!
						List<ICookie> cookieJars = LoggerPlusPlus.callbacks.getCookieJarContents();
						boolean oneNotMatched = false;
						boolean anyParamMatched = false;

						for (ICookie cookieItem : cookieJars) {
							if (cookieItem.getDomain().equals(this.hostname)) {
								// now we want to see if any of these cookies have been set here!
								String currentCookieJarParam = cookieItem.getName() + "=" + cookieItem.getValue() + ";";
								if (this.sentCookies.contains(currentCookieJarParam)) {
									anyParamMatched = true;
								} else {
									oneNotMatched = true;
								}
							}
							if (anyParamMatched && oneNotMatched) {
								break; // we do not need to analyse it more!
							}
						}
						if (oneNotMatched && anyParamMatched) {
							this.usesCookieJar = CookieJarStatus.PARTIALLY;
						} else if (!oneNotMatched && anyParamMatched) {
							this.usesCookieJar = CookieJarStatus.YES;
						}
					}
				} else if (headerItem[0].equalsIgnoreCase("referer")) {
					this.referrerURL = headerItem[1];
				} else if (headerItem[0].equalsIgnoreCase("content-type")) {
					this.requestContentType = headerItem[1];
				} else if (headerItem[0].equalsIgnoreCase("origin")) {
					this.origin = headerItem[1];
				}
			}
		}

		return Status.AWAITING_RESPONSE;

		// RegEx processing for requests - should be available only when we have a RegEx
		// rule!
		// There are 5 RegEx rule for requests
		// LogTableColumn.ColumnIdentifier[] regexReqColumns = new
		// LogTableColumn.ColumnIdentifier[]{
		// REGEX1REQ, REGEX2REQ, REGEX3REQ, REGEX4REQ, REGEX5REQ
		// };
		//
		// for (LogTableColumn.ColumnIdentifier regexReqColumn : regexReqColumns) {
		// int columnIndex = logTable.getColumnModel().getColumnIndex(regexReqColumn);
		// if(columnIndex == -1){
		// continue;
		// }
		// LogTableColumn column = (LogTableColumn)
		// logTable.getColumnModel().getColumn(columnIndex);
		// String regexString = regexColumn.getRegExData().getRegExString();
		// if(!regexString.isEmpty()){
		// // now we can process it safely!
		// Pattern p = null;
		// try{
		// if(regexColumn.getRegExData().isRegExCaseSensitive())
		// p = Pattern.compile(regexString);
		// else
		// p = Pattern.compile(regexString, Pattern.CASE_INSENSITIVE);
		//
		// Matcher m = p.matcher(strFullRequest);
		// StringBuilder allMatches = new StringBuilder();
		// int counter = 1;
		// while (m.find()) {
		// if(counter==2){
		// allMatches.insert(0, "X");
		// allMatches.append("X");
		// }
		// if(counter > 1){
		// allMatches.append("X"+m.group()+"X"); //TODO Investigate unicode use
		// }else{
		// allMatches.append(m.group());
		// }
		// counter++;
		//
		// }
		//
		// //TODO Fix storage of regex result
		//// this.regexAllReq[i] = allMatches.toString();
		//
		// }catch(Exception e){
		// LoggerPlusPlus.callbacks.printError("Error in regular expression: " +
		// regexString);
		// }
		//
		// }
		// }
	}

	/**
	 * Update entry with response object and arrival time.
	 * 
	 * @param requestResponse
	 * @param arrivalTime
	 */
	public void addResponse(IHttpRequestResponse requestResponse, Date arrivalTime) {
		this.responseDateTime = arrivalTime;

		//IHttpRequestResponse objects received by the proxy listener do not contain the latest request.
		//So we must store the content separately.
		this.response = requestResponse.getResponse();
		this.setComment(requestResponse.getComment()); //Update the comment with the current comment
	}

	private Status processResponse() {
		reflectedParameters = new ArrayList<>();
		IResponseInfo tempAnalyzedResp = LoggerPlusPlus.callbacks.getHelpers()
				.analyzeResponse(response);

		this.responseStatus = tempAnalyzedResp.getStatusCode();
		this.responseBodyLength = response.length - tempAnalyzedResp.getBodyOffset();
		this.responseMimeType = tempAnalyzedResp.getStatedMimeType();
		this.responseInferredMimeType = tempAnalyzedResp.getInferredMimeType();

		/**************************************
		 ************HEADER PROCESSING*********
		 **************************************/

		//Fancy handling to combine duplicate headers into CSVs.
		Map<String, String> headers = tempAnalyzedResp.getHeaders().stream().filter(s -> s.contains(":"))
				.collect(Collectors.toMap(s -> {
					String[] split = s.split(": ", 2);
					return split.length > 0 ? split[0] : "";
				}, s -> {
					String[] split = s.split(": ", 2);
					if (split.length > 1) {
						return split[1];
					}
					return "";
				}, (s, s2) -> {
					s += ", " + s2;
					return s;
				}, () -> new TreeMap<>(String.CASE_INSENSITIVE_ORDER)));

		responseHeaders = tempAnalyzedResp.getHeaders();

		if (headers.containsKey("Location")) {
			this.redirectURL = headers.get("Location");
		}

		// Extract HTTP Status message
		String[] httpStatusTokens = responseHeaders.get(0).split(" ");
		this.responseStatusText = httpStatusTokens[httpStatusTokens.length - 1];
		this.responseHttpVersion = httpStatusTokens[0];

		if (headers.containsKey("content-type")) {
			this.responseContentType = headers.get("content-type");
		}

		//Cookies
		for (ICookie cookieItem : tempAnalyzedResp.getCookies()) {
			this.newCookies += cookieItem.getName() + "=" + cookieItem.getValue() + "; "; //TODO convert to map, and add filter support for maps
		}
		this.hasSetCookies = !newCookies.isEmpty();


		if (this.responseDateTime == null) {
			// If it didn't have an arrival time set, parse the response for it.
			if (headers.get("date") != null && !StringUtils.isBlank(headers.get("date"))) {
				try {
					synchronized (LogProcessor.SERVER_DATE_FORMAT) {
						this.responseDateTime = LogProcessor.SERVER_DATE_FORMAT.parse(headers.get("date"));
					}
				} catch (ParseException e) {
					this.responseDateTime = null;
				}
			} else {
				// No date header...
				this.responseDateTime = null;
			}
		}
		if (responseDateTime != null) {
			this.formattedResponseTime = LogProcessor.LOGGER_DATE_FORMAT.format(responseDateTime);
		} else {
			this.formattedResponseTime = "";
		}

		if (requestDateTime != null && responseDateTime != null) {
			this.requestResponseDelay = (int) (responseDateTime.getTime() - requestDateTime.getTime());
		}

		/**************************************
		 *************BODY PROCESSING**********
		 **************************************/

		Long maxRespSize = ((Integer) LoggerPlusPlus.instance.getPreferencesController().getPreferences().getSetting(Globals.PREF_MAX_RESP_SIZE)) * 1000000L;
		int bodyOffset = response.length - responseBodyLength;
		if (responseBodyLength < maxRespSize) {
			//Only title match HTML files. Prevents expensive regex running on e.g. binary downloads.
			if (this.responseInferredMimeType.equalsIgnoreCase("HTML")) {
				String strFullResponse = new String(response);
				Matcher titleMatcher = Globals.HTML_TITLE_PATTERN.matcher(strFullResponse);
				if (titleMatcher.find()) {
					this.title = titleMatcher.group(1);
				}
			}

			String responseBody = new String(response, bodyOffset, responseBodyLength);
			ReflectionController reflectionController = LoggerPlusPlus.instance.getReflectionController();
			reflectedParameters = tempParameters.parallelStream()
					.filter(iParameter -> !reflectionController.isParameterFiltered(iParameter)
							&& reflectionController.validReflection(responseBody, iParameter))
					.map(IParameter::getName).collect(Collectors.toList());

//			this.requestResponse = LoggerPlusPlus.callbacks.saveBuffersToTempFiles(requestResponse);
		} else {
			//Just look for reflections in the headers.
			ReflectionController reflectionController = LoggerPlusPlus.instance.getReflectionController();
			reflectedParameters = tempParameters.parallelStream()
					.filter(iParameter -> !reflectionController.isParameterFiltered(iParameter)
							&& reflectionController.validReflection(new String(response, 0, bodyOffset), iParameter))
					.map(IParameter::getName).collect(Collectors.toList());

			//Trim the response down to a maximum size, but at least keep the headers!
			this.response = (new String(this.response, 0, bodyOffset) + "Response body trimmed by Logger++. To prevent this, increase \"Maximum Response Size\" in the Logger++ options.").getBytes(StandardCharsets.UTF_8);
		}


		tempParameters = null; // We're done with these. Allow them to be cleaned.

		this.complete = true;

		return Status.PROCESSED;

		// RegEx processing for responses - should be available only when we have a
		// RegEx rule!
		// There are 5 RegEx rule for requests
		// for(int i=0;i<5;i++){
		// String regexVarName = "regex"+(i+1)+"Resp";
		// if(logTable.getColumnModel().isColumnEnabled(regexVarName)){
		// // so this rule is enabled!
		// // check to see if the RegEx is not empty
		// LogTableColumn regexColumn =
		// logTable.getColumnModel().getColumnByName(regexVarName);
		// String regexString = regexColumn.getRegExData().getRegExString();
		// if(!regexString.isEmpty()){
		// // now we can process it safely!
		// Pattern p = null;
		// try{
		// if(regexColumn.getRegExData().isRegExCaseSensitive())
		// p = Pattern.compile(regexString);
		// else
		// p = Pattern.compile(regexString, Pattern.CASE_INSENSITIVE);
		//
		// Matcher m = p.matcher(strFullResponse);
		// StringBuilder allMatches = new StringBuilder();
		//
		// int counter = 1;
		// while (m.find()) {
		// if(counter==2){
		// allMatches.insert(0, "X");
		// allMatches.append("X");
		// }
		// if(counter > 1){
		// allMatches.append("X"+m.group()+"X"); //TODO investigate unicode use
		// }else{
		// allMatches.append(m.group());
		// }
		// counter++;
		//
		// }
		//
		// this.regexAllResp[i] = allMatches.toString();
		//
		// }catch(Exception e){
		// LoggerPlusPlus.callbacks.printError("Error in regular expression: " +
		// regexString);
		// }
		//
		// }
		// }
		// }

		// if(!logTable.getColumnModel().isColumnEnabled("response") &&
		// !logTable.getColumnModel().isColumnEnabled("request")){
		// this.requestResponse = null;
		// }
	}

	public byte[] getRequest() {
		return this.requestResponse.getRequest();
	}

	public byte[] getResponse() {
		return response;
	}

	public void setReqestTime(Date requestTime) {
		this.requestDateTime = requestTime;
		this.formattedRequestTime = LogProcessor.LOGGER_DATE_FORMAT.format(this.requestDateTime);
	}

	public void setResponseTime(Date responseTime) {
		this.responseDateTime = responseTime;
		this.formattedResponseTime = LogProcessor.LOGGER_DATE_FORMAT.format(this.responseDateTime);
	}

	public void setComment(String comment) {
		this.requestResponse.setComment(comment);
	}

	public String getComment() {
		return this.requestResponse.getComment();
	}


	public Object getValueByKey(LogEntryField columnName) {

		try {
			switch (columnName) {
				case PROXY_TOOL:
				case REQUEST_TOOL:
					return getToolName();
				case TAGS:
					return this.matchingTags.stream().map(Tag::getName).collect(Collectors.toList());
				case URL:
					return this.url;
				case PATH:
					return this.url.getPath();
				case QUERY:
					return this.url.getQuery();
				case PATHQUERY:
					return this.url.getFile();
				case STATUS:
					return this.responseStatus;
				case STATUS_TEXT:
					return this.responseStatusText;
				case RESPONSE_HTTP_VERSION:
					return this.responseHttpVersion;
				case PROTOCOL:
					return this.protocol;
				case HOSTNAME:
					return this.hostname;
				case HOST:
					return this.host;
				case MIME_TYPE:
					return this.responseMimeType;
				case RESPONSE_LENGTH:
					return this.responseBodyLength;
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
				case REQUEST_HTTP_VERSION:
					return this.requestHttpVersion;
				case EXTENSION:
					return this.urlExtension;
				case REFERRER:
					return this.referrerURL;
				case PARAMETERS:
					return this.parameters;
				case PARAMETER_COUNT:
					return this.parameters.size();
				case HASGETPARAM:
					return this.url.getQuery() != null;
				case HASPOSTPARAM:
					return this.hasBodyParam;
				case HASCOOKIEPARAM:
					return this.hasCookieParam;
				case REQUEST_LENGTH:
					return this.requestBodyLength;
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
				case USES_COOKIE_JAR:
					return this.usesCookieJar.toString();
				case ORIGIN:
					return this.origin;
				// case REGEX1REQ:
				// return this.regexAllReq[0];
				// case REGEX2REQ:
				// return this.regexAllReq[1];
				// case REGEX3REQ:
				// return this.regexAllReq[2];
				// case REGEX4REQ:
				// return this.regexAllReq[3];
				// case REGEX5REQ:
				// return this.regexAllReq[4];
				// case REGEX1RESP:
				// return this.regexAllResp[0];
				// case REGEX2RESP:
				// return this.regexAllResp[1];
				// case REGEX3RESP:
				// return this.regexAllResp[2];
				// case REGEX4RESP:
				// return this.regexAllResp[3];
				// case REGEX5RESP:
				// return this.regexAllResp[4];
				case REFLECTED_PARAMS:
					return reflectedParameters;
				case REFLECTION_COUNT:
					return reflectedParameters.size();
				case REQUEST_BODY: // request
					if (requestBodyLength == 0) return "";
					return new String(getRequest(), getRequest().length - requestBodyLength, requestBodyLength);
//							.substring(request.length - requestBodyLength);
				case RESPONSE_BODY: // response
					if (responseBodyLength == 0) return "";
					return new String(response, response.length - responseBodyLength, responseBodyLength);
//							.substring(response.length - responseBodyLength);
				case RTT:
					return requestResponseDelay;
				case REQUEST_HEADERS:
					return requestHeaders != null ? String.join("\r\n", requestHeaders) : "";
				case RESPONSE_HEADERS:
					return responseHeaders != null ? String.join("\r\n", responseHeaders) : "";
				case REDIRECT_URL:
					return redirectURL;
				case BASE64_REQUEST:
					return Base64.getEncoder().encodeToString(this.getRequest());
				case BASE64_RESPONSE:
					return Base64.getEncoder().encodeToString(response);
				case RESPONSE_HASH: {
					if (responseHash == null) {
						responseHash = DigestUtils
								.sha1Hex(((String) getValueByKey(LogEntryField.RESPONSE_BODY)).getBytes());
					}
					return responseHash;
				}
				default:
					return "";
			}
		} catch (Exception e) {
			return "";
		}
	}

	public List<UUID> getMatchingColorFilters() {
		return matchingColorFilters;
	}

	public List<Tag> getMatchingTags() {
		return matchingTags;
	}

	public IHttpService getHttpService() {
		return this.requestResponse.getHttpService();
	}

	public enum CookieJarStatus {
		YES("Yes"), NO("No"), PARTIALLY("Partially");

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
	 * 
	 * @param colorFilter
	 * @param retest
	 * @return If the list of matching color filters was updated
	 */
	public boolean testColorFilter(ColorFilter colorFilter, boolean retest) {
		if (!colorFilter.isEnabled() || colorFilter.getFilter() == null) {
			return this.getMatchingColorFilters().remove(colorFilter.getUUID());
		}

		// If we don't already know if the color filter matches (e.g. haven't checked it
		// before)
		if (!this.matchingColorFilters.contains(colorFilter.getUUID())) {
			if (colorFilter.getFilter().matches(this)) {
				this.matchingColorFilters.add(colorFilter.getUUID());
				return true;
			} else {
				return false;
			}
		} else if (retest) { // Or if we are forcing a retest (e.g. filter was updated)
			if (!colorFilter.getFilter().matches(this)) {
				this.matchingColorFilters.remove(colorFilter.getUUID());
			}
			return true;
		} else {
			return false;
		}
	}

	/*
	 * @param Tag
	 * @param retest
	 * @return If the list of matching color filters was updated
	 */
	public boolean testTag(Tag tag, boolean retest) {
		if (!tag.isEnabled() || tag.getFilter() == null) {
			return this.getMatchingTags().remove(tag);
		}

		// If we don't already know if the color filter matches (e.g. haven't checked it
		// before)
		if (!this.matchingTags.contains(tag)) {
			if (tag.getFilter().matches(this)) {
				this.matchingTags.add(tag);
				return true;
			} else {
				return false;
			}
		} else if (retest) { // Or if we are forcing a retest (e.g. filter was updated)
			if (!tag.getFilter().matches(this)) {
				this.matchingTags.remove(tag);
			}
			return true;
		} else {
			return false;
		}
	}

	@Override
	public String toString() {
		return this.url.toString();
	}

	public static Integer extractAndRemoveIdentifierFromComment(LogEntry logEntry) {
		return LogProcessorHelper.extractAndRemoveIdentifierFromRequestResponseComment(logEntry.requestResponse);
	}
}
