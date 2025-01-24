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

import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.MimeType;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.filter.colorfilter.TableColorRule;
import com.nccgroup.loggerplusplus.filter.tag.Tag;
import com.nccgroup.loggerplusplus.logview.processor.LogProcessor;
import com.nccgroup.loggerplusplus.reflection.ReflectionController;
import com.nccgroup.loggerplusplus.util.Globals;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.Setter;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.lang3.StringUtils;

import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.stream.Collectors;

import static com.nccgroup.loggerplusplus.LoggerPlusPlus.montoya;

@Getter
@Setter
public class LogEntry {

	Status previousStatus;
	Status status = Status.UNPROCESSED;

	@Setter(AccessLevel.NONE)
	private HttpRequest request;
	@Setter(AccessLevel.NONE)
	private HttpResponse response;

	private Integer identifier;
	private ToolType tool;
	private String hostname = "";
	private String host = "";
	private String method = "";
	private String urlString;
	private URL url;
	private boolean params = false;
	private Short responseStatus = -1;
	private String responseStatusText = "";
	private String responseHttpVersion = "";
	private boolean hasBodyParam = false;
	private boolean hasCookieParam = false;
	private String title = "";
	private String comment;
	private List<String> newCookies = new ArrayList<>();
	private String sentCookies = "";
	private String listenerInterface = "";
	private boolean isSSL = false;
	private String urlExtension = "";
	private String referrerURL = "";
	private String requestHttpVersion = "";
	private String requestContentType = "";
	private String protocol = "";
	private short targetPort = -1;
	private int requestBodyLength = -1;
	private String clientIP = "";
	private boolean hasSetCookies = false;
	private String formattedResponseTime = "";
	private MimeType responseMimeType;
	private MimeType responseInferredMimeType;
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
	private Date responseDateTime = null; // If null, gets pulled from the response
	private Date requestDateTime = null; // If null, becomes epoch start time
	private int requestResponseDelay = -1;
	private List<HttpHeader> responseHeaders;
	private List<HttpHeader> requestHeaders;
	private List<String> parameters;
	private List<String> reflectedParameters;

	private LogEntry() {
		this.matchingColorFilters = Collections.synchronizedList(new ArrayList<>());
		this.matchingTags = Collections.synchronizedList(new ArrayList<>());
	}

	public LogEntry(ToolType tool, HttpRequest request) {
		this();
		this.tool = tool;
		this.request = request;
	}

	public LogEntry(ToolType tool, HttpRequest request, HttpResponse response){
		this(tool, request);
		this.response = response;
		this.requestDateTime = new Date(0);
	}

	public LogEntry(ToolType tool, HttpRequest request, HttpResponse response, Date requestTime, Date responseTime){
		this(tool, request);
		this.response = response;
		this.requestDateTime = requestTime;
		this.responseDateTime = responseTime;
	}

	/**
	 * Create new entry and specify arrival time.
	 *
	 * @param tool
	 * @param request
	 * @param formattedRequestTime
	 */
	public LogEntry(ToolType tool, HttpRequest request, Date formattedRequestTime) {
		this(tool, request);
		this.setReqestTime(formattedRequestTime);
	}

	public boolean process() {
		previousStatus = this.status;
		switch (this.status) {
			case UNPROCESSED: {
				this.status = processRequest();
				//fall through to process response
			}
			case AWAITING_RESPONSE: {
				if (this.response == null) {
					this.status = Status.AWAITING_RESPONSE;
					return false;
				}
				processResponse();
				this.status = Status.PROCESSED;
				return true;
			}

			case PROCESSED: {
				// Nothing to do, we're done!
				return true;
			}

			default: return false;
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


		requestHeaders = new ArrayList<>(request.headers());

		this.requestHttpVersion = request.httpVersion();

		this.parameters = request.parameters().stream()
				.filter(param -> param.type() != HttpParameterType.COOKIE)
				.map(HttpParameter::name)
				.collect(Collectors.toList());

		this.urlString = request.url();
		this.hostname = this.request.httpService().host();
		this.protocol = this.request.httpService().secure() ? "https" : "http";
		this.isSSL = this.request.httpService().secure();
		this.targetPort = (short) this.request.httpService().port();

		boolean isDefaultPort = (this.protocol.equals("https") && this.targetPort == 443)
				|| (this.protocol.equals("http") && this.targetPort == 80);

		this.host = this.protocol + "://" + this.hostname + (isDefaultPort ? "" : ":" + this.targetPort);

		this.method = request.method();
		this.requestBodyLength = this.getRequestBytes().length - request.bodyOffset();
		this.hasBodyParam = requestBodyLength > 0;

		try {
			this.url = new URL(request.url());

			// I don't want to delete special characters such as ; or : from the extension
			// as it may really be part of the extension! (burp proxy log ignores them)
			String tempPath = url.getPath().replaceAll("\\\\", "/");
			tempPath = tempPath.substring(tempPath.lastIndexOf("/"));
			int tempPathDotLocation = tempPath.lastIndexOf(".");
			if (tempPathDotLocation >= 0) {
				this.urlExtension = tempPath.substring(tempPathDotLocation + 1);
			}
			this.params = url.getQuery() != null || this.hasBodyParam;
		} catch (MalformedURLException ignored) {}


		for (HttpHeader header : requestHeaders) {
			if (header.name().equalsIgnoreCase("cookie")) {
				this.sentCookies = header.value();
				if (!this.sentCookies.isEmpty()) {
					this.hasCookieParam = true;
					this.sentCookies += ";"; // we need to ad this to search it in cookie Jar!

					// Check to see if it uses cookie Jars!
					List<Cookie> cookiesInJar = montoya.http().cookieJar().cookies();
					boolean oneNotMatched = false;
					boolean anyParamMatched = false;

					for (Cookie cookieItem : cookiesInJar) {
						if (cookieItem.domain().equals(this.hostname)) {
							// now we want to see if any of these cookies have been set here!
							String currentCookieJarParam = cookieItem.name() + "=" + cookieItem.value() + ";";
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
			} else if (header.name().equalsIgnoreCase("referer")) {
				this.referrerURL = header.value();
			} else if (header.name().equalsIgnoreCase("content-type")) {
				this.requestContentType = header.value();
			} else if (header.name().equalsIgnoreCase("origin")) {
				this.origin = header.value();
			}
		}

		return Status.AWAITING_RESPONSE;

	}

	/**
	 * Update entry with response object and arrival time.
	 * 
	 * @param requestResponse
	 * @param arrivalTime
	 */
	public void addResponse(HttpResponse requestResponse, Date arrivalTime) {
		this.responseDateTime = arrivalTime;

		//IHttpRequestResponse objects received by the proxy listener do not contain the latest request.
		//So we must store the content separately.
		this.response = requestResponse;
//		this.setComment(requestResponse.getComment()); //Update the comment with the current comment
	}

	private Status processResponse() {
		reflectedParameters = new ArrayList<>();
//		IResponseInfo tempAnalyzedResp = LoggerPlusPlus.montoya.getHelpers()
//				.analyzeResponse(response);

		this.responseStatus = response.statusCode();
		this.responseBodyLength = response.body().length();
		this.responseMimeType = response.statedMimeType();
		this.responseInferredMimeType = response.inferredMimeType();

		/**************************************
		 ************HEADER PROCESSING*********
		 **************************************/

		Map<String, String> headers = response.headers().stream()
				.collect(Collectors.toMap(HttpHeader::name, HttpHeader::value, (s, s2) -> {
					s += ", " + s2;
					return s;
				}, () -> new TreeMap<>(String.CASE_INSENSITIVE_ORDER)));

		responseHeaders = response.headers();

		if (headers.containsKey("Location")) {
			this.redirectURL = headers.get("Location");
		}

		this.responseStatusText = response.reasonPhrase();
		this.responseHttpVersion = response.httpVersion();


		if (headers.containsKey("content-type")) {
			this.responseContentType = headers.get("content-type");
		}

		//Cookies
		this.newCookies = response.cookies().stream().map(cookie -> String.format("%s=%s", cookie.name(), cookie.value())).collect(Collectors.toList());
		this.hasSetCookies = !newCookies.isEmpty();

		// If response date isn't set, pull it from response headers
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
		int bodyOffset = response.bodyOffset();
		if (responseBodyLength < maxRespSize) {
			//Only title match HTML files. Prevents expensive regex running on e.g. binary downloads.
			if (this.responseInferredMimeType == MimeType.HTML) {
				Matcher titleMatcher = Globals.HTML_TITLE_PATTERN.matcher(response.bodyToString());
				if (titleMatcher.find()) {
					this.title = titleMatcher.group(1);
				}
			}

			ReflectionController reflectionController = LoggerPlusPlus.instance.getReflectionController();
			reflectedParameters = request.parameters().parallelStream()
					.filter(parameter -> !reflectionController.isParameterFiltered(parameter) && reflectionController.validReflection(response.bodyToString(), parameter))
					.map(HttpParameter::name).collect(Collectors.toList());

		} else {
			//Just look for reflections in the headers.
			ReflectionController reflectionController = LoggerPlusPlus.instance.getReflectionController();
			reflectedParameters = request.parameters().parallelStream()
					.filter(parameter -> !reflectionController.isParameterFiltered(parameter)
							&& reflectionController.validReflection(response.bodyToString(), parameter))
					.map(HttpParameter::name).collect(Collectors.toList());

			//Trim the response down to a maximum size, but at least keep the headers!
			//TODO Fix response trimming?
//			this.response = (new String(this.response, 0, bodyOffset) + "Response body trimmed by Logger++. To prevent this, increase \"Maximum Response Size\" in the Logger++ options.").getBytes(StandardCharsets.UTF_8);
		}

		this.complete = true;

		return Status.PROCESSED;
	}

	public byte[] getRequestBytes() {
		if(request == null) return new byte[0];
		return this.request.toByteArray().getBytes();
	}

	public byte[] getResponseBytes() {
		if(response == null) return new byte[0];
		return response.toByteArray().getBytes();
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
		this.comment = comment;
	}

	public String getComment() {
		return this.comment;
	}


	public Object getValueByKey(LogEntryField columnName) {

		try {
			switch (columnName) {
				case INSCOPE:
					return montoya.scope().isInScope(urlString);
				case PROXY_TOOL:
				case REQUEST_TOOL:
					return tool.toolName();
				case TAGS:
					return this.matchingTags.stream().collect(Collectors.toList());
				case URL:
					return this.urlString;
				case PATH:
					return (this.url != null ? this.url.getPath() : "");
				case QUERY:
					return (this.url != null ? this.url.getQuery() : "");
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
					return this.comment;
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
					return this.url != null && this.url.getQuery() != null;
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
				case REFLECTED_PARAMS:
					return reflectedParameters;
				case REFLECTION_COUNT:
					return reflectedParameters.size();
				case REQUEST_BODY: // request
					return request.bodyToString();
				case REQUEST_BODY_LENGTH:
					return request.body().length();
//							.substring(request.length - requestBodyLength);
				case RESPONSE_BODY: // response
					return response.bodyToString();
				case RESPONSE_BODY_LENGTH:
					return response.body().length();
				case RTT:
					return requestResponseDelay;
				case REQUEST_HEADERS: {
					if(requestHeaders == null) return "";
					//Hacky workaround since Burp doesn't include path in headers.
					return String.format("%s %s %s\r\n%s", request.method(), request.path(), request.httpVersion(), requestHeaders.stream().map(HttpHeader::toString).collect(Collectors.joining("\r\n")));
				}
				case RESPONSE_HEADERS:
					return responseHeaders != null ? responseHeaders.stream().map(HttpHeader::toString).collect(Collectors.joining("\r\n")) : "";
				case REDIRECT_URL:
					return redirectURL;
				case BASE64_REQUEST:
					return Base64.getEncoder().encodeToString(this.getRequestBytes());
				case BASE64_RESPONSE:
					return Base64.getEncoder().encodeToString(this.getResponseBytes());
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

	public HttpService getHttpService() {
		return this.request.httpService();
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
	 * @param tableColorRule
	 * @param retest
	 * @return If the list of matching color filters was updated
	 */
	public boolean testColorFilter(TableColorRule tableColorRule, boolean retest) {
		if (!tableColorRule.isEnabled() || tableColorRule.getFilterExpression() == null) {
			return this.getMatchingColorFilters().remove(tableColorRule.getUuid());
		}

		// If we don't already know if the color filter matches (e.g. haven't checked it
		// before)
		if (!this.matchingColorFilters.contains(tableColorRule.getUuid())) {
			if (tableColorRule.getFilterExpression().matches(this)) {
				this.matchingColorFilters.add(tableColorRule.getUuid());
				return true;
			} else {
				return false;
			}
		} else if (retest) { // Or if we are forcing a retest (e.g. filter was updated)
			if (!tableColorRule.getFilterExpression().matches(this)) {
				this.matchingColorFilters.remove(tableColorRule.getUuid());
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
		if (!tag.isEnabled() || tag.getFilterExpression() == null) {
			return this.getMatchingTags().remove(tag);
		}

		// If we don't already know if the color filter matches (e.g. haven't checked it
		// before)
		if (!this.matchingTags.contains(tag)) {
			if (tag.getFilterExpression().matches(this)) {
				this.matchingTags.add(tag);
				return true;
			} else {
				return false;
			}
		} else if (retest) { // Or if we are forcing a retest (e.g. filter was updated)
			if (!tag.getFilterExpression().matches(this)) {
				this.matchingTags.remove(tag);
			}
			return true;
		} else {
			return false;
		}
	}

	@Override
	public String toString() {
		return this.urlString.toString();
	}

//	public static Integer extractAndRemoveIdentifierFromComment(LogEntry logEntry) {
//		return LogProcessorHelper.extractAndRemoveIdentifierFromRequestResponseComment(logEntry.request);
//	}
}
