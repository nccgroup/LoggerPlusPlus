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

import static com.nccgroup.loggerplusplus.LoggerPlusPlus.montoya;

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
import com.nccgroup.loggerplusplus.util.Canonical;
import com.nccgroup.loggerplusplus.util.Globals;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;
import java.util.regex.Matcher;

/**
 * One row of the log: a request, its response once it arrives, and what the table, the filters and
 * the exports need to know about them.
 *
 * <p>An entry is built to be small, because a table holds up to a million of them. It keeps what is
 * asked for on every repaint and by most filters (the URL's parts, the status, lengths, times), and
 * works out the rest from Burp's own request and response objects when asked: headers, bodies,
 * cookies. Values that many entries repeat, such as the host, are shared between them.
 *
 * <p>{@link #process()} is called by one worker thread at a time; the table and the filters read
 * the entry from other threads while it runs.
 */
public class LogEntry {
    /**
     * Marks a response time that was given as null, where the entry falls back to the Date header.
     */
    private static final long NO_TIME = Long.MIN_VALUE;

    private static final Short[] STATUS_CODES = new Short[1000];

    private static final SimpleDateFormat SERVER_DATE_FORMAT =
            new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss zzz");

    private Status previousStatus;
    private Status status = Status.UNPROCESSED;

    private final HttpRequest request;
    private HttpResponse response;
    private final ToolType tool;
    private Integer identifier;
    private String comment;
    private String listenerInterface = "";
    private long arrivalNumber = -1;

    // What reading the request found.
    private boolean requestRead;
    private String urlString;
    private boolean urlParsed;
    private String path = "";
    private String query;
    private String hostname = "";
    private String host = "";
    private String protocol = "";
    private String method = "";
    private String urlExtension = "";
    private String referrerURL = "";
    private String origin = "";
    private String requestHttpVersion = "";
    private String requestContentType = "";
    private int targetPort = -1;
    private int requestBodyLength = -1;
    private boolean isSSL;
    private boolean params;
    private boolean hasBodyParam;
    private boolean hasCookieParam;
    private CookieJarStatus usesCookieJar = CookieJarStatus.NO;
    private List<String> parameters;

    // What reading the response found.
    private boolean responseRead;
    private short responseStatus = -1;
    private String responseStatusText = "";
    private String responseHttpVersion = "";
    private String responseContentType = "";
    private String title = "";
    private String redirectURL;
    private String responseHash;
    private MimeType responseMimeType;
    private MimeType responseInferredMimeType;
    private int responseBodyLength = -1;
    private int requestResponseDelay = -1;
    private boolean hasSetCookies;
    private boolean complete;
    private List<String> newCookies;
    private List<String> reflectedParameters;

    // Times, in milliseconds since the epoch. Both start at zero so that neither is ever null.
    private long requestTime;
    private boolean requestTimeGiven;
    private long responseTime;

    // Replaced, never changed in place: the table reads them while workers test filters.
    private volatile List<UUID> matchingColorFilters = List.of();
    private volatile List<Tag> matchingTags = List.of();

    public LogEntry(ToolType tool, HttpRequest request) {
        this.tool = tool;
        this.request = request;
    }

    public LogEntry(ToolType tool, HttpRequest request, HttpResponse response) {
        this(tool, request);
        this.response = response;
    }

    /** A new entry for a request that arrived at {@code requestTime}. */
    public LogEntry(ToolType tool, HttpRequest request, Date requestTime) {
        this(tool, request);
        this.setReqestTime(requestTime);
    }

    /**
     * Reads the request if it has not been read, then the response if there is one.
     *
     * @return whether the entry is complete, that is, its response has been read
     */
    public boolean process() {
        previousStatus = this.status;
        if (this.status == Status.PROCESSED) {
            return true;
        }
        if (this.status == Status.UNPROCESSED) {
            readRequest();
        }
        if (this.response == null) {
            this.status = Status.AWAITING_RESPONSE;
            return false;
        }
        readResponse();
        this.status = Status.PROCESSED;
        return true;
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

    private void readRequest() {
        this.requestHttpVersion = canonicalOrEmpty(request.httpVersion());

        List<String> names = new ArrayList<>();
        for (HttpParameter parameter : request.parameters()) {
            if (parameter.type() != HttpParameterType.COOKIE) {
                names.add(parameter.name());
            }
        }
        this.parameters = List.copyOf(names);

        HttpService service = request.httpService();
        this.urlString = request.url();
        this.hostname = Canonical.of(service.host());
        this.isSSL = service.secure();
        this.protocol = this.isSSL ? "https" : "http";
        this.targetPort = service.port();
        boolean isDefaultPort = this.targetPort == (this.isSSL ? 443 : 80);
        this.host =
                Canonical.of(
                        this.protocol
                                + "://"
                                + this.hostname
                                + (isDefaultPort ? "" : ":" + this.targetPort));

        this.method = Canonical.of(request.method());
        this.requestBodyLength = request.toByteArray().length() - request.bodyOffset();
        this.hasBodyParam = requestBodyLength > 0;
        readUrl();
        readRequestHeaders(request.headers());
        this.requestRead = true;
    }

    private void readUrl() {
        try {
            URL url = new URL(urlString);
            this.path = url.getPath();
            this.query = url.getQuery();
            this.urlParsed = true;
            this.urlExtension = Canonical.of(extensionOf(this.path));
            this.params = this.query != null || this.hasBodyParam;
        } catch (MalformedURLException ignored) {
            // The path, query and extension stay empty, as they always have for such a URL.
        }
    }

    /**
     * What follows the last dot of the path's last segment. Characters such as {@code ;} and {@code
     * :} stay: they may really be part of the extension, though Burp's proxy history drops them.
     */
    private static String extensionOf(String path) {
        String lastSegment = path.replace('\\', '/');
        lastSegment = lastSegment.substring(Math.max(lastSegment.lastIndexOf('/'), 0));
        int dot = lastSegment.lastIndexOf('.');
        return dot >= 0 ? lastSegment.substring(dot + 1) : "";
    }

    private static String canonicalOrEmpty(String text) {
        return text == null ? "" : Canonical.of(text);
    }

    private void readRequestHeaders(List<HttpHeader> headers) {
        for (HttpHeader header : headers) {
            String name = header.name();
            if (name.equalsIgnoreCase("cookie")) {
                String sentCookies = header.value();
                if (!sentCookies.isEmpty()) {
                    this.hasCookieParam = true;
                    compareWithCookieJar(sentCookies + ";");
                }
            } else if (name.equalsIgnoreCase("referer")) {
                this.referrerURL = header.value();
            } else if (name.equalsIgnoreCase("content-type")) {
                this.requestContentType = Canonical.of(header.value());
            } else if (name.equalsIgnoreCase("origin")) {
                this.origin = Canonical.of(header.value());
            }
        }
    }

    /** Records whether all, some or none of the jar's cookies for this host were sent. */
    private void compareWithCookieJar(String sentCookies) {
        boolean oneNotMatched = false;
        boolean anyMatched = false;
        for (Cookie cookie : montoya.http().cookieJar().cookies()) {
            if (this.hostname.equals(cookie.domain())) {
                if (sentCookies.contains(cookie.name() + "=" + cookie.value() + ";")) {
                    anyMatched = true;
                } else {
                    oneNotMatched = true;
                }
            }
            if (anyMatched && oneNotMatched) {
                break;
            }
        }
        if (anyMatched) {
            this.usesCookieJar = oneNotMatched ? CookieJarStatus.PARTIALLY : CookieJarStatus.YES;
        }
    }

    /**
     * Attaches the response, which arrived at {@code arrivalTime}, for the next {@link #process}.
     */
    public void addResponse(HttpResponse response, Date arrivalTime) {
        this.responseTime = arrivalTime == null ? NO_TIME : arrivalTime.getTime();
        this.response = response;
    }

    private void readResponse() {
        this.responseStatus = response.statusCode();
        this.responseStatusText = canonicalOrEmpty(response.reasonPhrase());
        this.responseHttpVersion = canonicalOrEmpty(response.httpVersion());
        this.responseBodyLength = response.body().length();
        this.responseMimeType = response.statedMimeType();
        this.responseInferredMimeType = response.inferredMimeType();

        List<HttpHeader> headers = response.headers();
        String location = combinedHeader(headers, "location");
        if (location != null) {
            this.redirectURL = location;
        }
        String contentType = combinedHeader(headers, "content-type");
        if (contentType != null) {
            this.responseContentType = Canonical.of(contentType);
        }
        this.hasSetCookies = !response.cookies().isEmpty();
        this.newCookies = null;

        if (this.responseTime == NO_TIME) {
            this.responseTime = parseServerDate(combinedHeader(headers, "date"));
        }
        if (this.responseTime != NO_TIME) {
            this.requestResponseDelay = (int) (this.responseTime - this.requestTime);
        }

        readResponseBody();
        this.responseHash = null;
        this.responseRead = true;
        this.complete = true;
    }

    /** The body is turned into a string at most once, and only if something needs to search it. */
    private void readResponseBody() {
        String body = null;
        int megabytes =
                LoggerPlusPlus.instance
                        .getPreferencesController()
                        .getPreferences()
                        .getSetting(Globals.PREF_MAX_RESP_SIZE);
        // Only HTML is searched for a title, and only below the size limit: the pattern is costly.
        if (responseBodyLength < megabytes * 1000000L
                && responseInferredMimeType == MimeType.HTML) {
            body = response.bodyToString();
            Matcher titleMatcher = Globals.HTML_TITLE_PATTERN.matcher(body);
            if (titleMatcher.find()) {
                this.title = titleMatcher.group(1);
            }
        }

        ReflectionController reflections = LoggerPlusPlus.instance.getReflectionController();
        ReflectionController.Scan scan = null;
        List<String> reflected = new ArrayList<>();
        for (HttpParameter parameter : request.parameters()) {
            if (reflections.isParameterFiltered(parameter)) {
                continue;
            }
            if (scan == null) {
                scan = reflections.scan(body != null ? body : response.bodyToString());
            }
            if (scan.reflects(parameter)) {
                reflected.add(parameter.name());
            }
        }
        this.reflectedParameters = List.copyOf(reflected);
    }

    /** The values of every header of that name, joined by a comma and a space; null when none. */
    private static String combinedHeader(List<HttpHeader> headers, String name) {
        String combined = null;
        for (HttpHeader header : headers) {
            if (header.name().equalsIgnoreCase(name)) {
                combined = combined == null ? header.value() : combined + ", " + header.value();
            }
        }
        return combined;
    }

    private static long parseServerDate(String dateHeader) {
        if (dateHeader == null || dateHeader.isBlank()) {
            return NO_TIME;
        }
        try {
            synchronized (SERVER_DATE_FORMAT) {
                return SERVER_DATE_FORMAT.parse(dateHeader).getTime();
            }
        } catch (ParseException e) {
            return NO_TIME;
        }
    }

    public HttpRequest getRequest() {
        return request;
    }

    public HttpResponse getResponse() {
        return response;
    }

    /** The request as it was sent; empty when the entry has none. */
    public byte[] getRequestBytes() {
        if (request == null) {
            return new byte[0];
        }
        return this.request.toByteArray().getBytes();
    }

    /** The response as it was received; empty until one has arrived. */
    public byte[] getResponseBytes() {
        if (response == null) {
            return new byte[0];
        }
        return response.toByteArray().getBytes();
    }

    public ToolType getTool() {
        return tool;
    }

    public Integer getIdentifier() {
        return identifier;
    }

    public void setIdentifier(Integer identifier) {
        this.identifier = identifier;
    }

    /**
     * The entry's place in the order entries were added to the log table, or -1 before it is added.
     * The table's rows are in this order, which lets it find an entry's row without searching.
     */
    public long getArrivalNumber() {
        return arrivalNumber;
    }

    public void setArrivalNumber(long arrivalNumber) {
        this.arrivalNumber = arrivalNumber;
    }

    public HttpService getHttpService() {
        return this.request.httpService();
    }

    public void setReqestTime(Date requestTime) {
        this.requestTime = requestTime.getTime();
        this.requestTimeGiven = true;
    }

    public void setResponseTime(Date responseTime) {
        this.responseTime = responseTime.getTime();
    }

    public Date getRequestDateTime() {
        return new Date(requestTime);
    }

    /** When the response arrived; null only when no time was given and its Date header had none. */
    public Date getResponseDateTime() {
        return responseTime == NO_TIME ? null : new Date(responseTime);
    }

    /** The request time as the table shows it; null when the entry was created without one. */
    public String getFormattedRequestTime() {
        return requestTimeGiven ? LogProcessor.LOGGER_DATE_FORMAT.format(requestTime) : null;
    }

    /** The response time as the table shows it; empty until a response with a time is read. */
    public String getFormattedResponseTime() {
        return responseRead && responseTime != NO_TIME
                ? LogProcessor.LOGGER_DATE_FORMAT.format(responseTime)
                : "";
    }

    /**
     * The proxy listener the message came through, such as {@code 127.0.0.1:8080}; empty for a
     * message of another tool.
     */
    public String getListenerInterface() {
        return listenerInterface;
    }

    public void setListenerInterface(String listenerInterface) {
        this.listenerInterface = listenerInterface == null ? null : Canonical.of(listenerInterface);
    }

    public void setComment(String comment) {
        this.comment = comment;
    }

    public String getComment() {
        return this.comment;
    }

    public String getUrlString() {
        return urlString;
    }

    /** The request's URL, parsed; null when it cannot be parsed. */
    public URL getUrl() {
        try {
            return urlParsed ? new URL(urlString) : null;
        } catch (MalformedURLException e) {
            return null;
        }
    }

    public String getHostname() {
        return hostname;
    }

    public String getProtocol() {
        return protocol;
    }

    public String getMethod() {
        return method;
    }

    public String getOrigin() {
        return origin;
    }

    public int getTargetPort() {
        return targetPort;
    }

    public String getRequestHttpVersion() {
        return requestHttpVersion;
    }

    public String getRequestContentType() {
        return requestContentType;
    }

    public int getRequestBodyLength() {
        return requestBodyLength;
    }

    public boolean isHasBodyParam() {
        return hasBodyParam;
    }

    public boolean isHasCookieParam() {
        return hasCookieParam;
    }

    /** The request's headers, without the request line. */
    public List<HttpHeader> getRequestHeaders() {
        return request.headers();
    }

    public Short getResponseStatus() {
        return boxedStatus(responseStatus);
    }

    /** One object per status code: every filter on the status asks for it, for every entry. */
    private static Short boxedStatus(short status) {
        if (status < 0 || status >= STATUS_CODES.length) {
            return status;
        }
        Short boxed = STATUS_CODES[status];
        if (boxed == null) {
            boxed = status;
            STATUS_CODES[status] = boxed;
        }
        return boxed;
    }

    public String getResponseStatusText() {
        return responseStatusText;
    }

    public String getResponseHttpVersion() {
        return responseHttpVersion;
    }

    public String getResponseContentType() {
        return responseContentType;
    }

    public int getResponseBodyLength() {
        return responseBodyLength;
    }

    public boolean isHasSetCookies() {
        return hasSetCookies;
    }

    public boolean isComplete() {
        return complete;
    }

    /** The response's headers, without the status line; null until a response has been read. */
    public List<HttpHeader> getResponseHeaders() {
        return responseRead ? response.headers() : null;
    }

    /** The Cookie header's value followed by a semicolon; empty when no cookie was sent. */
    private String sentCookies() {
        String sentCookies = "";
        if (requestRead) {
            for (HttpHeader header : request.headers()) {
                if (header.name().equalsIgnoreCase("cookie")) {
                    sentCookies = header.value();
                }
            }
        }
        return sentCookies.isEmpty() ? sentCookies : sentCookies + ";";
    }

    /** Each cookie the response set, as {@code name=value}. Worked out when first asked for. */
    private List<String> newCookies() {
        List<String> cookies = this.newCookies;
        if (cookies == null) {
            if (!responseRead) {
                return List.of();
            }
            List<String> found = new ArrayList<>();
            for (Cookie cookie : response.cookies()) {
                found.add(cookie.name() + "=" + cookie.value());
            }
            cookies = List.copyOf(found);
            this.newCookies = cookies;
        }
        return cookies;
    }

    /** The first line of the request, which Burp leaves out of the headers. */
    private String requestLine() {
        return request.method() + " " + request.path() + " " + request.httpVersion();
    }

    private static String joined(List<HttpHeader> headers) {
        StringBuilder joined = new StringBuilder();
        for (HttpHeader header : headers) {
            if (joined.length() > 0) {
                joined.append("\r\n");
            }
            joined.append(header.toString());
        }
        return joined.toString();
    }

    private String responseHash() {
        if (response == null) {
            return sha1Hex("");
        }
        if (responseHash == null) {
            responseHash = sha1Hex(response.bodyToString());
        }
        return responseHash;
    }

    private static String sha1Hex(String text) {
        try {
            MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
            return HexFormat.of().formatHex(sha1.digest(text.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Every Java platform provides SHA-1", e);
        }
    }

    /**
     * The value of a field, for the table, the filters and the exports. A field that cannot be
     * answered yet (a response field before the response arrives) is an empty string.
     */
    public Object getValueByKey(LogEntryField columnName) {
        try {
            return switch (columnName) {
                case INSCOPE -> montoya.scope().isInScope(urlString);
                case PROXY_TOOL, REQUEST_TOOL -> tool.toolName();
                case TAGS -> this.matchingTags;
                case URL -> this.urlString;
                case PATH -> this.path;
                case QUERY -> this.urlParsed ? this.query : "";
                case PATHQUERY ->
                        this.urlParsed
                                ? (this.query == null ? this.path : this.path + "?" + this.query)
                                : "";
                case STATUS -> boxedStatus(this.responseStatus);
                case STATUS_TEXT -> this.responseStatusText;
                case RESPONSE_HTTP_VERSION -> this.responseHttpVersion;
                case PROTOCOL -> this.protocol;
                case HOSTNAME -> this.hostname;
                case HOST -> this.host;
                case MIME_TYPE -> this.responseMimeType;
                case RESPONSE_LENGTH -> this.responseBodyLength;
                case PORT -> this.targetPort;
                case METHOD -> this.method;
                case REQUEST_TIME -> getRequestDateTime();
                case RESPONSE_TIME -> getResponseDateTime();
                case COMMENT -> this.comment;
                case REQUEST_CONTENT_TYPE -> this.requestContentType;
                case REQUEST_HTTP_VERSION -> this.requestHttpVersion;
                case EXTENSION -> this.urlExtension;
                case REFERRER -> this.referrerURL;
                case PARAMETERS -> this.parameters;
                case PARAMETER_COUNT ->
                        this.parameters == null ? "" : (Object) this.parameters.size();
                case HASGETPARAM -> this.query != null;
                case HASPOSTPARAM -> this.hasBodyParam;
                case HASCOOKIEPARAM -> this.hasCookieParam;
                case REQUEST_LENGTH -> this.requestBodyLength;
                case RESPONSE_CONTENT_TYPE -> this.responseContentType;
                case INFERRED_TYPE -> this.responseInferredMimeType;
                case HAS_SET_COOKIES -> this.hasSetCookies;
                case HASPARAMS -> this.params;
                case TITLE -> this.title;
                case ISSSL -> this.isSSL;
                case NEW_COOKIES -> newCookies();
                case LISTENER_INTERFACE -> this.listenerInterface;
                case CLIENT_IP -> ""; // Burp does not yet say which client sent a proxied request.
                case COMPLETE -> this.complete;
                case SENTCOOKIES -> sentCookies();
                case USES_COOKIE_JAR -> this.usesCookieJar.toString();
                case ORIGIN -> this.origin;
                case REFLECTED_PARAMS -> reflectedParameters;
                case REFLECTION_COUNT ->
                        reflectedParameters == null ? "" : (Object) reflectedParameters.size();
                case REQUEST_BODY -> request.bodyToString();
                case REQUEST_BODY_LENGTH -> request.body().length();
                case RESPONSE_BODY -> response == null ? "" : response.bodyToString();
                case RESPONSE_BODY_LENGTH ->
                        response == null ? "" : (Object) response.body().length();
                case RTT -> requestResponseDelay;
                case REQUEST_HEADERS ->
                        requestRead ? requestLine() + "\r\n" + joined(request.headers()) : "";
                case RESPONSE_HEADERS -> responseRead ? joined(response.headers()) : "";
                case REDIRECT_URL -> redirectURL;
                case BASE64_REQUEST -> Base64.getEncoder().encodeToString(this.getRequestBytes());
                case BASE64_RESPONSE ->
                        response == null
                                ? ""
                                : Base64.getEncoder().encodeToString(getResponseBytes());
                case RESPONSE_HASH -> responseHash();
                default -> "";
            };
        } catch (Exception e) {
            return "";
        }
    }

    /** The identifiers of the colour rules this entry matches. The list is never changed. */
    public List<UUID> getMatchingColorFilters() {
        return matchingColorFilters;
    }

    /** The tags this entry matches. The list is never changed. */
    public List<Tag> getMatchingTags() {
        return matchingTags;
    }

    /**
     * Stops counting this entry as a match of that colour rule.
     *
     * @return whether it was one
     */
    public synchronized boolean removeColorFilter(UUID colorFilter) {
        List<UUID> without = without(matchingColorFilters, colorFilter);
        boolean wasPresent = without != matchingColorFilters;
        matchingColorFilters = without;
        return wasPresent;
    }

    /**
     * Stops counting this entry as a match of that tag.
     *
     * @return whether it was one
     */
    public synchronized boolean removeTag(Tag tag) {
        List<Tag> without = without(matchingTags, tag);
        boolean wasPresent = without != matchingTags;
        matchingTags = without;
        return wasPresent;
    }

    private static <T> List<T> with(List<T> list, T added) {
        List<T> longer = new ArrayList<>(list.size() + 1);
        longer.addAll(list);
        longer.add(added);
        return List.copyOf(longer);
    }

    /** The list without its first element equal to {@code removed}; the same list when none is. */
    private static <T> List<T> without(List<T> list, T removed) {
        int index = list.indexOf(removed);
        if (index < 0) {
            return list;
        }
        List<T> shorter = new ArrayList<>(list);
        shorter.remove(index);
        return List.copyOf(shorter);
    }

    public enum CookieJarStatus {
        YES("Yes"),
        NO("No"),
        PARTIALLY("Partially");

        private final String value;

        CookieJarStatus(String value) {
            this.value = value;
        }

        @Override
        public String toString() {
            return this.value;
        }
    }

    /**
     * Tests the entry against a colour rule and records the result.
     *
     * @param retest whether to test again an entry already recorded as matching, as is needed after
     *     the rule's filter is edited
     * @return whether the entry's row may need repainting
     */
    public synchronized boolean testColorFilter(TableColorRule tableColorRule, boolean retest) {
        UUID uuid = tableColorRule.getUuid();
        if (!tableColorRule.isEnabled() || tableColorRule.getFilterExpression() == null) {
            return removeColorFilter(uuid);
        }

        if (!this.matchingColorFilters.contains(uuid)) {
            if (tableColorRule.getFilterExpression().matches(this)) {
                this.matchingColorFilters = with(this.matchingColorFilters, uuid);
                return true;
            }
            return false;
        }
        if (retest) {
            if (!tableColorRule.getFilterExpression().matches(this)) {
                removeColorFilter(uuid);
            }
            return true;
        }
        return false;
    }

    /**
     * Tests the entry against a tag and records the result.
     *
     * @param retest whether to test again an entry already recorded as matching, as is needed after
     *     the tag's filter is edited
     * @return whether the entry's row may need repainting
     */
    public synchronized boolean testTag(Tag tag, boolean retest) {
        if (!tag.isEnabled() || tag.getFilterExpression() == null) {
            return removeTag(tag);
        }

        if (!this.matchingTags.contains(tag)) {
            if (tag.getFilterExpression().matches(this)) {
                this.matchingTags = with(this.matchingTags, tag);
                return true;
            }
            return false;
        }
        if (retest) {
            if (!tag.getFilterExpression().matches(this)) {
                removeTag(tag);
            }
            return true;
        }
        return false;
    }

    @Override
    public String toString() {
        return this.urlString;
    }
}
