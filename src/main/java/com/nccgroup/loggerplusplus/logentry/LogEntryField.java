package com.nccgroup.loggerplusplus.logentry;

import java.net.URL;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;

public enum LogEntryField {

    //Proxy
    NUMBER(FieldGroup.ENTRY, Integer.class, "Item table number. Not valid for filter use.", "Number"),
    PROXY_TOOL(FieldGroup.ENTRY, String.class, "Originating tool name. Extension generated requests will be displayed as \"Extender\".", "Tool"),
    TAGS(FieldGroup.ENTRY, String.class, "The configured tags for which this entry match.", "Tags"),

    INSCOPE(FieldGroup.ENTRY, Boolean.class, "If the URL is in scope", "InScope"),
    LISTENER_INTERFACE(FieldGroup.ENTRY, String.class, "The interface the proxied message was delivered to.", "ListenInterface", "Interface"),
    CLIENT_IP(FieldGroup.ENTRY, String.class, "The requesting client IP address.", "ClientIP", "ClientAddress"),

    //Request,
    BASE64_REQUEST(FieldGroup.REQUEST, String.class, "The entire request encoded in Base64", "AsBase64"),
    REQUEST_HEADERS(FieldGroup.REQUEST, String.class, "The request line and associated headers.", "Headers", "Header"),
    REQUEST_BODY(FieldGroup.REQUEST, String.class, "The request body.", "Body"),
    REQUEST_BODY_LENGTH(FieldGroup.REQUEST, String.class, "The request body's length.", "BodyLength"),
    REQUEST_TIME(FieldGroup.REQUEST, Date.class, "Date and time of inital request (as received by L++).", "Time"),
    REQUEST_LENGTH(FieldGroup.REQUEST, Integer.class, "The length of the received request.", "Length"),
    REQUEST_TOOL(FieldGroup.REQUEST, String.class, "The tool used to initiate the request.", "Tool"), //Alias for proxy.tool,
    COMMENT(FieldGroup.REQUEST, String.class, "Comments set on the entry.", "Comment"),
    COMPLETE(FieldGroup.REQUEST, Boolean.class, "Has a response been received?", "Complete", "isComplete"),
    URL(FieldGroup.REQUEST, String.class, "The entire URL of the request.", "URL", "URI"),
    METHOD(FieldGroup.REQUEST, String.class, "The request method used.", "Method"),
    PATH(FieldGroup.REQUEST, String.class, "The path component of the requested URL.", "Path"),
    QUERY(FieldGroup.REQUEST, String.class, "The query parameters of the requested URL.", "Query", "GetParams", "QueryParams"),
    PATHQUERY(FieldGroup.REQUEST, String.class, "The path and query components of the requested URL.", "PathQuery"),
    PROTOCOL(FieldGroup.REQUEST, String.class, "The protocol component of the requested URL.", "Protocol"),
    ISSSL(FieldGroup.REQUEST, Boolean.class, "Did the request use SSL?", "IsSSL", "ssl"),
    USES_COOKIE_JAR(FieldGroup.REQUEST, String.class, "Compares the cookies with the cookie jar to see if any of them are in use.", "UsesCookieJar", "CookieJar"),
    HOSTNAME(FieldGroup.REQUEST, String.class, "The hostname component of the requested URL.", "Hostname"),
    HOST(FieldGroup.REQUEST, String.class, "The protocol and hostname of the requested URL.", "Host"),
    PORT(FieldGroup.REQUEST, Short.class, "The port the request was sent to.", "Port"),
    REQUEST_CONTENT_TYPE(FieldGroup.REQUEST, String.class, "The content-type header sent to the server.", "ContentType", "Content_Type"),
    REQUEST_HTTP_VERSION(FieldGroup.REQUEST, Short.class, "The HTTP version sent in the request.", "RequestHttpVersion", "RequestHttpVersion"),
    EXTENSION(FieldGroup.REQUEST, String.class, "The URL extension used in the request.", "Extension"),
    REFERRER(FieldGroup.REQUEST, String.class, "The referrer header value of the request.", "Referrer"),
    HASPARAMS(FieldGroup.REQUEST, Boolean.class, "Did the request contain parameters?", "HasParams"),
    HASGETPARAM(FieldGroup.REQUEST, Boolean.class, "Did the request contain get parameters?", "HasGetParam", "HasGetParams", "HasQueryString"),
    HASPOSTPARAM(FieldGroup.REQUEST, Boolean.class, "Did the request contain post parameters?", "HasPostParam", "HasPayload", "Payload"),
    HASCOOKIEPARAM(FieldGroup.REQUEST, Boolean.class, "Did the request contain cookies?", "HasSentCookies"),
    SENTCOOKIES(FieldGroup.REQUEST, Boolean.class, "The value of the cookies header sent to the server.", "CookieString", "SentCookies", "Cookies"),
    PARAMETER_COUNT(FieldGroup.REQUEST, Integer.class, "The number of parameters in the request.", "ParameterCount", "ParamCount"),
    PARAMETERS(FieldGroup.REQUEST, String.class, "The parameters in the request.", "Parameters", "Params"),
    ORIGIN(FieldGroup.REQUEST, String.class, "The Origin header", "Origin"),

    //Response
    BASE64_RESPONSE(FieldGroup.RESPONSE, String.class, "The entire response encoded in Base64", "AsBase64"),
    RESPONSE_HEADERS(FieldGroup.RESPONSE, String.class, "The status line and associated headers.", "Headers", "Header"),
    RESPONSE_BODY(FieldGroup.RESPONSE, String.class, "The response body.", "Body"),
    RESPONSE_BODY_LENGTH(FieldGroup.RESPONSE, String.class, "The response body's length.", "BodyLength"),
    RESPONSE_HASH(FieldGroup.RESPONSE, String.class, "SHA1 Hash of the response", "hash", "sha1"),
    RESPONSE_TIME(FieldGroup.RESPONSE, Date.class, "Date and time of receiving the response (as received by L++).", "Time"),
    RESPONSE_LENGTH(FieldGroup.RESPONSE, Integer.class, "The length of the received response.", "Length"),
    REDIRECT_URL(FieldGroup.RESPONSE, URL.class, "The URL the response redirects to.", "Redirect", "RedirectURL"),
    STATUS(FieldGroup.RESPONSE, Short.class, "The status code received in the response.", "Status", "StatusCode"),
    STATUS_TEXT(FieldGroup.RESPONSE, Short.class, "The status text received in the response.", "StatusText", "StatusText"),
    RESPONSE_HTTP_VERSION(FieldGroup.RESPONSE, Short.class, "The HTTP version received in the response.", "ResponseHttpVersion", "ResponseHttpVersion"),
    RTT(FieldGroup.RESPONSE, Integer.class, "The round trip time (as calculated by L++, not 100% accurate).", "RTT", "TimeTaken"),
    TITLE(FieldGroup.RESPONSE, String.class, "The HTTP response title.", "Title"),
    RESPONSE_CONTENT_TYPE(FieldGroup.RESPONSE, String.class, "The content-type header sent by the server.", "ContentType", "Content_Type"),
    INFERRED_TYPE(FieldGroup.RESPONSE, String.class, "The type inferred by the response content.", "InferredType", "Inferred_Type"),
    MIME_TYPE(FieldGroup.RESPONSE, String.class, "The mime-type stated by the server.", "MimeType", "Mime"),
    HAS_SET_COOKIES(FieldGroup.RESPONSE, Boolean.class, "Did the response set cookies?", "HasSetCookies", "DidSetCookies"),
    NEW_COOKIES(FieldGroup.RESPONSE, String.class, "The new cookies sent by the server", "Cookies", "NewCookies", "New_Cookies", "SetCookies"),
    REFLECTED_PARAMS(FieldGroup.RESPONSE, String.class, "Values reflected in the response", "ReflectedParams", "ReflectedParameters"),
    REFLECTION_COUNT(FieldGroup.RESPONSE, Integer.class, "Number of values reflected in the response", "Reflections", "ReflectionCount", "ReflectedCount");

    private static final HashMap<FieldGroup, HashMap<String, LogEntryField>> completeGroupFieldMap = new HashMap<>();
    private static final HashMap<FieldGroup, HashMap<String, LogEntryField>> shortGroupFieldMap = new HashMap<>();

    static {
        for (FieldGroup fieldGroup : FieldGroup.values()) {
            completeGroupFieldMap.put(fieldGroup, new LinkedHashMap<>());
            shortGroupFieldMap.put(fieldGroup, new LinkedHashMap<>());
        }

        for (LogEntryField field : LogEntryField.values()) {
            shortGroupFieldMap.get(field.fieldGroup).put(field.labels[0], field);
            for (String label : field.labels) {
                completeGroupFieldMap.get(field.fieldGroup).put(label.toLowerCase(), field);
            }
        }
    }


    private FieldGroup fieldGroup;
    private Class<?> type;
    private String description;
    private String[] labels;

    
    LogEntryField(FieldGroup fieldGroup, Class<?> type, String description, String... labels){
        this.fieldGroup = fieldGroup;
        this.type = type;
        this.description = description;
        this.labels = labels;
    }

    public FieldGroup getFieldGroup() {
        return fieldGroup;
    }

    public Class<?> getType() {
        return type;
    }

    public String[] getLabels() {
        return labels;
    }

    public String getFullLabel(String label){
        return this.fieldGroup.getLabel() + "." + label;
    }

    public String getFullLabel(){
        return this.fieldGroup.getLabel() + "." + labels[0];
    }

    public static LogEntryField getByLabel(FieldGroup fieldGroup, String searchLabel){
        HashMap<String, LogEntryField> groupFields = completeGroupFieldMap.get(fieldGroup);
        return groupFields != null ? groupFields.get(searchLabel.toLowerCase()) : null;
    }

    public static Collection<LogEntryField> getFieldsInGroup(FieldGroup fieldGroup){
        return shortGroupFieldMap.get(fieldGroup).values();
    }

    public static LogEntryField getByFullyQualifiedName(String fqn){
        String[] split = fqn.split("\\.");
        FieldGroup group = FieldGroup.findByLabel(split[0]);
        return getByLabel(group, split[1]);
    }

    public String getDescription() {
        return description;
    }

    public String getDescriptiveMessage(){
        return String.format("Field: <b>%s</b>\nType: %s\nDescription: %s", String.join(", ", labels), type.getSimpleName(), description);
    }

    @Override
    public String toString() {
        //TODO Better output for alternatives in error messages
        return getFullLabel();
    }
}
