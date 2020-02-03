package com.nccgroup.loggerplusplus.logentry;

import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;

public enum LogEntryField {

    //Proxy
    NUMBER(FieldGroup.PROXY, Integer.class, "Number"),
    PROXY_TOOL(FieldGroup.PROXY, String.class, "Tool"),
    LISTENER_INTERFACE(FieldGroup.PROXY, String.class, "ListenInterface", "Interface"),
    CLIENT_IP(FieldGroup.PROXY, String.class, "ClientIP", "ClientAddress"),
    USES_COOKIE_JAR_PROXY(FieldGroup.PROXY, String.class, "UsesCookieJar", "CookieJar"),
    COMMENT(FieldGroup.PROXY, String.class, "Comment"),

    //Request + Response
    REQUEST_HEADERS(FieldGroup.REQUEST, String.class, "Headers"),
    RESPONSE_HEADERS(FieldGroup.RESPONSE, String.class, "Headers"),
    REQUEST_BODY(FieldGroup.REQUEST, String.class, "Body"),
    RESPONSE_BODY(FieldGroup.RESPONSE, String.class, "Body"),
    REQUEST_TIME(FieldGroup.REQUEST, Date.class, "Time"),
    RESPONSE_TIME(FieldGroup.RESPONSE, Date.class, "Time"),
    REQUEST_LENGTH(FieldGroup.REQUEST, Integer.class, "Length"),
    RESPONSE_LENGTH(FieldGroup.RESPONSE, Integer.class, "Length"),


    //Request
    REQUEST_TOOL(FieldGroup.REQUEST, String.class, "Tool"), //Alias for proxy.tool
    COMPLETE(FieldGroup.REQUEST, Boolean.class, "Complete", "isComplete"),
    URL(FieldGroup.REQUEST, String.class, "URL"),
    METHOD(FieldGroup.REQUEST, String.class, "Method"),
    PATH(FieldGroup.REQUEST, String.class, "Path"),
    QUERY(FieldGroup.REQUEST, String.class, "Query"),
    PROTOCOL(FieldGroup.REQUEST, String.class, "Protocol"),
    ISSSL(FieldGroup.REQUEST, Boolean.class, "IsSSL", "ssl"),
    REQUEST_USES_COOKIE_JAR(FieldGroup.REQUEST, String.class, "UsesCookieJar", "CookieJar"), //Alias for proxy.usescookiejar
    HOSTNAME(FieldGroup.REQUEST, String.class, "Hostname"),
    HOST(FieldGroup.REQUEST, String.class, "Host"),
    PORT(FieldGroup.REQUEST, Short.class, "Port"),
    REQUEST_CONTENT_TYPE(FieldGroup.REQUEST, String.class, "ContentType", "Content_Type"),
    EXTENSION(FieldGroup.REQUEST, String.class, "Extension"),
    REFERRER(FieldGroup.REQUEST, String.class, "Referrer"),
    HASPARAMS(FieldGroup.REQUEST, Boolean.class, "HasParams", "Has_Params"),
    HASGETPARAM(FieldGroup.REQUEST, Boolean.class, "HasGetParam", "HasQueryString", "QueryString"),
    HASPOSTPARAM(FieldGroup.REQUEST, Boolean.class, "HasPostParam", "HasPayload", "Payload"),
    HASCOOKIEPARAM(FieldGroup.REQUEST, Boolean.class, "HasSentCookies"),
    SENTCOOKIES(FieldGroup.REQUEST, Boolean.class, "CookieString", "SentCookies", "Cookies"),


    //Response
    STATUS(FieldGroup.RESPONSE, Short.class, "Status"),
    RTT(FieldGroup.RESPONSE, Integer.class, "RTT", "TimeTaken"),
    TITLE(FieldGroup.RESPONSE, String.class, "Title"),
    RESPONSE_CONTENT_TYPE(FieldGroup.RESPONSE, String.class, "ContentType", "Content_Type"),
    MIME_TYPE(FieldGroup.RESPONSE, String.class, "MimeType", "Mime_Type"),
    INFERRED_TYPE(FieldGroup.RESPONSE, String.class, "InferredType", "Inferred_Type"),
    HAS_SET_COOKIES(FieldGroup.RESPONSE, Boolean.class, "HasSetCookies", "Has_Set_Cookies"),
    NEW_COOKIES(FieldGroup.RESPONSE, String.class, "NewCookies", "New_Cookies");

    private static final HashMap<FieldGroup, HashMap<String, LogEntryField>> completeGroupFieldMap = new HashMap<>();
    private static final HashMap<FieldGroup, HashMap<String, LogEntryField>> shortGroupFieldMap = new HashMap<>();

    static {
        for (FieldGroup fieldGroup : FieldGroup.values()) {
            completeGroupFieldMap.put(fieldGroup, new HashMap<>());
            shortGroupFieldMap.put(fieldGroup, new HashMap<>());
        }

        for (LogEntryField field : LogEntryField.values()) {
            shortGroupFieldMap.get(field.fieldGroup).put(field.labels[0].toUpperCase(), field);
            for (String label : field.labels) {
                completeGroupFieldMap.get(field.fieldGroup).put(label.toUpperCase(), field);
            }
        }
    }


    private FieldGroup fieldGroup;
    private Class<?> type;
    private String[] labels;

    
    LogEntryField(FieldGroup fieldGroup, Class<?> type, String... labels){
        this.fieldGroup = fieldGroup;
        this.type = type;
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
        return groupFields != null ? groupFields.get(searchLabel.toUpperCase()) : null;
    }

    public static HashMap<String, LogEntryField> getFieldsInGroup(FieldGroup fieldGroup){
        return completeGroupFieldMap.get(fieldGroup);
    }

    public static LogEntryField getByFullyQualifiedName(String fqn){
        String[] split = fqn.split("\\.");
        FieldGroup group = FieldGroup.findByLabel(split[0]);
        return getByLabel(group, split[1]);
    }

    @Override
    public String toString() {
        //TODO Better output for alternatives in error messages
        return getFullLabel();
    }
}
