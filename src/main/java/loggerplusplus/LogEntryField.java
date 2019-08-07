package loggerplusplus;

import java.util.Date;
import java.util.HashMap;

public enum LogEntryField {

    //Proxy
    NUMBER(Group.PROXY, Integer.class, "Number"),
    TOOL(Group.PROXY, String.class, "Tool"),
    LISTENER_INTERFACE(Group.PROXY, String.class, "ListenInterface", "Interface"),
    CLIENT_IP(Group.PROXY, String.class, "ClientIP", "ClientAddress"),
    USES_COOKIE_JAR(Group.PROXY, String.class, "UsesCookieJar", "CookieJar"),
    COMMENT(Group.PROXY, String.class, "Comment"),

    //Request + Response
    REQUEST_HEADERS(Group.REQUEST, String.class, "Headers"),
    RESPONSE_HEADERS(Group.RESPONSE, String.class, "Headers"),
    REQUEST_BODY(Group.REQUEST, String.class, "Body"),
    RESPONSE_BODY(Group.RESPONSE, String.class, "Body"),
    REQUEST_TIME(Group.REQUEST, Date.class, "Time"),
    RESPONSE_TIME(Group.RESPONSE, Date.class, "Time"),
    REQUEST_LENGTH(Group.REQUEST, Integer.class, "Length"),
    RESPONSE_LENGTH(Group.RESPONSE, Integer.class, "Length"),


    //Request
    COMPLETE(Group.REQUEST, Boolean.class, "Complete"),
    URL(Group.REQUEST, String.class, "URL"),
    METHOD(Group.REQUEST, String.class, "Method"),
    PATH(Group.REQUEST, String.class, "Path"),
    QUERY(Group.REQUEST, String.class, "Query"),
    PROTOCOL(Group.REQUEST, String.class, "Protocol"),
    ISSSL(Group.REQUEST, Boolean.class, "IsSSL"),
    HOSTNAME(Group.REQUEST, String.class, "Hostname"),
    HOST(Group.REQUEST, String.class, "Host"),
    PORT(Group.REQUEST, Short.class, "Port"),
    REQUEST_CONTENT_TYPE(Group.REQUEST, String.class, "ContentType", "Content_Type"),
    EXTENSION(Group.REQUEST, String.class, "Extension"),
    REFERRER(Group.REQUEST, String.class, "Referrer"),
    HASPARAMS(Group.REQUEST, Boolean.class, "HasParams"),
    HASGETPARAM(Group.REQUEST, Boolean.class, "HasGetParam", "HasQueryString", "QueryString"),
    HASPOSTPARAM(Group.REQUEST, Boolean.class, "HasPostParam", "HasPayload", "Payload"),
    HASCOOKIEPARAM(Group.REQUEST, Boolean.class, "HasSentCookies"),
    SENTCOOKIES(Group.REQUEST, Boolean.class, "CookieString", "SentCookies"),


    //Response
    STATUS(Group.RESPONSE, Short.class, "Status"),
    RTT(Group.RESPONSE, Integer.class, "RTT", "TimeTaken"),
    TITLE(Group.RESPONSE, String.class, "Title"),
    RESPONSE_CONTENT_TYPE(Group.RESPONSE, String.class, "ContentType", "Content_Type"),
    MIME_TYPE(Group.RESPONSE, String.class, "MimeType", "Mime_Type"),
    INFERRED_TYPE(Group.RESPONSE, String.class, "InferredType", "Inferred_Type"),
    HAS_SET_COOKIES(Group.RESPONSE, Boolean.class, "HasSetCookies", "Has_Set_Cookies"),
    NEW_COOKIES(Group.RESPONSE, String.class, "NewCookies", "New_Cookies");

    private static final HashMap<Group, HashMap<String, LogEntryField>> completeGroupFieldMap = new HashMap<>();
    private static final HashMap<Group, HashMap<String, LogEntryField>> shortGroupFieldMap = new HashMap<>();

    static {
        for (Group group : Group.values()) {
            completeGroupFieldMap.put(group, new HashMap<>());
            shortGroupFieldMap.put(group, new HashMap<>());
        }

        for (LogEntryField field : LogEntryField.values()) {
            shortGroupFieldMap.get(field.group).put(field.labels[0].toUpperCase(), field);
            for (String label : field.labels) {
                completeGroupFieldMap.get(field.group).put(label.toUpperCase(), field);
            }
        }
    }


    public enum Group{
        PROXY("Proxy"),
        REQUEST("Request"),
        RESPONSE("Response");
        private String label;

        private static final HashMap<String, Group> groupLabelMap = new HashMap<>();
        static {
            for (Group group : Group.values()) {
                groupLabelMap.put(group.label.toUpperCase(), group);
            }
        }

        Group(String label){
            this.label = label;
        }

        public String getLabel() {
            return label;
        }

        public static Group findByLabel(String label){
            return groupLabelMap.get(label.toUpperCase());
        }
    }

    private Group group;
    private Class type;
    private String[] labels;

    
    LogEntryField(Group group, Class type, String... labels){
        this.group = group;
        this.type = type;
        this.labels = labels;
    }

    public Group getGroup() {
        return group;
    }

    public Class getType() {
        return type;
    }

    public String[] getLabels() {
        return labels;
    }

    public String getFullLabel(String label){
        return this.group.getLabel() + "." + label;
    }

    public String getFullLabel(){
        return this.group.getLabel() + "." + labels[0];
    }

    public static LogEntryField getByLabel(Group group, String searchLabel){
        HashMap<String, LogEntryField> groupFields = completeGroupFieldMap.get(group);
        return groupFields != null ? groupFields.get(searchLabel.toUpperCase()) : null;
    }

    public static HashMap<String, LogEntryField> getFieldsInGroup(Group group){
        return completeGroupFieldMap.get(group);
    }
}
