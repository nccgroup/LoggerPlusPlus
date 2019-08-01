package loggerplusplus;

import java.lang.reflect.Type;
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
    REQUEST_TIME(Group.REQUEST, Integer.class, "Time"),
    RESPONSE_TIME(Group.RESPONSE, Integer.class, "Time"),
    REQUEST_LENGTH(Group.REQUEST, Integer.class, "Length"),
    RESPONSE_LENGTH(Group.RESPONSE, Integer.class, "Length"),


    //Request
    COMPLETE(Group.REQUEST, Boolean.class, "Complete"),
    URL(Group.REQUEST, String.class, "URL"),
    METHOD(Group.REQUEST, String.class, "Method"),
    PATH(Group.REQUEST, String.class, "Path"),
    QUERY(Group.REQUEST, String.class, "QUERY"),
    PROTOCOL(Group.REQUEST, String.class, "PROTOCOL"),
    ISSSL(Group.REQUEST, Boolean.class, "ISSSL"),
    HOSTNAME(Group.REQUEST, String.class, "HOSTNAME"),
    HOST(Group.REQUEST, String.class, "HOST"),
    PORT(Group.REQUEST, Short.class, "PORT"),
    REQUEST_CONTENT_TYPE(Group.REQUEST, String.class, "CONTENTTYPE", "CONTENT_TYPE"),
    EXTENSION(Group.REQUEST, String.class, "EXTENSION"),
    REFERRER(Group.REQUEST, String.class, "REFERRER"),
    HASPARAMS(Group.REQUEST, Boolean.class, "HASPARAMS"),
    HASGETPARAM(Group.REQUEST, Boolean.class, "HASGETPARAM", "HASQUERYSTRING", "QUERYSTRING"),
    HASPOSTPARAM(Group.REQUEST, Boolean.class, "HASPOSTPARAM", "HASPAYLOAD", "PAYLOAD"),
    HASCOOKIEPARAM(Group.REQUEST, Boolean.class, "HASCOOKIEPARAM"),
    SENTCOOKIES(Group.REQUEST, Boolean.class, "SENTCOOKIES"),


    //Response
    STATUS(Group.RESPONSE, Short.class, "STATUS"),
    RTT(Group.RESPONSE, Integer.class, "RTT"),
    TITLE(Group.RESPONSE, String.class, "TITLE"),
    RESPONSE_CONTENT_TYPE(Group.RESPONSE, String.class, "CONTENTTYPE", "CONTENT_TYPE"),
    MIME_TYPE(Group.RESPONSE, String.class, "MIME_TYPE", "MIMETYPE"),
    INFERRED_TYPE(Group.RESPONSE, String.class, "INFERRED_TYPE", "INFERREDTYPE"),
    HAS_SET_COOKIES(Group.RESPONSE, Boolean.class, "HAS_SET_COOKIES", "SETCOOKIES", "HASSETCOOKIES"),
    NEW_COOKIES(Group.RESPONSE, String.class, "NEW_COOKIES", "NEWCOOKIES");

    private static final HashMap<Group, HashMap<String, LogEntryField>> groupFieldMap = new HashMap<>();
    static {
        for (Group group : Group.values()) {
            groupFieldMap.put(group, new HashMap<>());
        }

        for (LogEntryField field : LogEntryField.values()) {
            for (String label : field.labels) {
                groupFieldMap.get(field.group).put(label.toUpperCase(), field);
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

    public static LogEntryField getByLabel(Group group, String searchLabel){
        HashMap<String, LogEntryField> groupFields = groupFieldMap.get(group);
        return groupFields != null ? groupFields.get(searchLabel.toUpperCase()) : null;
    }

    public static HashMap<String, LogEntryField> getFieldsInGroup(Group group){
        return groupFieldMap.get(group);
    }

}
