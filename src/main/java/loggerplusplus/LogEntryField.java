package loggerplusplus;

public enum LogEntryField {

    //Proxy
    TOOL(Group.PROXY, "Tool"),
    LISTENER_INTERFACE(Group.PROXY, "ListenInterface", "Interface"),
    CLIENT_IP(Group.PROXY, "ClientIP", "ClientAddress"),
    USES_COOKIE_JAR(Group.PROXY, "UsesCookieJar", "CookieJar"),
    COMMENT(Group.PROXY, "Comment"),

    //Request + Response
    REQUEST_HEADERS(Group.REQUEST, "Headers"),
    RESPONSE_HEADERS(Group.RESPONSE, "Headers"),
    REQUEST_BODY(Group.REQUEST, "Body"),
    RESPONSE_BODY(Group.RESPONSE, "Body"),
    REQUEST_TIME(Group.REQUEST, "Time"),
    RESPONSE_TIME(Group.RESPONSE, "Time"),
    REQUEST_LENGTH(Group.REQUEST, "Length"),
    RESPONSE_LENGTH(Group.RESPONSE, "Length"),


    //Request
    COMPLETE(Group.REQUEST, "Complete"),
    URL(Group.REQUEST, "URL"),
    METHOD(Group.REQUEST, "Method"),
    PATH(Group.REQUEST, "Path"),
    QUERY(Group.REQUEST, "QUERY"),
    PROTOCOL(Group.REQUEST, "PROTOCOL"),
    ISSSL(Group.REQUEST, "ISSSL"),
    HOSTNAME(Group.REQUEST, "HOSTNAME"),
    HOST(Group.REQUEST, "HOST"),
    PORT(Group.REQUEST, "PORT"),
    CONTENTTYPE(Group.REQUEST, "CONTENTTYPE"),
    EXTENSION(Group.REQUEST, "EXTENSION"),
    REFERRER(Group.REQUEST, "REFERRER"),
    HASPARAMS(Group.REQUEST, "HASPARAMS"),
    HASGETPARAM(Group.REQUEST, "HASGETPARAM"),
    HASPOSTPARAM(Group.REQUEST, "HASPOSTPARAM"),
    HASCOOKIEPARAM(Group.REQUEST, "HASCOOKIEPARAM"),
    SENTCOOKIES(Group.REQUEST, "SENTCOOKIES"),


    //Response
    STATUS(Group.RESPONSE, "STATUS"),
    RTT(Group.RESPONSE, "RTT"),
    TITLE(Group.RESPONSE, "TITLE"),
    CONTENT_TYPE(Group.RESPONSE, "CONTENT_TYPE"),
    MIME_TYPE(Group.RESPONSE, "MIME_TYPE"),
    INFERRED_TYPE(Group.RESPONSE, "INFERRED_TYPE"),
    HAS_SET_COOKIES(Group.RESPONSE, "HAS_SET_COOKIES"),
    NEW_COOKIES(Group.RESPONSE, "NEW_COOKIES");

    public enum Group{
        PROXY("Proxy"),
        REQUEST("Request"),
        RESPONSE("Response");
        private String label;

        Group(String label){
            this.label = label;
        }
    }

    private Group group;
    private String[] labels;

    
    LogEntryField(Group group, String... labels){
        this.group = group;
        this.labels = labels;
    }

    LogEntryField getByLabel(String searchLabel){
        for (LogEntryField field : LogEntryField.values()) {
            for (String label : field.labels) {
                if(label.equalsIgnoreCase(searchLabel)) return field;
            }
        }
        return null;
    }


}
