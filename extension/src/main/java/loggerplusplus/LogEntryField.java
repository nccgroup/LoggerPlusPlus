package loggerplusplus;

public enum LogEntryField {
    A,

    private LogEntryField(){

    }


    public enum Proxy {
        TOOL,
        LISTENER_INTERFACE,
        CLIENT_IP,
        USES_COOKIE_JAR,
        COMMENT,
    }

    public enum Request {
        COMPLETE,
        URL,
        METHOD,
        PATH,
        QUERY,
        PROTOCOL,
        ISSSL,
        HOSTNAME,
        HOST,
        PORT,
        TIME,
        LENGTH,
        CONTENTTYPE,
        EXTENSION,
        REFERRER,
        HASPARAMS,
        HASGETPARAM,
        HASPOSTPARAM,
        HASCOOKIEPARAM,
        SENTCOOKIES,

        HEADERS,
        BODY
    }

    public enum Response {
        STATUS,
        LENGTH,
        RTT,
        TIME,
        TITLE,
        CONTENT_TYPE,
        MIME_TYPE,
        INFERRED_TYPE,
        HAS_SET_COOKIES,
        NEW_COOKIES,

        HEADERS,
        BODY
    }


}
