package com.nccgroup.loggerplusplus.util;

import java.util.regex.Pattern;
import static com.nccgroup.loggerplusplus.logentry.LogEntryField.*;

public class Globals {
    public static final String APP_NAME = "Logger++";
    public static final double VERSION = 3.18;
    public static final String AUTHOR = "Corey Arthur (@CoreyD97), Soroush Dalili (@irsdl) from NCC Group";
    public static final String TWITTER_URL = "https://twitter.com/CoreyD97";
    public static final String IRSDL_TWITTER_URL = "https://twitter.com/irsdl";
    public static final String NCC_TWITTER_URL = "https://twitter.com/nccgroup";
    public static final String COMPANY_LINK = "https://www.nccgroup.trust/";
    public static final String GITHUB_URL = "https://github.com/nccgroup/LoggerPlusPlus";
    public static final String GITHUB_FEATURE_URL = "https://github.com/nccgroup/LoggerPlusPlus/issues/new?assignees=CoreyD97&labels=enhancement&template=feature_request.md&title=";
    public static final String GITHUB_BUG_URL = "https://github.com/nccgroup/LoggerPlusPlus/issues/new?assignees=CoreyD97&labels=bug&template=bug_report.md&title=v" + VERSION + "%20-%20Bug:%20YOUR_TITLE_HERE";
    public static final String PROJECT_ISSUE_LINK = "https://github.com/nccgroup/LoggerPlusPlus/issues";
    public static final String CHANGELOG = "https://raw.githubusercontent.com/NCCGroup/LoggerPlusPlus/master/CHANGELOG";
    public static final String UPDATE_URL = "https://raw.githubusercontent.com/NCCGroup/LoggerPlusPlus/releases/burplogger++.jar";

    //Preferences Keys
    public static final String PREF_LOG_TABLE_SETTINGS = "tabledetailsjson";
    public static final String PREF_IS_DEBUG = "isDebug";
    public static final String PREF_UPDATE_ON_STARTUP = "updateonstartup";
    public static final String PREF_ENABLED = "enabled";
    public static final String PREF_RESTRICT_TO_SCOPE = "restricttoscope";
    public static final String PREF_LOG_GLOBAL = "logglobal";
    public static final String PREF_LOG_PROXY = "logproxy";
    public static final String PREF_LOG_SPIDER = "logspider";
    public static final String PREF_LOG_INTRUDER = "logintruder";
    public static final String PREF_LOG_SCANNER = "logscanner";
    public static final String PREF_LOG_REPEATER = "logrepeater";
    public static final String PREF_LOG_SEQUENCER = "logsequencer";
    public static final String PREF_LOG_EXTENDER = "logextender";
    public static final String PREF_LOG_TARGET_TAB = "logtargettab";
    public static final String PREF_COLOR_FILTERS = "colorfilters";
    public static final String PREF_SAVED_FILTERS = "savedfilters";
    public static final String PREF_SORT_COLUMN = "sortcolumn";
    public static final String PREF_SORT_ORDER = "sortorder";
    public static final String PREF_RESPONSE_TIMEOUT = "responsetimeout";
    public static final String PREF_MAXIMUM_ENTRIES = "maximumentries";
    public static final String PREF_LAYOUT = "layout";
    public static final String PREF_MESSAGE_VIEW_LAYOUT = "msgviewlayout";
    public static final String PREF_SEARCH_THREADS = "searchthreads";
    public static final String PREF_AUTO_IMPORT_PROXY_HISTORY = "autoimportproxyhistory";
    public static final String PREF_ELASTIC_ADDRESS = "esAddress";
    public static final String PREF_ELASTIC_PORT = "esPort";
    public static final String PREF_ELASTIC_PROTOCOL = "esProto";
    public static final String PREF_ELASTIC_CLUSTER_NAME = "esClusterName";
    public static final String PREF_ELASTIC_INDEX = "esIndex";
    public static final String PREF_ELASTIC_DELAY = "esDelay";
    public static final String PREF_ELASTIC_INCLUDE_REQ_RESP = "esIncludeReqResp";
    public static final String PREF_LOG_OTHER_LIVE = "otherToolLiveLogging";
    public static final String PREF_FILTER_HISTORY = "filterHistory";
    public static final String PREF_AUTO_SAVE = "autoSave";
    public static final String PREF_AUTO_SCROLL = "autoScroll";
    public static final String PREF_GREP_HISTORY = "grepHistory";
    public static final String PREF_PREVIOUS_EXPORT_FIELDS = "previousExportFields";
    public static final String PREF_PREVIOUS_ELASTIC_FIELDS = "previousElasticFields";
    public static final String PREF_SAVED_FIELD_SELECTIONS = "savedFieldSelections";

    public enum Protocol {HTTP, HTTPS}

    public static final String DEFAULT_COLOR_FILTERS_JSON = "{\"2add8ace-b652-416a-af08-4d78c5d22bc7\":{\"uid\":\"2add8ace-b652-416a-af08-4d78c5d22bc7\"," +
            "\"filter\":{\"filter\":\"Request.Complete == False\"},\"filterString\":\"Request.Complete == False\",\"backgroundColor\":{\"value\":-16777216,\"falpha\":0.0}," +
            "\"foregroundColor\":{\"value\":-65536,\"falpha\":0.0},\"enabled\":true,\"modified\":false,\"shouldRetest\":true,\"priority\":1}}";
    
    private static int colOrder = 0;
    public static final String DEFAULT_LOG_TABLE_COLUMNS_JSON = new StringBuilder().append("[")
        .append("{'id':" + NUMBER + ",'name':'Number','defaultVisibleName':'#','visibleName':'#','preferredWidth':65,'type':'int','readonly':true,'order':" + colOrder++ + ",'visible':true,'description':'Item index number','isRegEx':false,'regExString':'','regExCaseSensitive':false},")
        .append("{'id':" + COMPLETE + ",'name':'Complete','defaultVisibleName':'Complete','visibleName':'Complete','preferredWidth':80,'type':'boolean','readonly':true,'order':" + colOrder++ + ",'visible':true,'description':'Indicates if a response has been received.','isRegEx':false,'regExString':'','regExCaseSensitive':false},")
        .append("{'id':" + PROXY_TOOL + ",'name':'Tool','defaultVisibleName':'Tool','visibleName':'Tool','preferredWidth':70,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':true,'description':'Tool name','isRegEx':false,'regExString':'','regExCaseSensitive':false},")
        .append("{'id':" + METHOD + ",'name':'Method','defaultVisibleName':'Method','visibleName':'Method','preferredWidth':65,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':true,'description':'HTTP request method','isRegEx':false,'regExString':'','regExCaseSensitive':false},")
        .append("{'id':" + HASPARAMS + ",'name':'Has Params','defaultVisibleName':'Has Params','visibleName':'Has Params','preferredWidth':75,'type':'boolean','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Indicates whether or not the request has GET or POST parameter(s)','isRegEx':false,'regExString':'','regExCaseSensitive':false},")
        .append("{'id':" + PROTOCOL + ",'name':'Protocol','defaultVisibleName':'Protocol','visibleName':'Protocol','preferredWidth':80,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Shows the request protocol','isRegEx':false,'regExString':'','regExCaseSensitive':false},")
        .append("{'id':" + ISSSL + ",'name':'IsSSL','defaultVisibleName':'SSL','visibleName':'SSL','preferredWidth':50,'type':'boolean','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Indicates whether or not the HTTP protocol is HTTPS','isRegEx':false,'regExString':'','regExCaseSensitive':false},")
        .append("{'id':" + HOSTNAME + ",'name':'Hostname','defaultVisibleName':'Host Name','visibleName':'Host Name','preferredWidth':150,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Shows the request host name','isRegEx':false,'regExString':'','regExCaseSensitive':false},")
        .append("{'id':" + PORT + ",'name':'TargetPort','defaultVisibleName':'Port','visibleName':'Port','preferredWidth':50,'type':'int','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Shows the target port number','isRegEx':false,'regExString':'','regExCaseSensitive':false},")
        .append("{'id':" + HOST + ",'name':'Host','defaultVisibleName':'Host','visibleName':'Host','preferredWidth':150,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':true,'description':'Host and Protocol (similar to the Proxy tab)','isRegEx':false,'regExString':'','regExCaseSensitive':false},")
        .append("{'id':" + PATH + ",'name':'Path','defaultVisibleName':'Path','visibleName':'Path','preferredWidth':250,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':true,'description':'Request Path','isRegEx':false,'regExString':'','regExCaseSensitive':false},")
        .append("{'id':" + EXTENSION + ",'name':'UrlExtension','defaultVisibleName':'Extension','visibleName':'Extension','preferredWidth':70,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Target page extension','isRegEx':false,'regExString':'','regExCaseSensitive':false},")
        .append("{'id':" + QUERY + ",'name':'Query','defaultVisibleName':'Query','visibleName':'Query','preferredWidth':250,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':true,'description':'Query Parameters','isRegEx':false,'regExString':'','regExCaseSensitive':false},")
        .append("{'id':" + STATUS + ",'name':'Status','defaultVisibleName':'Status','visibleName':'Status','preferredWidth':55,'type':'short','readonly':true,'order':" + colOrder++ + ",'visible':true,'description':'Response status header','isRegEx':false,'regExString':'','regExCaseSensitive':false},")
        .append("{'id':" + REQUEST_LENGTH + ",'name':'RequestLength','defaultVisibleName':'Request Length','visibleName':'Request Length','preferredWidth':150,'type':'int','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Shows the request body length','isRegEx':false,'regExString':'','regExCaseSensitive':false},")
        .append("{'id':" + RESPONSE_LENGTH + ",'name':'ResponseLength','defaultVisibleName':'Response Length','visibleName':'Response Length','preferredWidth':125,'type':'int','readonly':true,'order':" + colOrder++ + ",'visible':true,'description':'Length of response','isRegEx':false,'regExString':'','regExCaseSensitive':false},")
        .append("{'id':" + INFERRED_TYPE + ",'name':'InferredType','defaultVisibleName':'Inferred Type','visibleName':'Inferred Type','preferredWidth':100,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':true,'description':'Shows the content type which was inferred by Burp','isRegEx':false,'regExString':'','regExCaseSensitive':false},")
        .append("{'id':" + COMMENT + ",'name':'Comment','defaultVisibleName':'Comment','visibleName':'Comment','preferredWidth':200,'type':'string','readonly':false,'order':" + colOrder++ + ",'visible':true,'description':'Editable comment','isRegEx':false,'regExString':'','regExCaseSensitive':false},")
        .append("{'id':" + URL + ",'name':'Url','defaultVisibleName':'URL','visibleName':'URL','preferredWidth':250,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Complete URL','isRegEx':false,'regExString':'','regExCaseSensitive':false},")
        .append("{'id':" + MIME_TYPE + ",'name':'MimeType','defaultVisibleName':'MIME type','visibleName':'MIME type','preferredWidth':100,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Response content type sent by the server','isRegEx':false,'regExString':'','regExCaseSensitive':false},")
        .append("{'id':" + NEW_COOKIES + ",'name':'NewCookies','defaultVisibleName':'New Cookies','visibleName':'New Cookies','preferredWidth':125,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':true,'description':'Shows any new cookies in the response','isRegEx':false,'regExString':'','regExCaseSensitive':false},")
        .append("{'id':" + REQUEST_TIME + ",'name':'RequestTime','defaultVisibleName':'Request Time','visibleName':'Request Time','preferredWidth':150,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':true,'description':'Shows date and time of making the request in this extension','isRegEx':false,'regExString':'','regExCaseSensitive':false},")
        .append("{'id':" + RESPONSE_TIME + ",'name':'ResponseTime','defaultVisibleName':'Response Time','visibleName':'Response Time','preferredWidth':150,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':true,'description':'Shows date and time of receiving the response in this extension','isRegEx':false,'regExString':'','regExCaseSensitive':false},")
        .append("{'id':" + RTT + ",'name':'RTT','defaultVisibleName':'RTT (ms)','visibleName':'RTT (ms)','preferredWidth':100,'type':'int','readonly':true,'order':" + colOrder++ + ",'visible':true,'description':'Shows delay between making the request, and receiving the response. Note: Includes BurpSuite processing time','isRegEx':false,'regExString':'','regExCaseSensitive':false},")
        .append("{'id':" + LISTENER_INTERFACE + ",'name':'ListenerInterface','defaultVisibleName':'Proxy Listener Interface','visibleName':'Proxy Listener Interface','preferredWidth':150,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':true,'description':'Shows the proxy listener interface for proxied requests','isRegEx':false,'regExString':'','regExCaseSensitive':false},")
        .append("{'id':" + CLIENT_IP + ",'name':'ClientIP','defaultVisibleName':'Proxy Client IP','visibleName':'Proxy Client IP','preferredWidth':150,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Shows the client IP address when using the Proxy tab','isRegEx':false,'regExString':'','regExCaseSensitive':false},")
        .append("{'id':" + RESPONSE_CONTENT_TYPE + ",'name':'ResponseContentType','defaultVisibleName':'Response Content-Type','visibleName':'Response Content-Type','preferredWidth':150,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Shows the content-type header in the response','isRegEx':false,'regExString':'','regExCaseSensitive':false},")
        .append("{'id':" + HASGETPARAM + ",'name':'HasQueryStringParam','defaultVisibleName':'QueryString?','visibleName':'QueryString?','preferredWidth':50,'type':'boolean','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Indicates whether or not the request has any querystring parameters','isRegEx':false,'regExString':'','regExCaseSensitive':false},")
        .append("{'id':" + HASPOSTPARAM + ",'name':'HasBodyParam','defaultVisibleName':'Body Params?','visibleName':'Body Params?','preferredWidth':50,'type':'boolean','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Indicates whether or not the request contains any POST parameters','isRegEx':false,'regExString':'','regExCaseSensitive':false},")
        .append("{'id':" + HASCOOKIEPARAM + ",'name':'HasCookieParam','defaultVisibleName':'Sent Cookie?','visibleName':'Sent Cookie?','preferredWidth':50,'type':'boolean','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Indicates whether or not the request has any Cookie parameters','isRegEx':false,'regExString':'','regExCaseSensitive':false},")
        .append("{'id':" + SENTCOOKIES + ",'name':'SentCookies','defaultVisibleName':'Sent Cookies','visibleName':'Sent Cookies','preferredWidth':150,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Shows the cookies which was sent in the request','isRegEx':false,'regExString':'','regExCaseSensitive':false},")
        .append("{'id':" + USES_COOKIE_JAR + ",'name':'UsesCookieJar','defaultVisibleName':'Contains cookie jar?','visibleName':'Contains cookie jar?','preferredWidth':150,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Compares the cookies with the cookie jar ones to see if any of them in use','isRegEx':false,'regExString':'','regExCaseSensitive':false},")
        .append("{'id':" + REQUEST_CONTENT_TYPE + ",'name':'RequestContentType','defaultVisibleName':'Request Content Type','visibleName':'Request Type','preferredWidth':150,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Shows the request content-type header','isRegEx':false,'regExString':'','regExCaseSensitive':false},")
        .append("{'id':" + REFERRER + ",'name':'Referrer','defaultVisibleName':'Referrer','visibleName':'Referrer','preferredWidth':250,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Shows the referer header','isRegEx':false,'regExString':'','regExCaseSensitive':false},")
        .append("{'id':" + HAS_SET_COOKIES + ",'name':'HasSetCookies','defaultVisibleName':'Set-Cookie?','visibleName':'Set-Cookie?','preferredWidth':50,'type':'boolean','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Indicates whether or not the response contains the set-cookie header','isRegEx':false,'regExString':'','regExCaseSensitive':false},")
//            .append("{'id':" + REGEX1REQ + ",'name':'Regex1Req','defaultVisibleName':'Request RegEx 1','visibleName':'Request RegEx 1','preferredWidth':150,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':true,'description':'Custom regular expression for request header/body','isRegEx':true,'regExString':'','regExCaseSensitive':false},")
//            .append("{'id':" + REGEX2REQ + ",'name':'Regex2Req','defaultVisibleName':'Request RegEx 2','visibleName':'Request RegEx 2','preferredWidth':150,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Custom regular expression for request header/body','isRegEx':true,'regExString':'','regExCaseSensitive':false},")
//            .append("{'id':" + REGEX3REQ + ",'name':'Regex3Req','defaultVisibleName':'Request RegEx 3','visibleName':'Request RegEx 3','preferredWidth':150,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Custom regular expression for request header/body','isRegEx':true,'regExString':'','regExCaseSensitive':false},")
//            .append("{'id':" + REGEX4REQ + ",'name':'Regex4Req','defaultVisibleName':'Request RegEx 4','visibleName':'Request RegEx 4','preferredWidth':150,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Custom regular expression for request header/body','isRegEx':true,'regExString':'','regExCaseSensitive':false},")
//            .append("{'id':" + REGEX5REQ + ",'name':'Regex5Req','defaultVisibleName':'Request RegEx 5','visibleName':'Request RegEx 5','preferredWidth':150,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Custom regular expression for request header/body','isRegEx':true,'regExString':'','regExCaseSensitive':false},")
//            .append("{'id':" + REGEX1RESP + ",'name':'Regex1Resp','defaultVisibleName':'Response RegEx 1','visibleName':'Response RegEx 1 - Title','preferredWidth':220,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':true,'description':'Custom regular expression for response header/body','isRegEx':true,'regExString':'(?<=\\\\<title\\\\>)(.)+(?=\\\\<\\\\/title\\\\>)','regExCaseSensitive':false},")
//            .append("{'id':" + REGEX2RESP + ",'name':'Regex2Resp','defaultVisibleName':'Response RegEx 2','visibleName':'Response RegEx 2','preferredWidth':150,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Custom regular expression for response header/body','isRegEx':true,'regExString':'','regExCaseSensitive':false},")
//            .append("{'id':" + REGEX3RESP + ",'name':'Regex3Resp','defaultVisibleName':'Response RegEx 3','visibleName':'Response RegEx 3','preferredWidth':150,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Custom regular expression for response header/body','isRegEx':true,'regExString':'','regExCaseSensitive':true},")
//            .append("{'id':" + REGEX4RESP + ",'name':'Regex4Resp','defaultVisibleName':'Response RegEx 4','visibleName':'Response RegEx 4','preferredWidth':150,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Custom regular expression for response header/body','isRegEx':true,'regExString':'','regExCaseSensitive':false},")
//            .append("{'id':" + REGEX5RESP + ",'name':'Regex5Resp','defaultVisibleName':'Response RegEx 5','visibleName':'Response RegEx 5','preferredWidth':150,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Custom regular expression for response header/body','isRegEx':true,'regExString':'','regExCaseSensitive':false},")
        .append("{'id':" + REQUEST_BODY + ",'name':'Request','defaultVisibleName':'Request Body','visibleName':'Request Body','preferredWidth':150,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Full Request Body','isRegEx':false,'regExString':'','regExCaseSensitive':false},")
        .append("{'id':" + REQUEST_HEADERS + ",'name':'RequestHeaders','defaultVisibleName':'Request Headers','visibleName':'Request Headers','preferredWidth':150,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Comma Delimited Request Headers','isRegEx':false,'regExString':'','regExCaseSensitive':false},")
        .append("{'id':" + RESPONSE_BODY + ",'name':'Response','defaultVisibleName':'Response Body','visibleName':'Response Body','preferredWidth':150,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Full Response Body','isRegEx':false,'regExString':'','regExCaseSensitive':false},")
        .append("{'id':" + RESPONSE_HEADERS + ",'name':'ResponseHeaders','defaultVisibleName':'Response Headers','visibleName':'Response Headers','preferredWidth':150,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Comma Delimited Response Headers','isRegEx':false,'regExString':'','regExCaseSensitive':false}")
        .append("]").toString();
    
             


    public static final Pattern UUID_COMMENT_PATTERN = Pattern.compile("\\$LPP:(\\d\\d):(.*?)\\$");
    public static final Pattern HTML_TITLE_PATTERN = Pattern.compile("<title>(.+?)</title>");
}
