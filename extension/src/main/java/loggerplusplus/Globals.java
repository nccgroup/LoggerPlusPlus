package loggerplusplus;

import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

import static loggerplusplus.userinterface.LogTableColumn.ColumnIdentifier.*;

public class Globals {
    public static final String APP_NAME = "Burp Suite Logger++";
    public static final double VERSION = 3.10;
    public static final String AUTHOR = "Corey Arthur (@CoreyD97), Soroush Dalili (@irsdl) from NCC Group";
    public static final String COMPANY_LINK = "https://www.nccgroup.trust/";
    public static final String AUTHOR_LINK = "https://soroush.secproject.com/";
    public static final String PROJECT_LINK = "https://github.com/NCCGroup/BurpSuiteLoggerPlusPlus";
    public static final String PROJECT_ISSUE_LINK = "https://github.com/nccgroup/BurpSuiteLoggerPlusPlus/issues";
    public static final String CHANGELOG = "https://raw.githubusercontent.com/NCCGroup/BurpSuiteLoggerPlusPlus/master/CHANGELOG";
    public static final String UPDATE_URL = "https://raw.githubusercontent.com/NCCGroup/BurpSuiteLoggerPlusPlus/master/burplogger++.jar";

    //Preferences Keys
    public static final String PREF_LOG_TABLE_SETTINGS = "tabledetailsjson";
    public static final String PREF_LAST_USED_VERSION = "version";
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
    public static final String PREF_ELASTIC_CLUSTER_NAME = "esClusterName";
    public static final String PREF_ELASTIC_INDEX = "esIndex";
    public static final String PREF_ELASTIC_DELAY = "esDelay";
    public static final String PREF_ELASTIC_INCLUDE_REQ_RESP = "esIncludeReqResp";
    public static final String PREF_LOG_OTHER_LIVE = "otherToolLiveLogging";
    public static final String PREF_FILTER_HISTORY = "filterHistory";
    public static final String PREF_AUTO_SAVE = "autoSave";
    public static final String PREF_AUTO_SCROLL = "autoScroll";

    public static final String[] VERSION_CHANGE_SETTINGS_TO_RESET = new String[]{
            PREF_LOG_TABLE_SETTINGS
    };

    public static final String DEFAULT_COLOR_FILTERS_JSON = "{\"2add8ace-b652-416a-af08-4d78c5d22bc7\":{\"uid\":\"2add8ace-b652-416a-af08-4d78c5d22bc7\"," +
            "\"filter\":{\"filter\":\"!COMPLETE\"},\"filterString\":\"!COMPLETE\",\"backgroundColor\":{\"value\":-16777216,\"falpha\":0.0}," +
            "\"foregroundColor\":{\"value\":-65536,\"falpha\":0.0},\"enabled\":true,\"modified\":false,\"shouldRetest\":true,\"priority\":1}}";
    private static int colModelIndex = 0;
    private static int colOrder = 0;
    public static final String DEFAULT_LOG_TABLE_COLUMNS_JSON = "["
            + "{'id':" + NUMBER + ",'index':" + (colModelIndex++) + ",'name':'Number','defaultVisibleName':'#','visibleName':'#','preferredWidth':35,'type':'int','readonly':true,'order':" + colOrder++ + ",'visible':true,'description':'Item index number','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':" + COMPLETE + ",'index':" + (colModelIndex++) + ",'name':'Complete','defaultVisibleName':'Complete','visibleName':'Complete','preferredWidth':80,'type':'boolean','readonly':true,'order':" + colOrder++ + ",'visible':true,'description':'Indicates if a response has been received.','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':" + TOOL + ",'index':" + (colModelIndex++) + ",'name':'Tool','defaultVisibleName':'Tool','visibleName':'Tool','preferredWidth':70,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':true,'description':'Tool name','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':" + METHOD + ",'index':" + (colModelIndex++) + ",'name':'Method','defaultVisibleName':'Method','visibleName':'Method','preferredWidth':65,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':true,'description':'HTTP request method','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':" + HOST + ",'index':" + (colModelIndex++) + ",'name':'Host','defaultVisibleName':'Host','visibleName':'Host','preferredWidth':150,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':true,'description':'Host and Protocol (similar to the Proxy tab)','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':" + PATH + ",'index':" + (colModelIndex++) + ",'name':'Path','defaultVisibleName':'Path','visibleName':'Path','preferredWidth':250,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':true,'description':'Request Path','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':" + QUERY + ",'index':" + (colModelIndex++) + ",'name':'Query','defaultVisibleName':'Query','visibleName':'Query','preferredWidth':250,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':true,'description':'Query Parameters','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':" + PARAMS + ",'index':" + (colModelIndex++) + ",'name':'Params','defaultVisibleName':'Params','visibleName':'Params','preferredWidth':65,'type':'boolean','readonly':true,'order':" + colOrder++ + ",'visible':true,'description':'Indicates whether or not the request has GET or POST parameter(s)','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':" + URL + ",'index':" + (colModelIndex++) + ",'name':'Url','defaultVisibleName':'URL','visibleName':'URL','preferredWidth':250,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Complete URL','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':" + STATUS + ",'index':" + (colModelIndex++) + ",'name':'Status','defaultVisibleName':'Status','visibleName':'Status','preferredWidth':55,'type':'short','readonly':true,'order':" + colOrder++ + ",'visible':true,'description':'Response status header','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':" + RESPONSELENGTH + ",'index':" + (colModelIndex++) + ",'name':'ResponseLength','defaultVisibleName':'Response Length','visibleName':'Response Length','preferredWidth':100,'type':'int','readonly':true,'order':" + colOrder++ + ",'visible':true,'description':'Length of response','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':" + MIMETYPE + ",'index':" + (colModelIndex++) + ",'name':'MimeType','defaultVisibleName':'MIME type','visibleName':'MIME type','preferredWidth':100,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':true,'description':'Response content type using Burp API','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':" + ISSSL + ",'index':" + (colModelIndex++) + ",'name':'IsSSL','defaultVisibleName':'SSL','visibleName':'SSL','preferredWidth':50,'type':'boolean','readonly':true,'order':" + colOrder++ + ",'visible':true,'description':'Indicates whether or not the HTTP protocol is HTTPS','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':" + URLEXTENSION + ",'index':" + (colModelIndex++) + ",'name':'UrlExtension','defaultVisibleName':'Extension','visibleName':'Extension','preferredWidth':70,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':true,'description':'Target page extension','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':" + COMMENT + ",'index':" + (colModelIndex++) + ",'name':'Comment','defaultVisibleName':'Comment','visibleName':'Comment','preferredWidth':200,'type':'string','readonly':false,'order':" + colOrder++ + ",'visible':true,'description':'Editable comment','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':" + NEWCOOKIES + ",'index':" + (colModelIndex++) + ",'name':'NewCookies','defaultVisibleName':'New Cookies','visibleName':'New Cookies','preferredWidth':150,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':true,'description':'Shows any new cookies in the response','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':" + REQUESTTIME + ",'index':" + (colModelIndex++) + ",'name':'RequestTime','defaultVisibleName':'Request Time','visibleName':'Request Time','preferredWidth':150,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':true,'description':'Shows date and time of making the request in this extension','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':" + RESPONSETIME + ",'index':" + (colModelIndex++) + ",'name':'ResponseTime','defaultVisibleName':'Response Time','visibleName':'Response Time','preferredWidth':150,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':true,'description':'Shows date and time of receiving the response in this extension','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':" + RTT + ",'index':" + (colModelIndex++) + ",'name':'RTT','defaultVisibleName':'RTT (ms)','visibleName':'RTT (ms)','preferredWidth':100,'type':'int','readonly':true,'order':" + colOrder++ + ",'visible':true,'description':'Shows delay between making the request, and receiving the response. Note: Includes BurpSuite processing time','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':" + LISTENERINTERFACE + ",'index':" + (colModelIndex++) + ",'name':'ListenerInterface','defaultVisibleName':'Proxy Listener Interface','visibleName':'Proxy Listener Interface','preferredWidth':150,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':true,'description':'Shows the proxy listener interface for proxied requests','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':" + CLIENTIP + ",'index':" + (colModelIndex++) + ",'name':'ClientIP','defaultVisibleName':'Proxy Client IP','visibleName':'Proxy Client IP','preferredWidth':150,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Shows the client IP address when using the Proxy tab','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':" + RESPONSECONTENTTYPE + ",'index':" + (colModelIndex++) + ",'name':'ResponseContentType','defaultVisibleName':'Response Content-Type','visibleName':'Response Content-Type','preferredWidth':150,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Shows the content-type header in the response','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':" + INFERREDTYPE + ",'index':" + (colModelIndex++) + ",'name':'InferredType','defaultVisibleName':'Inferred Type','visibleName':'Inferred Type','preferredWidth':150,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Shows the content type which was inferred by Burp','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':" + HASQUERYSTRINGPARAM + ",'index':" + (colModelIndex++) + ",'name':'HasQueryStringParam','defaultVisibleName':'QueryString?','visibleName':'QueryString?','preferredWidth':50,'type':'boolean','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Indicates whether or not the request has any querystring parameters','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':" + HASBODYPARAM + ",'index':" + (colModelIndex++) + ",'name':'HasBodyParam','defaultVisibleName':'Body Params?','visibleName':'Body Params?','preferredWidth':50,'type':'boolean','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Indicates whether or not the request contains any POST parameters','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':" + HASCOOKIEPARAM + ",'index':" + (colModelIndex++) + ",'name':'HasCookieParam','defaultVisibleName':'Sent Cookie?','visibleName':'Sent Cookie?','preferredWidth':50,'type':'boolean','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Indicates whether or not the request has any Cookie parameters','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':" + SENTCOOKIES + ",'index':" + (colModelIndex++) + ",'name':'SentCookies','defaultVisibleName':'Sent Cookies','visibleName':'Sent Cookies','preferredWidth':150,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Shows the cookies which was sent in the request','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':" + USESCOOKIEJAR + ",'index':" + (colModelIndex++) + ",'name':'UsesCookieJar','defaultVisibleName':'Contains cookie jar?','visibleName':'Contains cookie jar?','preferredWidth':150,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Compares the cookies with the cookie jar ones to see if any of them in use','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':" + PROTOCOL + ",'index':" + (colModelIndex++) + ",'name':'Protocol','defaultVisibleName':'Protocol','visibleName':'Protocol','preferredWidth':80,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Shows the request protocol','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':" + HOSTNAME + ",'index':" + (colModelIndex++) + ",'name':'Hostname','defaultVisibleName':'Host Name','visibleName':'Host Name','preferredWidth':150,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Shows the request host name','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':" + TARGETPORT + ",'index':" + (colModelIndex++) + ",'name':'TargetPort','defaultVisibleName':'Port','visibleName':'Port','preferredWidth':50,'type':'int','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Shows the target port number','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':" + REQUESTCONTENTTYPE + ",'index':" + (colModelIndex++) + ",'name':'RequestContentType','defaultVisibleName':'Request Content Type','visibleName':'Request Type','preferredWidth':150,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Shows the request content-type header','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':" + REFERRER + ",'index':" + (colModelIndex++) + ",'name':'Referrer','defaultVisibleName':'Referrer','visibleName':'Referrer','preferredWidth':250,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Shows the referer header','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':" + REQUESTLENGTH + ",'index':" + (colModelIndex++) + ",'name':'RequestLength','defaultVisibleName':'Request Length','visibleName':'Request Length','preferredWidth':150,'type':'int','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Shows the request body length','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':" + HASSETCOOKIES + ",'index':" + (colModelIndex++) + ",'name':'HasSetCookies','defaultVisibleName':'Set-Cookie?','visibleName':'Set-Cookie?','preferredWidth':50,'type':'boolean','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Indicates whether or not the response contains the set-cookie header','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':" + REGEX1REQ + ",'index':" + (colModelIndex++) + ",'name':'Regex1Req','defaultVisibleName':'Request RegEx 1','visibleName':'Request RegEx 1','preferredWidth':150,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':true,'description':'Custom regular expression for request header/body','isRegEx':true,'regExString':'','regExCaseSensitive':false},"
            + "{'id':" + REGEX2REQ + ",'index':" + (colModelIndex++) + ",'name':'Regex2Req','defaultVisibleName':'Request RegEx 2','visibleName':'Request RegEx 2','preferredWidth':150,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Custom regular expression for request header/body','isRegEx':true,'regExString':'','regExCaseSensitive':false},"
            + "{'id':" + REGEX3REQ + ",'index':" + (colModelIndex++) + ",'name':'Regex3Req','defaultVisibleName':'Request RegEx 3','visibleName':'Request RegEx 3','preferredWidth':150,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Custom regular expression for request header/body','isRegEx':true,'regExString':'','regExCaseSensitive':false},"
            + "{'id':" + REGEX4REQ + ",'index':" + (colModelIndex++) + ",'name':'Regex4Req','defaultVisibleName':'Request RegEx 4','visibleName':'Request RegEx 4','preferredWidth':150,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Custom regular expression for request header/body','isRegEx':true,'regExString':'','regExCaseSensitive':false},"
            + "{'id':" + REGEX5REQ + ",'index':" + (colModelIndex++) + ",'name':'Regex5Req','defaultVisibleName':'Request RegEx 5','visibleName':'Request RegEx 5','preferredWidth':150,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Custom regular expression for request header/body','isRegEx':true,'regExString':'','regExCaseSensitive':false},"
            + "{'id':" + REGEX1RESP + ",'index':" + (colModelIndex++) + ",'name':'Regex1Resp','defaultVisibleName':'Response RegEx 1','visibleName':'Response RegEx 1 - Title','preferredWidth':220,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':true,'description':'Custom regular expression for response header/body','isRegEx':true,'regExString':'(?<=\\\\<title\\\\>)(.)+(?=\\\\<\\\\/title\\\\>)','regExCaseSensitive':false},"
            + "{'id':" + REGEX2RESP + ",'index':" + (colModelIndex++) + ",'name':'Regex2Resp','defaultVisibleName':'Response RegEx 2','visibleName':'Response RegEx 2','preferredWidth':150,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Custom regular expression for response header/body','isRegEx':true,'regExString':'','regExCaseSensitive':false},"
            + "{'id':" + REGEX3RESP + ",'index':" + (colModelIndex++) + ",'name':'Regex3Resp','defaultVisibleName':'Response RegEx 3','visibleName':'Response RegEx 3','preferredWidth':150,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Custom regular expression for response header/body','isRegEx':true,'regExString':'','regExCaseSensitive':true},"
            + "{'id':" + REGEX4RESP + ",'index':" + (colModelIndex++) + ",'name':'Regex4Resp','defaultVisibleName':'Response RegEx 4','visibleName':'Response RegEx 4','preferredWidth':150,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Custom regular expression for response header/body','isRegEx':true,'regExString':'','regExCaseSensitive':false},"
            + "{'id':" + REGEX5RESP + ",'index':" + (colModelIndex++) + ",'name':'Regex5Resp','defaultVisibleName':'Response RegEx 5','visibleName':'Response RegEx 5','preferredWidth':150,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Custom regular expression for response header/body','isRegEx':true,'regExString':'','regExCaseSensitive':false},"
            + "{'id':" + REQUEST + ",'index':" + (colModelIndex++) + ",'name':'Request','defaultVisibleName':'Request Body','visibleName':'Request Body','preferredWidth':150,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Full Request Body','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':" + REQUESTHEADERS + ",'index':" + (colModelIndex++) + ",'name':'RequestHeaders','defaultVisibleName':'Request Headers','visibleName':'Request Headers','preferredWidth':150,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Comma Delimited Request Headers','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':" + RESPONSE + ",'index':" + (colModelIndex++) + ",'name':'Response','defaultVisibleName':'Response Body','visibleName':'Response Body','preferredWidth':150,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Full Response Body','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':" + RESPONSEHEADERS + ",'index':" + (colModelIndex++) + ",'name':'ResponseHeaders','defaultVisibleName':'Response Headers','visibleName':'Response Headers','preferredWidth':150,'type':'string','readonly':true,'order':" + colOrder++ + ",'visible':false,'description':'Comma Delimited Response Headers','isRegEx':false,'regExString':'','regExCaseSensitive':false}"
            + "]";

    public static final Pattern UUID_COMMENT_PATTERN = Pattern.compile("\\$LPP:(\\d\\d):(.*?)\\$");
    public static final Pattern HTML_TITLE_PATTERN = Pattern.compile("(?<=<title>)(.)+(?=</title>)");
}
