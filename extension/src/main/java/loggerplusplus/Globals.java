package loggerplusplus;

public class Globals {
    public static final String APP_NAME = "Burp Suite Logger++";
    public static final double VERSION = 3.10;
    public static final String AUTHOR = "Soroush Dalili (@irsdl), Corey Arthur (@CoreyD97) from NCC Group";
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
    public static final String PREF_LOG_OTHER_LIVE = "otherToolLiveLogging";
    public static final String PREF_FILTER_HISTORY = "filterHistory";
    public static final String PREF_AUTO_SAVE = "autoSave";
    public static final String PREF_AUTO_SCROLL = "autoScroll";

    public static final String DEFAULT_COLOR_FILTERS_JSON = "{\"2add8ace-b652-416a-af08-4d78c5d22bc7\":{\"uid\":\"2add8ace-b652-416a-af08-4d78c5d22bc7\"," +
            "\"filter\":{\"filter\":\"!COMPLETE\"},\"filterString\":\"!COMPLETE\",\"backgroundColor\":{\"value\":-16777216,\"falpha\":0.0}," +
            "\"foregroundColor\":{\"value\":-65536,\"falpha\":0.0},\"enabled\":true,\"modified\":false,\"shouldRetest\":true,\"priority\":1}}";
    public static final String DEFAULT_LOG_TABLE_COLUMNS_JSON = "["
            + "{'id':0,'name':'Number','enabled':true,'defaultVisibleName':'#','visibleName':'#','preferredWidth':35,'type':'int','readonly':true,'order':0,'visible':true,'description':'Item index number','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':1,'name':'Tool','enabled':true,'defaultVisibleName':'Tool','visibleName':'Tool','preferredWidth':70,'type':'string','readonly':true,'order':2,'visible':true,'description':'Tool name','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':2,'name':'Host','enabled':true,'defaultVisibleName':'Host','visibleName':'Host','preferredWidth':150,'type':'string','readonly':true,'order':3,'visible':true,'description':'Host and Protocol (similar to the Proxy tab)','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':3,'name':'Method','enabled':true,'defaultVisibleName':'Method','visibleName':'Method','preferredWidth':65,'type':'string','readonly':true,'order':4,'visible':true,'description':'HTTP request method','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':4,'name':'Url','enabled':true,'defaultVisibleName':'URL','visibleName':'URL','preferredWidth':250,'type':'string','readonly':true,'order':5,'visible':false,'description':'Complete URL','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':5,'name':'Path','enabled':true,'defaultVisibleName':'Path','visibleName':'Path','preferredWidth':250,'type':'string','readonly':true,'order':6,'visible':true,'description':'Request Path','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':6,'name':'Query','enabled':true,'defaultVisibleName':'Query','visibleName':'Query','preferredWidth':250,'type':'string','readonly':true,'order':7,'visible':true,'description':'Query Parameters','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':7,'name':'Params','enabled':true,'defaultVisibleName':'Params','visibleName':'Params','preferredWidth':65,'type':'boolean','readonly':true,'order':7,'visible':true,'description':'Indicates whether or not the request has GET or POST parameter(s)','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':8,'name':'Status','enabled':true,'defaultVisibleName':'Status','visibleName':'Status','preferredWidth':55,'type':'short','readonly':true,'order':8,'visible':true,'description':'Response status header','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':9,'name':'ResponseLength','enabled':true,'defaultVisibleName':'Response Length','visibleName':'Response Length','preferredWidth':100,'type':'int','readonly':true,'order':9,'visible':true,'description':'Length of response','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':10,'name':'MimeType','enabled':true,'defaultVisibleName':'MIME type','visibleName':'MIME type','preferredWidth':100,'type':'string','readonly':true,'order':10,'visible':true,'description':'Response content type using Burp API','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':11,'name':'UrlExtension','enabled':true,'defaultVisibleName':'Extension','visibleName':'Extension','preferredWidth':70,'type':'string','readonly':true,'order':11,'visible':true,'description':'Target page extension','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':12, 'name':'Comment','enabled':true,'defaultVisibleName':'Comment','visibleName':'Comment','preferredWidth':200,'type':'string','readonly':false,'order':12,'visible':true,'description':'Editable comment','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':13,'name':'IsSSL','enabled':true,'defaultVisibleName':'SSL','visibleName':'SSL','preferredWidth':50,'type':'boolean','readonly':true,'order':13,'visible':true,'description':'Indicates whether or not the HTTP protocol is HTTPS','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':14,'name':'NewCookies','enabled':true,'defaultVisibleName':'New Cookies','visibleName':'New Cookies','preferredWidth':150,'type':'string','readonly':true,'order':14,'visible':true,'description':'Shows any new cookies in the response','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':15,'name':'RequestTime','enabled':true,'defaultVisibleName':'Request Time','visibleName':'Request Time','preferredWidth':150,'type':'string','readonly':true,'order':15,'visible':true,'description':'Shows date and time of making the request in this extension','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':16,'name':'ListenerInterface','enabled':true,'defaultVisibleName':'Proxy Listener interface','visibleName':'Proxy Listener interface','preferredWidth':150,'type':'string','readonly':true,'order':16,'visible':true,'description':'Shows the proxy listener interface for proxied requests','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':17,'name':'ClientIP','enabled':true,'defaultVisibleName':'Proxy Client IP','visibleName':'Proxy Client IP','preferredWidth':150,'type':'string','readonly':true,'order':17,'visible':false,'description':'Shows the client IP address when using the Proxy tab','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':18,'name':'ResponseContentType','enabled':true,'defaultVisibleName':'Response Content-Type','visibleName':'Response Content-Type','preferredWidth':150,'type':'string','readonly':true,'order':18,'visible':false,'description':'Shows the content-type header in the response','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':19,'name':'InferredType','enabled':true,'defaultVisibleName':'Inferred Type','visibleName':'Inferred Type','preferredWidth':150,'type':'string','readonly':true,'order':19,'visible':false,'description':'Shows the content type which was inferred by Burp','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':20,'name':'HasQueryStringParam','enabled':true,'defaultVisibleName':'QueryString?','visibleName':'QueryString?','preferredWidth':50,'type':'boolean','readonly':true,'order':20,'visible':false,'description':'Indicates whether or not the request has any querystring parameters','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':21,'name':'HasBodyParam','enabled':true,'defaultVisibleName':'Body Params?','visibleName':'Body Params?','preferredWidth':50,'type':'boolean','readonly':true,'order':21,'visible':false,'description':'Indicates whether or not the request contains any POST parameters','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':22,'name':'HasCookieParam','enabled':true,'defaultVisibleName':'Sent Cookie?','visibleName':'Sent Cookie?','preferredWidth':50,'type':'boolean','readonly':true,'order':22,'visible':false,'description':'Indicates whether or not the request has any Cookie parameters','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':23,'name':'SentCookies','enabled':true,'defaultVisibleName':'Sent Cookies','visibleName':'Sent Cookies','preferredWidth':150,'type':'string','readonly':true,'order':23,'visible':false,'description':'Shows the cookies which was sent in the request','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':24,'name':'UsesCookieJar','enabled':true,'defaultVisibleName':'Contains cookie jar?','visibleName':'Contains cookie jar?','preferredWidth':150,'type':'string','readonly':true,'order':24,'visible':false,'description':'Compares the cookies with the cookie jar ones to see if any of them in use','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':25,'name':'Protocol','enabled':true,'defaultVisibleName':'Protocol','visibleName':'Protocol','preferredWidth':80,'type':'string','readonly':true,'order':25,'visible':false,'description':'Shows the request protocol','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':26,'name':'Hostname','enabled':true,'defaultVisibleName':'Host Name','visibleName':'Host Name','preferredWidth':150,'type':'string','readonly':true,'order':26,'visible':false,'description':'Shows the request host name','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':27,'name':'TargetPort','enabled':true,'defaultVisibleName':'Port','visibleName':'Port','preferredWidth':50,'type':'int','readonly':true,'order':27,'visible':false,'description':'Shows the target port number','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':28,'name':'RequestContentType','enabled':true,'defaultVisibleName':'Request Content Type','visibleName':'Request Type','preferredWidth':150,'type':'string','readonly':true,'order':28,'visible':false,'description':'Shows the request content-type header','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':29,'name':'Referrer','enabled':true,'defaultVisibleName':'Referrer','visibleName':'Referrer','preferredWidth':250,'type':'string','readonly':true,'order':29,'visible':false,'description':'Shows the referer header','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':30,'name':'RequestLength','enabled':true,'defaultVisibleName':'Request Length','visibleName':'Request Length','preferredWidth':150,'type':'int','readonly':true,'order':30,'visible':false,'description':'Shows the request body length','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':31,'name':'HasSetCookies','enabled':true,'defaultVisibleName':'Set-Cookie?','visibleName':'Set-Cookie?','preferredWidth':50,'type':'boolean','readonly':true,'order':31,'visible':false,'description':'Indicates whether or not the response contains the set-cookie header','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':32,'name':'Complete','enabled':true,'defaultVisibleName':'Complete','visibleName':'Complete','preferredWidth':80,'type':'boolean','readonly':true,'order':1,'visible':true,'description':'Indicates if a response has been received.','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':33,'name':'Regex1Req','enabled':true,'defaultVisibleName':'Request RegEx 1','visibleName':'Request RegEx 1','preferredWidth':150,'type':'string','readonly':true,'order':34,'visible':true,'description':'Custom regular expression for request header/body','isRegEx':true,'regExString':'','regExCaseSensitive':false},"
            + "{'id':34,'name':'Regex2Req','enabled':false,'defaultVisibleName':'Request RegEx 2','visibleName':'Request RegEx 2','preferredWidth':150,'type':'string','readonly':true,'order':35,'visible':true,'description':'Custom regular expression for request header/body','isRegEx':true,'regExString':'','regExCaseSensitive':false},"
            + "{'id':35,'name':'Regex3Req','enabled':false,'defaultVisibleName':'Request RegEx 3','visibleName':'Request RegEx 3','preferredWidth':150,'type':'string','readonly':true,'order':36,'visible':true,'description':'Custom regular expression for request header/body','isRegEx':true,'regExString':'','regExCaseSensitive':false},"
            + "{'id':36,'name':'Regex4Req','enabled':false,'defaultVisibleName':'Request RegEx 4','visibleName':'Request RegEx 4','preferredWidth':150,'type':'string','readonly':true,'order':37,'visible':true,'description':'Custom regular expression for request header/body','isRegEx':true,'regExString':'','regExCaseSensitive':false},"
            + "{'id':37,'name':'Regex5Req','enabled':false,'defaultVisibleName':'Request RegEx 5','visibleName':'Request RegEx 5','preferredWidth':150,'type':'string','readonly':true,'order':38,'visible':true,'description':'Custom regular expression for request header/body','isRegEx':true,'regExString':'','regExCaseSensitive':false},"
            + "{'id':38,'name':'Regex1Resp','enabled':true,'defaultVisibleName':'Response RegEx 1','visibleName':'Response RegEx 1 - Title','preferredWidth':220,'type':'string','readonly':true,'order':39,'visible':true,'description':'Custom regular expression for response header/body','isRegEx':true,'regExString':'(?<=\\\\<title\\\\>)(.)+(?=\\\\<\\\\/title\\\\>)','regExCaseSensitive':false},"
            + "{'id':39,'name':'Regex2Resp','enabled':false,'defaultVisibleName':'Response RegEx 2','visibleName':'Response RegEx 2','preferredWidth':150,'type':'string','readonly':true,'order':40,'visible':true,'description':'Custom regular expression for response header/body','isRegEx':true,'regExString':'','regExCaseSensitive':false},"
            + "{'id':40,'name':'Regex3Resp','enabled':false,'defaultVisibleName':'Response RegEx 3','visibleName':'Response RegEx 3','preferredWidth':150,'type':'string','readonly':true,'order':41,'visible':true,'description':'Custom regular expression for response header/body','isRegEx':true,'regExString':'','regExCaseSensitive':true},"
            + "{'id':41,'name':'Regex4Resp','enabled':false,'defaultVisibleName':'Response RegEx 4','visibleName':'Response RegEx 4','preferredWidth':150,'type':'string','readonly':true,'order':42,'visible':true,'description':'Custom regular expression for response header/body','isRegEx':true,'regExString':'','regExCaseSensitive':false},"
            + "{'id':42,'name':'Regex5Resp','enabled':false,'defaultVisibleName':'Response RegEx 5','visibleName':'Response RegEx 5','preferredWidth':150,'type':'string','readonly':true,'order':43,'visible':true,'description':'Custom regular expression for response header/body','isRegEx':true,'regExString':'','regExCaseSensitive':false},"
            + "{'id':43,'name':'Request','enabled':true,'defaultVisibleName':'Request Body','visibleName':'Request Body','preferredWidth':150,'type':'string','readonly':true,'order':44,'visible':false,'description':'Full Request Body','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':47,'name':'RequestHeaders','enabled':true,'defaultVisibleName':'Request Headers','visibleName':'Request Headers','preferredWidth':150,'type':'string','readonly':true,'order':44,'visible':false,'description':'Comma Delimited Request Headers','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':44,'name':'Response','enabled':true,'defaultVisibleName':'Response Body','visibleName':'Response Body','preferredWidth':150,'type':'string','readonly':true,'order':45,'visible':false,'description':'Full Response Body','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':48,'name':'ResponseHeaders','enabled':true,'defaultVisibleName':'Response Headers','visibleName':'Response Headers','preferredWidth':150,'type':'string','readonly':true,'order':45,'visible':false,'description':'Comma Delimited Response Headers','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':45,'name':'ResponseTime','enabled':true,'defaultVisibleName':'Response Time','visibleName':'Response Time','preferredWidth':150,'type':'string','readonly':true,'order':15,'visible':true,'description':'Shows date and time of receiving the response in this extension','isRegEx':false,'regExString':'','regExCaseSensitive':false},"
            + "{'id':46,'name':'RTT','enabled':true,'defaultVisibleName':'RTT (ms)','visibleName':'RTT (ms)','preferredWidth':100,'type':'int','readonly':true,'order':15,'visible':true,'description':'Shows delay between making the request, and receiving the response. Note: Includes BurpSuite processing time','isRegEx':false,'regExString':'','regExCaseSensitive':false}"
            + "]";
}
