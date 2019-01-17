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

    public static final String DEFAULT_COLOR_FILTERS_JSON = "{\"2add8ace-b652-416a-af08-4d78c5d22bc7\":{\"uid\":\"2add8ace-b652-416a-af08-4d78c5d22bc7\"," +
            "\"filter\":{\"filter\":\"!COMPLETE\"},\"filterString\":\"!COMPLETE\",\"backgroundColor\":{\"value\":-16777216,\"falpha\":0.0}," +
            "\"foregroundColor\":{\"value\":-65536,\"falpha\":0.0},\"enabled\":true,\"modified\":false,\"shouldRetest\":true,\"priority\":1}}";
}
