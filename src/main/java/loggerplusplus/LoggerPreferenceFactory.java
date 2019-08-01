package loggerplusplus;

import burp.IBurpExtenderCallbacks;
import com.coreyd97.BurpExtenderUtilities.IGsonProvider;
import com.coreyd97.BurpExtenderUtilities.ILogProvider;
import com.coreyd97.BurpExtenderUtilities.PreferenceFactory;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.google.gson.reflect.TypeToken;
import loggerplusplus.filter.ColorFilter;
import loggerplusplus.filter.LogFilter;
import loggerplusplus.filter.SavedFilter;
import loggerplusplus.userinterface.LogTableColumn;

import java.util.*;

import static loggerplusplus.Globals.*;

public class LoggerPreferenceFactory extends PreferenceFactory {

    private HashMap<UUID, ColorFilter> defaultColorFilters;
    private ArrayList<LogTableColumn> defaultlogTableColumns;

    public LoggerPreferenceFactory(IGsonProvider gsonProvider, ILogProvider logProvider, IBurpExtenderCallbacks callbacks){
        super("LoggerPlusPlus", gsonProvider, logProvider, callbacks);
    }

    public LoggerPreferenceFactory(IGsonProvider gsonProvider, IBurpExtenderCallbacks callbacks){
        super("LoggerPlusPlus", gsonProvider, callbacks);
    }

    @Override
    protected void createDefaults(){
        defaultColorFilters = this.gsonProvider.getGson().fromJson(
                Globals.DEFAULT_COLOR_FILTERS_JSON, new TypeToken<HashMap<UUID, ColorFilter>>(){}.getType());
        defaultlogTableColumns = this.gsonProvider.getGson().fromJson(
                Globals.DEFAULT_LOG_TABLE_COLUMNS_JSON, new TypeToken<List<LogTableColumn>>() {}.getType());
    }

    @Override
    protected void registerTypeAdapters(){
        this.gsonProvider.registerTypeAdapter(LogFilter.class, new LogFilter.FilterSerializer());
        this.gsonProvider.registerTypeAdapter(LogTableColumn.class, new LogTableColumn.ColumnSerializer());
    }

    @Override
    protected void registerSettings() {
        prefs.registerSetting(PREF_LOG_TABLE_SETTINGS, new TypeToken<List<LogTableColumn>>() {}.getType(), defaultlogTableColumns, Preferences.Visibility.GLOBAL);
        prefs.registerSetting(PREF_LAST_USED_VERSION, Double.class, Globals.VERSION, Preferences.Visibility.GLOBAL);
        prefs.registerSetting(PREF_IS_DEBUG, Boolean.class, false, Preferences.Visibility.GLOBAL);
        prefs.registerSetting(PREF_UPDATE_ON_STARTUP, Boolean.class, true, Preferences.Visibility.GLOBAL);
        prefs.registerSetting(PREF_ENABLED, Boolean.class, true, Preferences.Visibility.GLOBAL);
        prefs.registerSetting(PREF_RESTRICT_TO_SCOPE, Boolean.class, false, Preferences.Visibility.GLOBAL);
        prefs.registerSetting(PREF_LOG_GLOBAL, Boolean.class, true, Preferences.Visibility.GLOBAL);
        prefs.registerSetting(PREF_LOG_PROXY, Boolean.class, true, Preferences.Visibility.GLOBAL);
        prefs.registerSetting(PREF_LOG_SPIDER, Boolean.class, true, Preferences.Visibility.GLOBAL);
        prefs.registerSetting(PREF_LOG_INTRUDER, Boolean.class, true, Preferences.Visibility.GLOBAL);
        prefs.registerSetting(PREF_LOG_SCANNER, Boolean.class, true, Preferences.Visibility.GLOBAL);
        prefs.registerSetting(PREF_LOG_REPEATER, Boolean.class, true, Preferences.Visibility.GLOBAL);
        prefs.registerSetting(PREF_LOG_SEQUENCER, Boolean.class, true, Preferences.Visibility.GLOBAL);
        prefs.registerSetting(PREF_LOG_EXTENDER, Boolean.class, true, Preferences.Visibility.GLOBAL);
        prefs.registerSetting(PREF_LOG_TARGET_TAB, Boolean.class, true, Preferences.Visibility.GLOBAL);
        prefs.registerSetting(PREF_COLOR_FILTERS, new TypeToken<Map<UUID, ColorFilter>>() {}.getType(), defaultColorFilters);
        prefs.registerSetting(PREF_SAVED_FILTERS, new TypeToken<List<SavedFilter>>() {}.getType(), new ArrayList<SavedFilter>());
        prefs.registerSetting(PREF_SORT_COLUMN, Integer.class, -1, Preferences.Visibility.GLOBAL);
        prefs.registerSetting(PREF_SORT_ORDER, String.class, "ASCENDING", Preferences.Visibility.GLOBAL);
        prefs.registerSetting(PREF_RESPONSE_TIMEOUT, Integer.class, 60000, Preferences.Visibility.GLOBAL);
        prefs.registerSetting(PREF_MAXIMUM_ENTRIES, Integer.class, 5000, Preferences.Visibility.GLOBAL);
        prefs.registerSetting(PREF_SEARCH_THREADS, Integer.class, 5, Preferences.Visibility.GLOBAL);
        prefs.registerSetting(PREF_AUTO_IMPORT_PROXY_HISTORY, Boolean.class, false, Preferences.Visibility.GLOBAL);
        prefs.registerSetting(PREF_LOG_OTHER_LIVE, Boolean.class, true, Preferences.Visibility.GLOBAL);
        prefs.registerSetting(PREF_ELASTIC_ADDRESS, String.class, "127.0.0.1", Preferences.Visibility.GLOBAL);
        prefs.registerSetting(PREF_ELASTIC_PORT, Integer.class, 9300, Preferences.Visibility.GLOBAL);
        prefs.registerSetting(PREF_ELASTIC_CLUSTER_NAME, String.class, "elasticsearch", Preferences.Visibility.GLOBAL);
        prefs.registerSetting(PREF_ELASTIC_INDEX, String.class, "logger", Preferences.Visibility.GLOBAL);
        prefs.registerSetting(PREF_ELASTIC_DELAY, Integer.class, 120, Preferences.Visibility.GLOBAL);
        prefs.registerSetting(PREF_ELASTIC_INCLUDE_REQ_RESP, Boolean.class, false, Preferences.Visibility.GLOBAL);

        prefs.registerSetting(PREF_AUTO_SAVE, Boolean.class, false, Preferences.Visibility.VOLATILE);
        prefs.registerSetting(PREF_AUTO_SCROLL, Boolean.class, true, Preferences.Visibility.VOLATILE);
    }

}
