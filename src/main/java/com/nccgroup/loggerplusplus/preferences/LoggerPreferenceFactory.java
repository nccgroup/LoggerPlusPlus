package com.nccgroup.loggerplusplus.preferences;

import burp.api.montoya.MontoyaApi;
import com.coreyd97.BurpExtenderUtilities.IGsonProvider;
import com.coreyd97.BurpExtenderUtilities.ILogProvider;
import com.coreyd97.BurpExtenderUtilities.PreferenceFactory;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.google.gson.reflect.TypeToken;
import com.nccgroup.loggerplusplus.filter.*;
import com.nccgroup.loggerplusplus.filter.colorfilter.TableColorRule;
import com.nccgroup.loggerplusplus.filter.logfilter.LogTableFilter;
import com.nccgroup.loggerplusplus.filter.savedfilter.SavedFilter;
import com.nccgroup.loggerplusplus.filter.tag.Tag;
import com.nccgroup.loggerplusplus.logentry.LogEntry;
import com.nccgroup.loggerplusplus.logentry.LogEntryField;
import com.nccgroup.loggerplusplus.logentry.LogEntryFieldSerializer;
import com.nccgroup.loggerplusplus.logentry.LogEntrySerializer;
import com.nccgroup.loggerplusplus.logview.logtable.LogTableColumn;
import com.nccgroup.loggerplusplus.util.Globals;
import lombok.SneakyThrows;
import lombok.extern.log4j.Log4j2;
import org.apache.logging.log4j.Level;

import javax.swing.*;
import java.util.*;

import static com.nccgroup.loggerplusplus.util.Globals.*;

@Log4j2
public class LoggerPreferenceFactory extends PreferenceFactory {

    private HashMap<UUID, TableColorRule> defaultColorFilters;
    private ArrayList<LogTableColumn> defaultlogTableColumns;
    private Set<String> defaultBlacklistedReflections;
    private FilterExpression doNotLogFilter;

    public LoggerPreferenceFactory(MontoyaApi montoya, IGsonProvider gsonProvider, ILogProvider logProvider){
        super(montoya, gsonProvider, logProvider);
    }

    public LoggerPreferenceFactory(MontoyaApi montoya, IGsonProvider gsonProvider){
        super(montoya, gsonProvider);
    }

    @SneakyThrows
    @Override
    protected void createDefaults(){

        doNotLogFilter = new FilterExpression("Request.Extension IN [\"css\", \"svg\", \"woff2\", \"woff\", \"ico\", \"png\", \"jpeg\", \"jpg\", \"mp4\"]");
        defaultColorFilters = this.gsonProvider.getGson().fromJson(
                Globals.DEFAULT_COLOR_FILTERS_JSON, new TypeToken<HashMap<UUID, TableColorRule>>(){}.getType());

        defaultlogTableColumns = this.gsonProvider.getGson().fromJson(
                Globals.DEFAULT_LOG_TABLE_COLUMNS_JSON, new TypeToken<List<LogTableColumn>>() {}.getType());
        defaultBlacklistedReflections = new TreeSet(String.CASE_INSENSITIVE_ORDER);
        defaultBlacklistedReflections.addAll(Arrays.asList("0", "1", "true", "false"));
    }

    @Override
    protected void registerTypeAdapters(){
        this.gsonProvider.registerTypeAdapter(LogEntryField.class, new LogEntryFieldSerializer());
        this.gsonProvider.registerTypeAdapter(FilterExpression.class, new FilterExpressionSerializer());
        this.gsonProvider.registerTypeAdapter(Tag.class, new TagSerializer());
        this.gsonProvider.registerTypeAdapter(TableColorRule.class, new TableColorRuleSerializer());
        this.gsonProvider.registerTypeAdapter(SavedFilter.class, new SavedFilterSerializer());
        this.gsonProvider.registerTypeAdapter(LogTableColumn.class, new LogTableColumn.ColumnSerializer());
        this.gsonProvider.registerTypeAdapter(LogEntry.class, new LogEntrySerializer());
    }

    @Override
    protected void registerSettings() {
        prefs.registerSetting(PREF_LOG_LEVEL, Level.class, Level.INFO);
        prefs.registerSetting(PREF_LOG_TO_CONSOLE, Boolean.class, false);
        prefs.registerSetting(PREF_LOG_TABLE_SETTINGS, new TypeToken<List<LogTableColumn>>() {
        }.getType(), defaultlogTableColumns);
        prefs.registerSetting(PREF_UPDATE_ON_STARTUP, Boolean.class, true);
        prefs.registerSetting(PREF_ENABLED, Boolean.class, true);
        prefs.registerSetting(PREF_RESTRICT_TO_SCOPE, Boolean.class, false);
        prefs.registerSetting(PREF_DO_NOT_LOG_IF_MATCH, FilterExpression.class, doNotLogFilter, Preferences.Visibility.GLOBAL);
        prefs.registerSetting(PREF_LOG_GLOBAL, Boolean.class, true);
        prefs.registerSetting(PREF_LOG_PROXY, Boolean.class, true);
        prefs.registerSetting(PREF_LOG_SPIDER, Boolean.class, true);
        prefs.registerSetting(PREF_LOG_INTRUDER, Boolean.class, true);
        prefs.registerSetting(PREF_LOG_SCANNER, Boolean.class, true);
        prefs.registerSetting(PREF_LOG_REPEATER, Boolean.class, true);
        prefs.registerSetting(PREF_LOG_SEQUENCER, Boolean.class, true);
        prefs.registerSetting(PREF_LOG_EXTENSIONS, Boolean.class, true);
        prefs.registerSetting(PREF_LOG_TARGET_TAB, Boolean.class, true);
        prefs.registerSetting(PREF_MAX_RESP_SIZE, Integer.class, 10); //Default 10MB
        prefs.registerSetting(PREF_TABLE_PILL_STYLE, Boolean.class, true);
        prefs.registerSetting(PREF_COLOR_FILTERS, new TypeToken<Map<UUID, TableColorRule>>() {
        }.getType(), defaultColorFilters);
        prefs.registerSetting(PREF_TAG_FILTERS, new TypeToken<Map<UUID, Tag>>() {
        }.getType(), new HashMap<>());
        prefs.registerSetting(PREF_SAVED_FILTERS, new TypeToken<List<SavedFilter>>() {
        }.getType(), new ArrayList<SavedFilter>());
        prefs.registerSetting(PREF_SORT_COLUMN, Integer.class, -1);
        prefs.registerSetting(PREF_SORT_ORDER, SortOrder.class, SortOrder.UNSORTED);
        prefs.registerSetting(PREF_RESPONSE_TIMEOUT, Integer.class, 60);
        prefs.registerSetting(PREF_MAXIMUM_ENTRIES, Integer.class, 1000000);
        prefs.registerSetting(PREF_SEARCH_THREADS, Integer.class, 5);
        prefs.registerSetting(PREF_AUTO_IMPORT_PROXY_HISTORY, Boolean.class, false);
        prefs.registerSetting(PREF_LOG_OTHER_LIVE, Boolean.class, true);
        prefs.registerSetting(PREF_ELASTIC_ADDRESS, String.class, "127.0.0.1");
        prefs.registerSetting(PREF_ELASTIC_PORT, Integer.class, 9200);
        prefs.registerSetting(PREF_ELASTIC_PROTOCOL, Protocol.class, Protocol.HTTP);
        prefs.registerSetting(PREF_ELASTIC_AUTH, Globals.ElasticAuthType.class, ElasticAuthType.Basic);
        prefs.registerSetting(PREF_ELASTIC_CLUSTER_NAME, String.class, "elasticsearch");
        prefs.registerSetting(PREF_ELASTIC_API_KEY_ID, String.class, "");
        prefs.registerSetting(PREF_ELASTIC_API_KEY_SECRET, String.class, "");
        prefs.registerSetting(PREF_ELASTIC_USERNAME, String.class, "");
        prefs.registerSetting(PREF_ELASTIC_PASSWORD, String.class, "");
        prefs.registerSetting(PREF_ELASTIC_INDEX, String.class, "logger");
        prefs.registerSetting(PREF_ELASTIC_DELAY, Integer.class, 120);
        prefs.registerSetting(PREF_ELASTIC_FILTER, String.class, "", Preferences.Visibility.GLOBAL);
        prefs.registerSetting(PREF_ELASTIC_FILTER_PROJECT_PREVIOUS, String.class, null, Preferences.Visibility.PROJECT);
        prefs.registerSetting(PREF_ELASTIC_AUTOSTART_GLOBAL, Boolean.class, false);
        prefs.registerSetting(PREF_ELASTIC_AUTOSTART_PROJECT, Boolean.class, false, Preferences.Visibility.PROJECT);
        prefs.registerSetting(PREF_PREVIOUS_EXPORT_FIELDS, new TypeToken<List<LogEntryField>>() {
        }.getType(), new ArrayList<LogEntry>());
        prefs.registerSetting(PREF_PREVIOUS_ELASTIC_FIELDS, new TypeToken<List<LogEntryField>>() {
        }.getType(), new ArrayList<LogEntry>());
        prefs.registerSetting(PREF_COLUMNS_VERSION, Integer.class, null, Preferences.Visibility.GLOBAL);
        prefs.registerSetting(PREF_SAVED_FIELD_SELECTIONS, new TypeToken<LinkedHashMap<String, LinkedHashMap<LogEntryField, Boolean>>>() {
        }.getType(), new LinkedHashMap<>(), Preferences.Visibility.GLOBAL);

        prefs.registerSetting(PREF_AUTO_SAVE, Boolean.class, false, Preferences.Visibility.VOLATILE);
        prefs.registerSetting(PREF_AUTO_SCROLL, Boolean.class, true, Preferences.Visibility.VOLATILE);

        //Reset table columns if they have been modified by an update.
        if (prefs.getSetting(PREF_COLUMNS_VERSION) == null || (int) prefs.getSetting(PREF_COLUMNS_VERSION) != CURRENT_COLUMN_VERSION) {
            prefs.resetSetting(PREF_LOG_TABLE_SETTINGS);
            prefs.setSetting(PREF_COLUMNS_VERSION, CURRENT_COLUMN_VERSION);
        }
    }

}
