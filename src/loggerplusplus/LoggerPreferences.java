//
// Burp Suite Logger++
// 
// Released as open source by NCC Group Plc - https://www.nccgroup.trust/
// 
// Developed by Soroush Dalili (@irsdl)
//
// Project link: http://www.github.com/nccgroup/BurpSuiteLoggerPlusPlus
//
// Released under AGPL see LICENSE for more information
//

package loggerplusplus;

import burp.BurpExtender;
import loggerplusplus.filter.ColorFilter;
import loggerplusplus.filter.Filter;
import loggerplusplus.filter.SavedFilter;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonSyntaxException;
import com.google.gson.reflect.TypeToken;
import loggerplusplus.userinterface.VariableViewPanel.View;

import javax.swing.*;
import java.lang.reflect.Type;
import java.util.*;

public class LoggerPreferences {
	private final LoggerPlusPlus loggerPlusPlus;
	private Gson gson = new GsonBuilder().registerTypeAdapter(Filter.class, new Filter.FilterSerializer()).create();
	static final double version = 3.05;
	static final String appName = "Burp Suite Logger++";
	static final String author = "Soroush Dalili (@irsdl), Corey Arthur (@CoreyD97) from NCC Group";
	static final String companyLink = "https://www.nccgroup.trust/";
	static final String authorLink = "https://soroush.secproject.com/";
	static final String projectLink = "https://github.com/NCCGroup/BurpSuiteLoggerPlusPlus";
	static final String projectIssueLink = "https://github.com/nccgroup/BurpSuiteLoggerPlusPlus/issues";
	static final String changeLog = "https://raw.githubusercontent.com/NCCGroup/BurpSuiteLoggerPlusPlus/master/CHANGELOG";
	static final String updateURL = "https://raw.githubusercontent.com/NCCGroup/BurpSuiteLoggerPlusPlus/master/burplogger++.jar";
	private int sortColumn;
	private SortOrder sortOrder;
	private boolean autoScroll = true;

	private boolean isDebugMode;

	private boolean isEnabled;
	private boolean isRestrictedToScope;
	private boolean isEnabled4All;
	private boolean isEnabled4Proxy;
	private boolean isEnabled4Spider;
	private boolean isEnabled4Intruder;
	private boolean isEnabled4Scanner;
	private boolean isEnabled4Repeater;
	private boolean isEnabled4Sequencer;
	private boolean isEnabled4Extender;
	private boolean isEnabled4TargetTab;
	private boolean logFiltered;
	private String tableDetailsJSONString;
	private boolean autoSave;
	private ArrayList<SavedFilter> savedFilters;
	private Map<UUID, ColorFilter> colorFilters;
	private View view;
	private View reqRespView;
	private boolean updateOnStartup;
	private long responseTimeout;
	private int maximumEntries;
	private boolean canSaveCSV;

	// Reading from registry constantly is expensive so I have changed the preferences to load them in objects

	public String getTableDetailsJSONString() {
		return tableDetailsJSONString;
	}

	public void setTableDetailsJSONString(String tableDetailsJSONString) {
		BurpExtender.getCallbacks().saveExtensionSetting("tabledetailsjson", tableDetailsJSONString);
		this.tableDetailsJSONString = tableDetailsJSONString;
	}

	public synchronized double getVersion() {
		return version;
	}

	private synchronized void setVersion(double version) {
		BurpExtender.getCallbacks().saveExtensionSetting("version", String.valueOf(version));
	}

	public synchronized String getProjectLink() {
		return projectLink;
	}

	public synchronized String getAppInfo() {
		return "Name: "+appName + " | Version: " + String.valueOf(version) + " | Source: " + projectLink + " | Author: " + author;
	}

	public synchronized boolean isDebugMode() {
		return isDebugMode;
	}


	public synchronized void setDebugMode(boolean isDebugMode) {
		BurpExtender.getCallbacks().saveExtensionSetting("isDebug", String.valueOf(isDebugMode));
		this.isDebugMode = isDebugMode;
	}

	public synchronized boolean checkUpdatesOnStartup(){
		return updateOnStartup;
	}

	public synchronized void setUpdateOnStartup(Boolean b){
		BurpExtender.getCallbacks().saveExtensionSetting("updateonstartup", String.valueOf(b));
		this.updateOnStartup = b;
	}

	public synchronized boolean isEnabled() {
		return isEnabled;
	}

	public synchronized  void setEnabled(boolean isEnabled) {
		BurpExtender.getCallbacks().saveExtensionSetting("enabled", String.valueOf(isEnabled));
		this.isEnabled = isEnabled;
	}

	public synchronized boolean isRestrictedToScope() {
		return isRestrictedToScope;
	}


	public synchronized  void setRestrictedToScope(boolean isRestrictedToScope) {
		BurpExtender.getCallbacks().saveExtensionSetting("restricttoscope", String.valueOf(isRestrictedToScope));
		this.isRestrictedToScope = isRestrictedToScope;
	}

	public synchronized boolean isEnabled4All() {
		return isEnabled4All;
	}

	public synchronized  void setEnabled4All(boolean isEnabled4All) {
		BurpExtender.getCallbacks().saveExtensionSetting("logglobal", String.valueOf(isEnabled4All));
		this.isEnabled4All = isEnabled4All;
	}

	public synchronized boolean isEnabled4Proxy() {
		return isEnabled4Proxy;
	}

	public synchronized  void setEnabled4Proxy(boolean isEnabled4Proxy) {
		BurpExtender.getCallbacks().saveExtensionSetting("logproxy", String.valueOf(isEnabled4Proxy));
		this.isEnabled4Proxy = isEnabled4Proxy;
	}

	public synchronized boolean isEnabled4Spider() {
		return isEnabled4Spider;
	}

	public synchronized  void setEnabled4Spider(boolean isEnabled4Spider) {
		BurpExtender.getCallbacks().saveExtensionSetting("logspider", String.valueOf(isEnabled4Spider));
		this.isEnabled4Spider = isEnabled4Spider;
	}

	public synchronized boolean isEnabled4Intruder() {
		return isEnabled4Intruder;
	}

	public synchronized  void setEnabled4Intruder(boolean isEnabled4Intruder) {
		BurpExtender.getCallbacks().saveExtensionSetting("logintruder", String.valueOf(isEnabled4Intruder));
		this.isEnabled4Intruder = isEnabled4Intruder;
	}

	public synchronized boolean isEnabled4Scanner() {
		return isEnabled4Scanner;
	}

	public synchronized  void setEnabled4Scanner(boolean isEnabled4Scanner) {
		BurpExtender.getCallbacks().saveExtensionSetting("logscanner", String.valueOf(isEnabled4Scanner));
		this.isEnabled4Scanner = isEnabled4Scanner;
	}

	public synchronized boolean isEnabled4Repeater() {
		return isEnabled4Repeater;
	}

	public synchronized  void setEnabled4Repeater(boolean isEnabled4Repeater) {
		BurpExtender.getCallbacks().saveExtensionSetting("logrepeater", String.valueOf(isEnabled4Repeater));
		this.isEnabled4Repeater = isEnabled4Repeater;
	}

	public synchronized boolean isEnabled4Sequencer() {
		return isEnabled4Sequencer;
	}

	public synchronized  void setEnabled4Sequencer(boolean isEnabled4Sequencer) {
		BurpExtender.getCallbacks().saveExtensionSetting("logsequencer", String.valueOf(isEnabled4Sequencer));
		this.isEnabled4Sequencer = isEnabled4Sequencer;
	}

	public synchronized boolean isEnabled4Extender() {
		return isEnabled4Extender;
	}

	public synchronized  void setEnabled4Extender(boolean isEnabled4Extender) {
		BurpExtender.getCallbacks().saveExtensionSetting("logextender", String.valueOf(isEnabled4Extender));
		this.isEnabled4Extender = isEnabled4Extender;
	}

	public synchronized boolean isEnabled4TargetTab() {
		return isEnabled4TargetTab;
	}

	public synchronized  void setEnabled4TargetTab(boolean isEnabled4TargetTab) {
		BurpExtender.getCallbacks().saveExtensionSetting("logtargettab", String.valueOf(isEnabled4TargetTab));
		this.isEnabled4TargetTab = isEnabled4TargetTab;
	}

	public synchronized void setLoggingFiltered(boolean logFiltered){
		BurpExtender.getCallbacks().saveExtensionSetting("filterlog", String.valueOf(logFiltered));
		this.logFiltered = logFiltered;
	}

	public synchronized boolean isLoggingFiltered(){
		return this.logFiltered;
	}

	public Map<UUID, ColorFilter> getColorFilters() { return colorFilters; }

	public synchronized void setColorFilters(Map<UUID, ColorFilter> colorFilters) {
		BurpExtender.getCallbacks().saveExtensionSetting("colorfilters", gson.toJson(colorFilters));
		this.colorFilters = colorFilters;
	}

	public synchronized ArrayList<SavedFilter> getSavedFilters() {
		if(savedFilters == null){
			setSavedFilters(new ArrayList<SavedFilter>());
		}
		return savedFilters;
	}

	public synchronized void setSavedFilters(ArrayList<SavedFilter> savedFilters) {
		Type type = new TypeToken<List<SavedFilter>>() {}.getType();
		BurpExtender.getCallbacks().saveExtensionSetting("savedfilters", gson.toJson(savedFilters, type));
		this.savedFilters = savedFilters;
	}

	public synchronized void setSortColumn(int columnIdentifier) {
		BurpExtender.getCallbacks().saveExtensionSetting("sortcolumn", String.valueOf(columnIdentifier));
		this.sortColumn = columnIdentifier;
	}

	public synchronized int getSortColumn(){
		return this.sortColumn;
	}

	public synchronized void setSortOrder(SortOrder sortOrder){
		String order = sortOrder == null ? null : String.valueOf(sortOrder);
		BurpExtender.getCallbacks().saveExtensionSetting("sortorder", order);
		this.sortOrder = sortOrder;
	}

	public synchronized SortOrder getSortOrder(){
		return this.sortOrder;
	}

	public void setResponseTimeout(long responseTimeout){
		BurpExtender.getCallbacks().saveExtensionSetting("responsetimeout", String.valueOf(responseTimeout));
		this.responseTimeout = responseTimeout;
	}

	public long getResponseTimeout(){
		return responseTimeout;
	}

	public void setMaximumEntries(int maximumEntries) {
		BurpExtender.getCallbacks().saveExtensionSetting("maximumentries", String.valueOf(maximumEntries));
		this.maximumEntries = maximumEntries;
	}

	public int getMaximumEntries() {
		return maximumEntries;
	}

	public View getView() {
		return this.view;
	}

	public void setView(View view){
		BurpExtender.getCallbacks().saveExtensionSetting("layout", String.valueOf(view));
		this.view = view;
	}

	public void setReqRespView(View reqRespView) {
		BurpExtender.getCallbacks().saveExtensionSetting("msgviewlayout", String.valueOf(reqRespView));
		this.reqRespView = reqRespView;
	}

	public View getReqRespView() {
		return reqRespView;
	}


	//Do not persist over restarts.
	public void setAutoSave(boolean autoSave) {
		this.autoSave = autoSave;
		if(loggerPlusPlus.getLoggerOptionsPanel() != null)
			loggerPlusPlus.getLoggerOptionsPanel().setAutoSaveBtn(autoSave);
	}
	public boolean getAutoSave(){
		return this.autoSave;
	}

	public void setAutoScroll(boolean autoScroll) {
		this.autoScroll = autoScroll;
	}

	public boolean getAutoScroll() {
		return autoScroll;
	}


	public LoggerPreferences(LoggerPlusPlus loggerPlusPlus) {
		this.loggerPlusPlus = loggerPlusPlus;
		double pastVersion = getDoubleSetting("version", 0.0);
		if(pastVersion < getVersion()){
			MoreHelp.showMessage("A new version of Logger++ has been installed. LogTable settings have be reset.");
			setVersion(getVersion());
			resetTableSettings();
		}else if(pastVersion > getVersion()){
			MoreHelp.showMessage("A newer version of Logger++ was installed previously. LogTable settings have been reset.");
			setVersion(getVersion());
			resetTableSettings();
		}

		loadAllSettings();
	}

	private void loadAllSettings(){
		String defaultColorFilter = "{\"2add8ace-b652-416a-af08-4d78c5d22bc7\":{\"uid\":\"2add8ace-b652-416a-af08-4d78c5d22bc7\"," +
				"\"filter\":{\"filter\":\"!COMPLETE\"},\"filterString\":\"!COMPLETE\",\"backgroundColor\":{\"value\":-16777216,\"falpha\":0.0}," +
				"\"foregroundColor\":{\"value\":-65536,\"falpha\":0.0},\"enabled\":true,\"modified\":false,\"shouldRetest\":true,\"priority\":1}}";
		isDebugMode = getBooleanSetting("isDebug", false);
		updateOnStartup = getBooleanSetting("updateonstartup", true);
		isEnabled = getBooleanSetting("enabled", true);
		isRestrictedToScope = getBooleanSetting("restricttoscope", false);
		isEnabled4All = getBooleanSetting("logglobal", true);
		isEnabled4Proxy = getBooleanSetting("logproxy", true);
		isEnabled4TargetTab = getBooleanSetting("logtargettab", true);
		isEnabled4Extender = getBooleanSetting("logextender", true);
		isEnabled4Sequencer = getBooleanSetting("logsequencer", true);
		isEnabled4Repeater = getBooleanSetting("logrepeater", true);
		isEnabled4Scanner = getBooleanSetting("logscanner", true);
		isEnabled4Intruder = getBooleanSetting("logintruder", true);
		isEnabled4Spider = getBooleanSetting("logspider", true);
		logFiltered = getBooleanSetting("filterlog", false);
		tableDetailsJSONString = getStringSetting("tabledetailsjson", "");
		String colorFilters = getStringSetting("colorfilters", defaultColorFilter);
		try {
			this.colorFilters = gson.fromJson(colorFilters, new TypeToken<Map<UUID, ColorFilter>>() {}.getType());
		}catch (JsonSyntaxException jSException){}
		if(this.colorFilters == null) this.colorFilters = new HashMap<UUID, ColorFilter>();
		String savedFilters = getStringSetting("savedfilters", "");
		try{
			this.savedFilters = gson.fromJson(savedFilters, new TypeToken<List<SavedFilter>>(){}.getType());
		}catch (JsonSyntaxException jSException){}
		if(this.savedFilters == null) this.savedFilters = new ArrayList<SavedFilter>();
		BurpExtender.getCallbacks().printOutput("Loaded " + this.savedFilters.size() + " filters.");
		BurpExtender.getCallbacks().printOutput("Loaded " + this.colorFilters.size() + " color filters.");
		this.sortColumn = getIntSetting("sortcolumn", -1);
		try {
			this.sortOrder = SortOrder.valueOf(getStringSetting("sortorder", "ASCENDING"));
		}catch (Exception e){
			this.sortOrder = SortOrder.ASCENDING;
		}
		responseTimeout = getLongSetting("responsetimeout", 60000);
		maximumEntries = getIntSetting("maximumentries", 5000);
		view = View.valueOf(getStringSetting("layout", "VERTICAL"));
		reqRespView = View.valueOf(getStringSetting("msgviewlayout", "HORIZONTAL"));
	}

	private Boolean getBooleanSetting(String setting, Boolean fallback){
		String val = BurpExtender.getCallbacks().loadExtensionSetting(setting);
		if(val == null) return fallback;
		try {
			return Boolean.valueOf(val);
		}catch(NullPointerException nPException){
			return fallback;
		}
	}

	private Double getDoubleSetting(String setting, Double fallback){
		String val = BurpExtender.getCallbacks().loadExtensionSetting(setting);
		try {
			return Double.valueOf(val);
		}catch(NullPointerException nPException){
			return fallback;
		}
	}

	private Long getLongSetting(String setting, long fallback){
		String val = BurpExtender.getCallbacks().loadExtensionSetting(setting);
		try {
			return Long.valueOf(val);
		}catch(NullPointerException | NumberFormatException nPException){
			return fallback;
		}
	}

	private int getIntSetting(String setting, int fallback){
		String val = BurpExtender.getCallbacks().loadExtensionSetting(setting);
		try {
			return Integer.valueOf(val);
		}catch(NullPointerException | NumberFormatException nPException){
			return fallback;
		}
	}

	private String getStringSetting(String setting, String fallback){
		String val = BurpExtender.getCallbacks().loadExtensionSetting(setting);
		return val != null ? val : fallback;
	}

	public void resetLoggerPreferences(){
		setDebugMode(false);
		setRestrictedToScope(false);
		setUpdateOnStartup(true);
		setEnabled(true);
		setEnabled4All(true);
		setEnabled4Proxy(true);
		setEnabled4Spider(true);
		setEnabled4Intruder(true);
		setEnabled4Scanner(true);
		setEnabled4Repeater(true);
		setEnabled4Sequencer(true);
		setEnabled4Extender(true);
		setEnabled4TargetTab(true);
		setLoggingFiltered(false);
		loggerPlusPlus.getLogSplitPanel().setView(View.VERTICAL);
		loggerPlusPlus.getReqRespPanel().setView(View.HORIZONTAL);

		setAutoSave(false);
		resetTableSettings();
	}

	private void clearSettings(){
		BurpExtender.getCallbacks().saveExtensionSetting("isDebug", null);
		BurpExtender.getCallbacks().saveExtensionSetting("updateonstartup", null);
		BurpExtender.getCallbacks().saveExtensionSetting("enabled", null);
		BurpExtender.getCallbacks().saveExtensionSetting("restricttoscope", null);
		BurpExtender.getCallbacks().saveExtensionSetting("logglobal", null);
		BurpExtender.getCallbacks().saveExtensionSetting("logproxy", null);
		BurpExtender.getCallbacks().saveExtensionSetting("logtargettab", null);
		BurpExtender.getCallbacks().saveExtensionSetting("logextender", null);
		BurpExtender.getCallbacks().saveExtensionSetting("logsequencer", null);
		BurpExtender.getCallbacks().saveExtensionSetting("logrepeater", null);
		BurpExtender.getCallbacks().saveExtensionSetting("logscanner", null);
		BurpExtender.getCallbacks().saveExtensionSetting("logintruder", null);
		BurpExtender.getCallbacks().saveExtensionSetting("logspider", null);
		BurpExtender.getCallbacks().saveExtensionSetting("filterlog", null);
		BurpExtender.getCallbacks().saveExtensionSetting("tabledetailsjson", null);
		BurpExtender.getCallbacks().saveExtensionSetting("responsetimeout", null);
		BurpExtender.getCallbacks().saveExtensionSetting("maximumentries", null);
		BurpExtender.getCallbacks().saveExtensionSetting("layout", null);
		BurpExtender.getCallbacks().saveExtensionSetting("msgviewlayout", null);
	}
	
	public void resetTableSettings(){
		setTableDetailsJSONString("");
	}

	public String getProjectIssueLink() {
		return projectIssueLink;
	}

	public String getChangeLog() {
		return changeLog;
	}

	public String getAuthorLink() {
		return authorLink;
	}

	public String getCompanyLink() {
		return companyLink;
	}

	public String getAppName() {
		return appName;
	}

	public String getAuthor() {
		return author;
	}

	public String getUpdateURL() { return updateURL; }

	public void setCanSaveCSV(boolean canSaveCSV) {
		this.canSaveCSV = canSaveCSV;
	}

	public boolean canSaveCSV() {
		return canSaveCSV;
	}
}
