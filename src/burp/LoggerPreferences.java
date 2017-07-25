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

package burp;

import burp.filter.ColorFilter;
import burp.filter.Filter;
import burp.filter.FilterSerializer;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;

import java.io.PrintWriter;
import java.util.Map;
import java.util.UUID;
import java.util.prefs.Preferences;

public class LoggerPreferences {
	private PrintWriter stdout;
	private PrintWriter stderr;
	private boolean isDebug = false;
	Gson gson = new GsonBuilder().registerTypeAdapter(Filter.class, new FilterSerializer()).create();

	private Preferences prefs=Preferences.userRoot().node("Logger++");
	private final double version = 2.83;
	private final String appName = "Burp Suite Logger++";
	private final String author = "Soroush Dalili from NCC Group";
	private final String companyLink = "https://www.nccgroup.trust/";
	private final String authorLink = "https://soroush.secproject.com/";
	private final String projectLink = "https://github.com/CoreyD97/BurpSuiteLoggerPlusPlus";
	private final String projectIssueLink = "https://github.com/nccgroup/BurpSuiteLoggerPlusPlus/issues";
	private final String changeLog = "https://raw.githubusercontent.com/CoreyD97/BurpSuiteLoggerPlusPlus/master/CHANGELOG";
	private final String updateURL = "https://raw.githubusercontent.com/CoreyD97/BurpSuiteLoggerPlusPlus/master/burplogger++.jar";

	enum View {HORIZONTAL, VERTICAL, TABS}

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
	private Map<UUID, ColorFilter> colorFilters;
	private View view;
	private boolean updateOnStartup;


	// Reading from registry constantly is expensive so I have changed the preferences to load them in objects

	public String getTableDetailsJSONString() {
		return tableDetailsJSONString;
	}

	public void setTableDetailsJSONString(String tableDetailsJSONString) {
		// this value is too long to be stored in one registry key
		// it will be stored in multiple keys such as tableDetailsJSONString.1
		// number of chunks is stored in tableDetailsJSONString.size
		String value = tableDetailsJSONString;
		String key = "tableDetailsJSONString";
		int size = value.length();
		int cnt = 1;
		if (size > prefs.MAX_VALUE_LENGTH) {
			for(int idx = 0 ; idx < size ; cnt++) {
				if ((size - idx) > prefs.MAX_VALUE_LENGTH) {
					prefs.put(key + "." + cnt, value.substring(idx,idx+prefs.MAX_VALUE_LENGTH));
					idx += prefs.MAX_VALUE_LENGTH;
				} else {
					prefs.put(key + "." + cnt, value.substring(idx));
					idx = size;
				}
			}
			cnt--;
		} else {
			prefs.put(key+"."+ 1, value);
		}

		prefs.putInt("tableDetailsJSONString.size", cnt);

		this.tableDetailsJSONString = tableDetailsJSONString;
	}

	public synchronized double getVersion() {
		return version;
	}

	private synchronized void setVersion(double version) {
		prefs.putDouble("version", version);
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
		prefs.putBoolean("isDebugMode", isDebugMode);
		this.isDebugMode = isDebugMode;
	}

	public synchronized boolean checkUpdatesOnStartup(){
		return updateOnStartup;
	}

	public synchronized void setUpdateOnStartup(Boolean b){
		this.updateOnStartup = b;
		prefs.putBoolean("updateOnStartup", b);
	}

	public synchronized boolean isEnabled() {

		return isEnabled;
	}

	public synchronized  void setEnabled(boolean isEnabled) {
		prefs.putBoolean("isEnabled", isEnabled);
		this.isEnabled = isEnabled;
	}

	public synchronized boolean isRestrictedToScope() {

		return isRestrictedToScope;
	}


	public synchronized  void setRestrictedToScope(boolean isRestrictedToScope) {
		prefs.putBoolean("isRestrictedToScope", isRestrictedToScope);
		this.isRestrictedToScope = isRestrictedToScope;
	}

	public synchronized boolean isEnabled4All() {

		return isEnabled4All;
	}

	public synchronized  void setEnabled4All(boolean isEnabled4All) {
		prefs.putBoolean("isEnabled4All", isEnabled4All);
		this.isEnabled4All = isEnabled4All;
	}

	public synchronized boolean isEnabled4Proxy() {

		return isEnabled4Proxy;
	}

	public synchronized  void setEnabled4Proxy(boolean isEnabled4Proxy) {
		prefs.putBoolean("isEnabled4Proxy", isEnabled4Proxy);
		this.isEnabled4Proxy = isEnabled4Proxy;
	}

	public synchronized boolean isEnabled4Spider() {

		return isEnabled4Spider;
	}

	public synchronized  void setEnabled4Spider(boolean isEnabled4Spider) {
		prefs.putBoolean("isEnabled4Spider", isEnabled4Spider);
		this.isEnabled4Spider = isEnabled4Spider;
	}

	public synchronized boolean isEnabled4Intruder() {

		return isEnabled4Intruder;
	}

	public synchronized  void setEnabled4Intruder(boolean isEnabled4Intruder) {
		prefs.putBoolean("isEnabled4Intruder", isEnabled4Intruder);
		this.isEnabled4Intruder = isEnabled4Intruder;
	}

	public synchronized boolean isEnabled4Scanner() {

		return isEnabled4Scanner;
	}

	public synchronized  void setEnabled4Scanner(boolean isEnabled4Scanner) {
		prefs.putBoolean("isEnabled4Scanner", isEnabled4Scanner);
		this.isEnabled4Scanner = isEnabled4Scanner;
	}

	public synchronized boolean isEnabled4Repeater() {

		return isEnabled4Repeater;
	}

	public synchronized  void setEnabled4Repeater(boolean isEnabled4Repeater) {
		prefs.putBoolean("isEnabled4Repeater", isEnabled4Repeater);
		this.isEnabled4Repeater = isEnabled4Repeater;
	}

	public synchronized boolean isEnabled4Sequencer() {

		return isEnabled4Sequencer;
	}

	public synchronized  void setEnabled4Sequencer(boolean isEnabled4Sequencer) {
		prefs.putBoolean("isEnabled4Sequencer", isEnabled4Sequencer);
		this.isEnabled4Sequencer = isEnabled4Sequencer;
	}

	public synchronized boolean isEnabled4Extender() {

		return isEnabled4Extender;
	}

	public synchronized  void setEnabled4Extender(boolean isEnabled4Extender) {
		prefs.putBoolean("isEnabled4Extender", isEnabled4Extender);
		this.isEnabled4Extender = isEnabled4Extender;
	}

	public synchronized boolean isEnabled4TargetTab() {

		return isEnabled4TargetTab;
	}

	public synchronized  void setEnabled4TargetTab(boolean isEnabled4TargetTab) {
		prefs.putBoolean("isEnabled4TargetTab", isEnabled4TargetTab);
		this.isEnabled4TargetTab = isEnabled4TargetTab;
	}

	public synchronized void setLoggingFiltered(boolean logFiltered){
		prefs.putBoolean("isLoggingFiltered", logFiltered);
		this.logFiltered = logFiltered;
	}

	public synchronized boolean isLoggingFiltered(){
		return this.logFiltered;
	}

	public Map<UUID, ColorFilter> getColorFilters() { return colorFilters; }

	public synchronized void setColorFilters(Map<UUID, ColorFilter> colorFilters) {
		prefs.put("colorFilters", gson.toJson(colorFilters));
		this.colorFilters = colorFilters;
	}

	public LoggerPreferences(PrintWriter stdout, PrintWriter stderr, boolean isDebug) {
		this.stdout = stdout;
		this.stderr=stderr;
		this.isDebug=isDebug;
		
		if(prefs.getDouble("version", 0.0) < getVersion()){
			// an upgrade has been detected
			// settings should be reset
			MoreHelp.showMessage("A new version of Logger++ has been installed. LogTable settings will be reset in order to prevent any errors.");
			resetTableSettings();
			setVersion(getVersion());
		}else if(prefs.getDouble("version", 0.0) > getVersion()){
			// an upgrade has been detected
			// settings should be reset
			MoreHelp.showMessage("A newer version of Logger++ was installed previously. LogTable settings will be reset in order to prevent any errors.");
			resetTableSettings();
			setVersion(getVersion());
		}

		isDebugMode = prefs.getBoolean("isDebugMode", false);
		updateOnStartup = prefs.getBoolean("updateOnStartup", true);
		isEnabled = prefs.getBoolean("isEnabled", true);
		isRestrictedToScope = prefs.getBoolean("isRestrictedToScope", false);
		isEnabled4All = prefs.getBoolean("isEnabled4All", true);
		isEnabled4Proxy = prefs.getBoolean("isEnabled4Proxy", false);
		isEnabled4TargetTab = prefs.getBoolean("isEnabled4TargetTab", false);
		isEnabled4Extender = prefs.getBoolean("isEnabled4Extender", false);
		isEnabled4Sequencer = prefs.getBoolean("isEnabled4Sequencer", false);
		isEnabled4Repeater = prefs.getBoolean("isEnabled4Repeater", false);
		isEnabled4Scanner = prefs.getBoolean("isEnabled4Scanner", false);
		isEnabled4Intruder = prefs.getBoolean("isEnabled4Intruder", false);
		isEnabled4Spider = prefs.getBoolean("isEnabled4Spider", false);
		logFiltered = prefs.getBoolean("isLoggingFiltered", false);

		int tableDetailsJSONString_size = prefs.getInt("tableDetailsJSONString.size", 1);
		if(tableDetailsJSONString_size > 99) tableDetailsJSONString_size = 1; // lame validation!
		String tempTableDetailsJSONString = "";
		for(int idx = 0 ; idx <= tableDetailsJSONString_size ; idx++) {
			tempTableDetailsJSONString += prefs.get("tableDetailsJSONString."+idx, "");
		}

		this.tableDetailsJSONString = tempTableDetailsJSONString;
		String c = prefs.get("colorFilters", "");
		this.colorFilters = gson.fromJson(prefs.get("colorFilters", ""), new TypeToken<Map<UUID, ColorFilter>>(){}.getType());
		this.view = View.valueOf(prefs.get("layout", "HORIZONTAL"));
	}

	public void resetLoggerPreferences(){
		setDebugMode(false);
		setRestrictedToScope(false);
		setEnabled(true);
		setEnabled4All(true);
		setEnabled4Proxy(false);
		setEnabled4Spider(false);
		setEnabled4Intruder(false);
		setEnabled4Scanner(false);
		setEnabled4Repeater(false);
		setEnabled4Sequencer(false);
		setEnabled4Extender(false);
		setEnabled4TargetTab(false);
		setLoggingFiltered(false);
		setTableDetailsJSONString("");
		setView(View.VERTICAL);
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


	//Do not persist over restarts.
	public void setAutoSave(boolean autoSave) {
		this.autoSave = autoSave;
	}
	public boolean getAutoSave(){
		return this.autoSave;
	}

    public View getView() {
        return this.view;
    }

    public void setView(View view){
		prefs.put("layout", view.toString());
		this.view = view;
	}
}
