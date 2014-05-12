package burp;
import java.util.prefs.Preferences;

public class LoggerPreferences {
	private Preferences prefs=Preferences.userRoot().node("Logger++");
	private final double version = 1.0;
	private final String appName = "Burp Suite Logger++";
	private final String author = "Soroush Dalili (@irsdl)";
	private final String authorLink = "https://secproject.com/";
	private final String projectLink = "https://github.com/irsdl/BurpSuiteLoggerPlusPlus";

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
	private boolean isOutputRedirected;


	// Reading from registry constantly is expensive so I have changed the preferences to load them in objects

	public synchronized double getVersion() {
		return version;
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
		this.isDebugMode = prefs.getBoolean("isDebugMode", false);
	}

	public synchronized boolean isEnabled() {

		return isEnabled;
	}

	public synchronized  void setEnabled(boolean isEnabled) {
		prefs.putBoolean("isEnabled", isEnabled);
		this.isEnabled = prefs.getBoolean("isEnabled", true);
	}

	public synchronized boolean isRestrictedToScope() {

		return isRestrictedToScope;
	}


	public synchronized  void setRestrictedToScope(boolean isRestrictedToScope) {
		prefs.putBoolean("isRestrictedToScope", isRestrictedToScope);
		this.isRestrictedToScope = prefs.getBoolean("isRestrictedToScope", false);
	}

	public synchronized boolean isEnabled4All() {

		return isEnabled4All;
	}

	public synchronized  void setEnabled4All(boolean isEnabled4All) {
		prefs.putBoolean("isEnabled4All", isEnabled4All);
		this.isEnabled4All = prefs.getBoolean("isEnabled4All", true);
	}

	public synchronized boolean isEnabled4Proxy() {

		return isEnabled4Proxy;
	}

	public synchronized  void setEnabled4Proxy(boolean isEnabled4Proxy) {
		prefs.putBoolean("isEnabled4Proxy", isEnabled4Proxy);
		this.isEnabled4Proxy = prefs.getBoolean("isEnabled4Proxy", false);
	}

	public synchronized boolean isEnabled4Spider() {

		return isEnabled4Spider;
	}

	public synchronized  void setEnabled4Spider(boolean isEnabled4Spider) {
		prefs.putBoolean("isEnabled4Spider", isEnabled4Spider);
		this.isEnabled4Spider = prefs.getBoolean("isEnabled4Spider", false);
	}

	public synchronized boolean isEnabled4Intruder() {

		return isEnabled4Intruder;
	}

	public synchronized  void setEnabled4Intruder(boolean isEnabled4Intruder) {
		prefs.putBoolean("isEnabled4Intruder", isEnabled4Intruder);
		this.isEnabled4Intruder = prefs.getBoolean("isEnabled4Intruder", false);
	}

	public synchronized boolean isEnabled4Scanner() {

		return isEnabled4Scanner;
	}

	public synchronized  void setEnabled4Scanner(boolean isEnabled4Scanner) {
		prefs.putBoolean("isEnabled4Scanner", isEnabled4Scanner);
		this.isEnabled4Scanner = prefs.getBoolean("isEnabled4Scanner", false);
	}

	public synchronized boolean isEnabled4Repeater() {

		return isEnabled4Repeater;
	}

	public synchronized  void setEnabled4Repeater(boolean isEnabled4Repeater) {
		prefs.putBoolean("isEnabled4Repeater", isEnabled4Repeater);
		this.isEnabled4Repeater = prefs.getBoolean("isEnabled4Repeater", false);
	}

	public synchronized boolean isEnabled4Sequencer() {

		return isEnabled4Sequencer;
	}

	public synchronized  void setEnabled4Sequencer(boolean isEnabled4Sequencer) {
		prefs.putBoolean("isEnabled4Sequencer", isEnabled4Sequencer);
		this.isEnabled4Sequencer = prefs.getBoolean("isEnabled4Sequencer", false);
	}

	public synchronized boolean isEnabled4Extender() {

		return isEnabled4Extender;
	}

	public synchronized  void setEnabled4Extender(boolean isEnabled4Extender) {
		prefs.putBoolean("isEnabled4Extender", isEnabled4Extender);
		this.isEnabled4Extender = prefs.getBoolean("isEnabled4Extender", false);
	}

	public synchronized boolean isEnabled4TargetTab() {

		return isEnabled4TargetTab;
	}

	public synchronized  void setEnabled4TargetTab(boolean isEnabled4TargetTab) {
		prefs.putBoolean("isEnabled4TargetTab", isEnabled4TargetTab);
		this.isEnabled4TargetTab = prefs.getBoolean("isEnabled4TargetTab", false);
	}

	public synchronized boolean isOutputRedirected() {

		return isOutputRedirected;
	}

	public synchronized  void setOutputRedirected(boolean isOutputRedirected) {
		prefs.putBoolean("isOutputRedirected", isOutputRedirected);
		this.isOutputRedirected = prefs.getBoolean("isOutputRedirected", false);
	}



	public LoggerPreferences() {

		isDebugMode = prefs.getBoolean("isDebugMode", false);
		isEnabled = prefs.getBoolean("isEnabled", true);
		isRestrictedToScope = prefs.getBoolean("isRestrictedToScope", false);
		isEnabled4All = prefs.getBoolean("isEnabled4All", true);
		isEnabled4Proxy = prefs.getBoolean("isEnabled4Proxy", false);
		isOutputRedirected = prefs.getBoolean("isOutputRedirected", false);
		isEnabled4TargetTab = prefs.getBoolean("isEnabled4TargetTab", false);
		isEnabled4Extender = prefs.getBoolean("isEnabled4Extender", false);
		isEnabled4Sequencer = prefs.getBoolean("isEnabled4Sequencer", false);
		isEnabled4Repeater = prefs.getBoolean("isEnabled4Repeater", false);
		isEnabled4Scanner = prefs.getBoolean("isEnabled4Scanner", false);
		isEnabled4Intruder = prefs.getBoolean("isEnabled4Intruder", false);
		isEnabled4Spider = prefs.getBoolean("isEnabled4Spider", false);

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
		setOutputRedirected(false);
	}

}
