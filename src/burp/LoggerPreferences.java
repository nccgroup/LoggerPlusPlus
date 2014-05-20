//
// Burp Suite Logger++
// 
// Released as open source by NCC Group Plc - http://www.nccgroup.com/
// 
// Developed by Soroush Dalili, soroush dot dalili at nccgroup dot com
//
// http://www.github.com/nccgroup/BurpSuiteLoggerPlusPlus
//
// Released under AGPL see LICENSE for more information
//

package burp;
import java.util.prefs.Preferences;

public class LoggerPreferences {
	private Preferences prefs=Preferences.userRoot().node("Logger++");
	private final double version = 1.1;
	private final String appName = "Burp Suite Logger++";
	private final String author = "Soroush Dalili from NCC Group";
	private final String authorLink = "https://www.nccgroup.com/";
	private final String projectLink = "https://github.com/nccgroup/BurpSuiteLoggerPlusPlus";

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
		this.isDebugMode = isDebugMode;
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

	public synchronized boolean isOutputRedirected() {

		return isOutputRedirected;
	}

	public synchronized  void setOutputRedirected(boolean isOutputRedirected) {
		prefs.putBoolean("isOutputRedirected", isOutputRedirected);
		this.isOutputRedirected = isOutputRedirected;
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
		setEnabled4TargetTab(false);
		setOutputRedirected(false);
	}

}
