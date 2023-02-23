package com.nccgroup.loggerplusplus.reflection.filter;

import burp.api.montoya.http.message.params.HttpParameter;
import com.coreyd97.BurpExtenderUtilities.Preferences;

public abstract class ParameterFilter {

    protected final Preferences preferences;
    private final String name;
    private final String enabledPrefKey;
    private boolean enabled;

    ParameterFilter(Preferences preferences, String name){
        this.preferences = preferences;
        this.name = name;
        this.enabledPrefKey = "ParamFilter_" + name + "_Enabled";
        preferences.registerSetting(enabledPrefKey, boolean.class, true);
        this.enabled = preferences.getSetting(enabledPrefKey);
    }

    public String getName(){
        return this.name;
    };

    public void setEnabled(boolean enabled){
        this.enabled = enabled;
        preferences.setSetting(enabledPrefKey, enabled);
    }

    public boolean isEnabled() {
        return enabled;
    }

    public abstract boolean isFiltered(HttpParameter parameter);
    public abstract void showConfigDialog();

}
