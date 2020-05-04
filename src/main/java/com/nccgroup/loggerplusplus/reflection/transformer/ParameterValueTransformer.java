package com.nccgroup.loggerplusplus.reflection.transformer;

import com.coreyd97.BurpExtenderUtilities.Preferences;

public abstract class ParameterValueTransformer {

    protected final Preferences preferences;
    private final String name;
    private final String enabledPrefKey;
    private boolean enabled;

    ParameterValueTransformer(Preferences preferences, String name){
        this.preferences = preferences;
        this.name = name;
        this.enabledPrefKey = "ParamTransformer_" + name + "_Enabled";
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

    public abstract String transform(String value) throws Exception;
}
