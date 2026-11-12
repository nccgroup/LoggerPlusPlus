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

    /**
     * Whether HTML, XML and JSON escaping all leave {@code value} as it is: every character is
     * printable ASCII and none is one of {@code " & ' < > / \}. Most parameter values are like
     * this, and running them through an escaper only to get the same string back was a third of
     * the cost of reflection detection.
     */
    static boolean needsNoEscaping(String value) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (c < ' ' || c > '~' || c == '"' || c == '&' || c == '\'' || c == '<' || c == '>'
                    || c == '/' || c == '\\') {
                return false;
            }
        }
        return true;
    }
}
