package com.nccgroup.loggerplusplus.reflection.filter;

import burp.api.montoya.http.message.params.HttpParameter;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.google.gson.reflect.TypeToken;
import com.nccgroup.loggerplusplus.util.MoreHelp;
import org.apache.commons.lang3.StringUtils;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.TreeSet;

public class BlacklistFilter extends ParameterFilter {

    private static String BLACKLIST_PREF = "parameterValueBlacklist";
    private static HashSet<String> defaultBlacklist = new HashSet<>(Arrays.asList("0","1","true","false"));

    private final Set<String> blacklist = new TreeSet<String>(String.CASE_INSENSITIVE_ORDER);

    public BlacklistFilter(Preferences preferences){
        super(preferences, "Value Blacklist");
        preferences.registerSetting(BLACKLIST_PREF, new TypeToken<Set<String>>(){}.getType(), defaultBlacklist);

        blacklist.addAll(preferences.getSetting(BLACKLIST_PREF));
    }

    @Override
    public boolean isFiltered(HttpParameter parameter) {
        return blacklist.contains(parameter.value());
    }

    @Override
    public void showConfigDialog() {
        String valueString = MoreHelp.showPlainInputMessage("Enter comma separated blacklist values:", "Parameter Value Blacklist", StringUtils.join(blacklist, ","));
        String[] values = valueString.split(",");
        blacklist.clear();
        for (String value : values) {
            if(!value.isEmpty()) {
                blacklist.add(value.trim());
            }
        }
        preferences.setSetting(BLACKLIST_PREF, blacklist);
    }
}
