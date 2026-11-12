package com.nccgroup.loggerplusplus.reflection.transformer;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import org.apache.commons.text.StringEscapeUtils;

public class JsonUnescapeTransformer extends ParameterValueTransformer {

    public JsonUnescapeTransformer(Preferences preferences){
        super(preferences, "Json Unescape");
    }

    @Override
    public String transform(String string) {
        // Every JSON escape starts with a backslash.
        return string.indexOf('\\') < 0 ? string : StringEscapeUtils.unescapeJson(string);
    }
}
