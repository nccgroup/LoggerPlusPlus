package com.nccgroup.loggerplusplus.reflection.transformer;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import org.apache.commons.text.StringEscapeUtils;

public class JsonUnescapeTransformer extends ParameterValueTransformer {

    public JsonUnescapeTransformer(Preferences preferences){
        super(preferences, "Json Unescape");
    }

    @Override
    public String transform(String string) {
        return StringEscapeUtils.unescapeJson(string);
    }
}
