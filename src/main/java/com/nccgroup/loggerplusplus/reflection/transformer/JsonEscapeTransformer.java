package com.nccgroup.loggerplusplus.reflection.transformer;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import org.apache.commons.text.StringEscapeUtils;

public class JsonEscapeTransformer extends ParameterValueTransformer {

    public JsonEscapeTransformer(Preferences preferences){
        super(preferences, "Json Escape");
    }

    @Override
    public String transform(String string) {
        return StringEscapeUtils.escapeJson(string);
    }
}
