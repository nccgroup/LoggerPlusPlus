package com.nccgroup.loggerplusplus.reflection.transformer;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import org.apache.commons.text.StringEscapeUtils;

public class HTMLUnescapeTransformer extends ParameterValueTransformer {

    public HTMLUnescapeTransformer(Preferences preferences){
        super(preferences, "HTML Unescape");
    }

    @Override
    public String transform(String string) {
        return StringEscapeUtils.unescapeHtml4(string);
    }
}
