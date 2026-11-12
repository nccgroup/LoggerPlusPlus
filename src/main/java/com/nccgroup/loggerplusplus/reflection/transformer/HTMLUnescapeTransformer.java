package com.nccgroup.loggerplusplus.reflection.transformer;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import org.apache.commons.text.StringEscapeUtils;

public class HTMLUnescapeTransformer extends ParameterValueTransformer {

    public HTMLUnescapeTransformer(Preferences preferences){
        super(preferences, "HTML Unescape");
    }

    @Override
    public String transform(String string) {
        // Every HTML entity starts with an ampersand.
        return string.indexOf('&') < 0 ? string : StringEscapeUtils.unescapeHtml4(string);
    }
}
