package com.nccgroup.loggerplusplus.reflection.transformer;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import org.apache.commons.text.StringEscapeUtils;

public class XMLUnescapeTransformer extends ParameterValueTransformer {

    public XMLUnescapeTransformer(Preferences preferences){
        super(preferences, "XML Unescape");
    }

    @Override
    public String transform(String string) {
        // Every XML entity starts with an ampersand.
        return string.indexOf('&') < 0 ? string : StringEscapeUtils.unescapeXml(string);
    }
}
