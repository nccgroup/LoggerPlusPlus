package com.nccgroup.loggerplusplus.reflection.transformer;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import org.apache.commons.text.StringEscapeUtils;

public class XMLEscapeTransformer extends ParameterValueTransformer {

    public XMLEscapeTransformer(Preferences preferences){
        super(preferences, "XML Escape");
    }

    @Override
    public String transform(String string) {
        return StringEscapeUtils.escapeXml11(string);
    }
}
