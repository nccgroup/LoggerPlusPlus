package com.nccgroup.loggerplusplus.reflection.transformer;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.text.StringEscapeUtils;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

public class HTMLEscapeTransformer extends ParameterValueTransformer {

    public HTMLEscapeTransformer(Preferences preferences){
        super(preferences, "HTML Escape");
    }

    @Override
    public String transform(String string) {
        return StringEscapeUtils.escapeHtml4(string);
    }
}
