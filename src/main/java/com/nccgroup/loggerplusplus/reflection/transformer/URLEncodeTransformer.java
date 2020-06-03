package com.nccgroup.loggerplusplus.reflection.transformer;

import com.coreyd97.BurpExtenderUtilities.Preferences;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

public class URLEncodeTransformer extends ParameterValueTransformer {

    public URLEncodeTransformer(Preferences preferences){
        super(preferences, "URL Encode");
    }

    @Override
    public String transform(String string) throws UnsupportedEncodingException {
        return URLEncoder.encode(string, "UTF-8");
    }
}
