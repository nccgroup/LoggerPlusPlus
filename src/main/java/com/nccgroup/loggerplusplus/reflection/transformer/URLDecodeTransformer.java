package com.nccgroup.loggerplusplus.reflection.transformer;

import com.coreyd97.BurpExtenderUtilities.Preferences;

import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;

public class URLDecodeTransformer extends ParameterValueTransformer {

    public URLDecodeTransformer(Preferences preferences){
        super(preferences, "URL Decode");
    }

    @Override
    public String transform(String string) throws UnsupportedEncodingException {
        return URLDecoder.decode(string, "UTF-8");
    }
}
