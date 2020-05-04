package com.nccgroup.loggerplusplus.reflection.transformer;

import com.coreyd97.BurpExtenderUtilities.Preferences;

import java.io.UnsupportedEncodingException;
import java.util.Base64;

public class Base64DecodeTransformer extends ParameterValueTransformer {

    public Base64DecodeTransformer(Preferences preferences){
        super(preferences, "Base64 Decode");
    }

    @Override
    public String transform(String string) throws UnsupportedEncodingException {
        return new String(Base64.getDecoder().decode(string.getBytes()));
    }
}
