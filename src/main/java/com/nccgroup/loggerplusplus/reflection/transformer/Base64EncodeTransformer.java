package com.nccgroup.loggerplusplus.reflection.transformer;

import com.coreyd97.BurpExtenderUtilities.Preferences;

import java.io.UnsupportedEncodingException;
import java.util.Base64;

public class Base64EncodeTransformer extends ParameterValueTransformer {

    public Base64EncodeTransformer(Preferences preferences){
        super(preferences, "Base64 Encode");
    }

    @Override
    public String transform(String string) throws UnsupportedEncodingException {
        return new String(Base64.getEncoder().encode(string.getBytes()));
    }
}
