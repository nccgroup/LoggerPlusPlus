package com.nccgroup.loggerplusplus.reflection.transformer;

import com.coreyd97.BurpExtenderUtilities.Preferences;

import java.io.UnsupportedEncodingException;
import java.util.HexFormat;

public class HexEncodeTransformer extends ParameterValueTransformer {

    public HexEncodeTransformer(Preferences preferences){
        super(preferences, "Hex Encode");
    }

    @Override
    public String transform(String string) throws UnsupportedEncodingException {
        return HexFormat.of().formatHex(string.getBytes());
    }
}
