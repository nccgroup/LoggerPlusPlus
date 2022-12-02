package com.nccgroup.loggerplusplus.reflection.transformer;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import org.apache.commons.codec.binary.Hex;

import java.io.UnsupportedEncodingException;

public class HexEncodeTransformer extends ParameterValueTransformer {

    public HexEncodeTransformer(Preferences preferences){
        super(preferences, "Hex Encode");
    }

    @Override
    public String transform(String string) throws UnsupportedEncodingException {
        return Hex.encodeHexString(string.getBytes());
    }
}
