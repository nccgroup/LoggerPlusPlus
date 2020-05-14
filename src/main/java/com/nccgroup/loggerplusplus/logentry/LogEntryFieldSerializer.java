package com.nccgroup.loggerplusplus.logentry;

import com.google.gson.*;

import java.lang.reflect.Type;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;

public class LogEntryFieldSerializer implements JsonSerializer<LogEntryField>, JsonDeserializer<LogEntryField> {

    @Override
    public LogEntryField deserialize(JsonElement json, Type typeOfT, JsonDeserializationContext context) throws JsonParseException {
        return LogEntryField.getByFullyQualifiedName(json.getAsString());
    }

    @Override
    public JsonElement serialize(LogEntryField src, Type typeOfSrc, JsonSerializationContext context) {
        return context.serialize(src.getFullLabel());
    }
}
