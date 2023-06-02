package com.nccgroup.loggerplusplus.logentry;

import com.google.gson.*;

import java.lang.reflect.Type;

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
