package com.nccgroup.loggerplusplus.filter;

import com.google.gson.*;
import com.nccgroup.loggerplusplus.filter.savedfilter.SavedFilter;

import java.lang.reflect.Type;
import java.util.UUID;

public class SavedFilterSerializer implements JsonSerializer<SavedFilter>, JsonDeserializer<SavedFilter> {

    @Override
    public JsonElement serialize(SavedFilter tag, Type type, JsonSerializationContext context) {
        JsonObject object = new JsonObject();
        object.addProperty("uid", tag.getUuid().toString());
        object.addProperty("name", tag.getName());
        object.add("filter", context.serialize(tag.getFilterExpression()));
        return object;
    }

    @Override
    public SavedFilter deserialize(JsonElement jsonElement, Type type, JsonDeserializationContext context) throws JsonParseException {
        JsonObject obj = jsonElement.getAsJsonObject();
        String uid = obj.get("uid").getAsString();
        String name = obj.get("name").getAsString();
        FilterExpression filterExpression = context.deserialize(obj.get("filter"), FilterExpression.class);
        
        SavedFilter tag = new SavedFilter(name, filterExpression);
        tag.setUuid(UUID.fromString(uid));
        return tag;
    }
}
