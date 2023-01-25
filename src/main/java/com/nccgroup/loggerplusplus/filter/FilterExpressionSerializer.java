package com.nccgroup.loggerplusplus.filter;

import com.google.gson.*;
import com.nccgroup.loggerplusplus.filter.parser.ParseException;

import java.lang.reflect.Type;

public class FilterExpressionSerializer implements JsonSerializer<FilterExpression>, JsonDeserializer<FilterExpression> {

    @Override
    public JsonElement serialize(FilterExpression filter, Type type, JsonSerializationContext jsonSerializationContext) {
        JsonObject object = new JsonObject();
        object.addProperty("filter", filter.toString());
        return object;
    }

    @Override
    public FilterExpression deserialize(JsonElement jsonElement, Type type, JsonDeserializationContext jsonDeserializationContext) throws JsonParseException {
        FilterExpression filter = null;
        try {
            filter = new FilterExpression(jsonElement.getAsJsonObject().get("filter").getAsString());
        } catch (ParseException e) {
        }
        return filter;
    }
}
