package com.nccgroup.loggerplusplus.filter;

import com.google.gson.*;
import com.nccgroup.loggerplusplus.filter.colorfilter.TableColorRule;

import java.awt.*;
import java.lang.reflect.Type;
import java.util.UUID;

public class TableColorRuleSerializer implements JsonSerializer<TableColorRule>, JsonDeserializer<TableColorRule> {

    @Override
    public JsonElement serialize(TableColorRule tag, Type type, JsonSerializationContext context) {
        JsonObject object = new JsonObject();
        object.addProperty("uid", tag.getUuid().toString());
        object.addProperty("name", tag.getName());
        object.add("filter", context.serialize(tag.getFilterExpression()));
        object.add("foregroundColor", context.serialize(tag.getForegroundColor()));
        object.add("backgroundColor", context.serialize(tag.getBackgroundColor()));
        object.addProperty("enabled", tag.isEnabled());
        object.addProperty("priority", tag.getPriority());
        return object;
    }

    @Override
    public TableColorRule deserialize(JsonElement jsonElement, Type type, JsonDeserializationContext context) throws JsonParseException {
        JsonObject obj = jsonElement.getAsJsonObject();
        String uid = obj.get("uid").getAsString();
        String name = obj.has("name") ? obj.get("name").getAsString() : "";
        FilterExpression filterExpression = context.deserialize(obj.get("filter"), FilterExpression.class);
        Color foregroundColor = context.deserialize(obj.get("foregroundColor"), Color.class);
        Color backgroundColor = context.deserialize(obj.get("backgroundColor"), Color.class);
        boolean enabled = obj.get("enabled").getAsBoolean();
        short priority = obj.get("priority").getAsShort();
        
        TableColorRule tag = new TableColorRule(name, filterExpression);
        tag.setUuid(UUID.fromString(uid));
        tag.setForegroundColor(foregroundColor);
        tag.setBackgroundColor(backgroundColor);
        tag.setEnabled(enabled);
        tag.setPriority(priority);
        return tag;
    }
}
