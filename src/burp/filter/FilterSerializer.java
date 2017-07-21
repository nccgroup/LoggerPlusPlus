package burp.filter;

import com.google.gson.*;

import java.lang.reflect.Type;

/**
 * Created by corey on 21/07/17.
 */
public class FilterSerializer implements JsonSerializer<Filter>, JsonDeserializer<Filter>{
    @Override
    public JsonElement serialize(Filter filter, Type type, JsonSerializationContext jsonSerializationContext) {
        JsonObject object = new JsonObject();
        object.addProperty("filter", filter.toString());
        return object;
    }

    @Override
    public Filter deserialize(JsonElement jsonElement, Type type, JsonDeserializationContext jsonDeserializationContext) throws JsonParseException {
        Filter filter = null;
        try {
            filter = FilterCompiler.parseString(jsonElement.getAsJsonObject().get("filter").getAsString());
        } catch (Filter.FilterException e) {}
        return filter;
    }
}
