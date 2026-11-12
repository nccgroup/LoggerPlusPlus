package com.nccgroup.loggerplusplus.logging;

import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonSerializationContext;
import com.google.gson.JsonSerializer;
import java.lang.reflect.Type;

/** How much the extension writes to Burp's output: everything, or all but debugging detail. */
public enum LogLevel {
    DEBUG(500),
    INFO(400);

    private final int intLevel;

    LogLevel(int intLevel) {
        this.intLevel = intLevel;
    }

    /**
     * Reads and writes the level as earlier versions saved it. They kept a Log4j level, which was
     * stored as an object with its name and number; a level saved by them still loads, and what
     * this version saves they can still read.
     */
    public static final class Serializer
            implements JsonSerializer<LogLevel>, JsonDeserializer<LogLevel> {
        @Override
        public JsonElement serialize(LogLevel level, Type type, JsonSerializationContext context) {
            JsonObject saved = new JsonObject();
            saved.addProperty("name", level.name());
            saved.addProperty("intLevel", level.intLevel);
            saved.addProperty("standardLevel", level.name());
            return saved;
        }

        @Override
        public LogLevel deserialize(
                JsonElement saved, Type type, JsonDeserializationContext context) {
            if (saved == null || saved.isJsonNull()) {
                return INFO;
            }
            String name =
                    saved.isJsonObject() && saved.getAsJsonObject().has("name")
                            ? saved.getAsJsonObject().get("name").getAsString()
                            : saved.isJsonPrimitive() ? saved.getAsString() : "";
            // Log4j had levels more talkative than DEBUG; the menu only ever offered DEBUG and
            // INFO.
            return switch (name.toUpperCase(java.util.Locale.ROOT)) {
                case "DEBUG", "TRACE", "ALL" -> DEBUG;
                default -> INFO;
            };
        }
    }
}
