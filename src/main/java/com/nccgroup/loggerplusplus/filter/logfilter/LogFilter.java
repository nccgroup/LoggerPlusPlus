package com.nccgroup.loggerplusplus.filter.logfilter;

import com.google.gson.*;
import com.nccgroup.loggerplusplus.logentry.LogEntry;
import com.nccgroup.loggerplusplus.filter.parser.ASTExpression;
import com.nccgroup.loggerplusplus.filter.parser.FilterEvaluationVisitor;
import com.nccgroup.loggerplusplus.filter.parser.FilterParser;
import com.nccgroup.loggerplusplus.filter.parser.ParseException;
import com.nccgroup.loggerplusplus.userinterface.LogTableModel;

import javax.swing.*;
import javax.swing.table.TableModel;
import java.io.IOException;
import java.lang.reflect.Type;

public class LogFilter extends RowFilter<TableModel, Integer> {

    private final ASTExpression filter;
    private final FilterEvaluationVisitor visitor;

    public LogFilter(String filterString) throws ParseException {
        try {
            filter = FilterParser.parseFilter(filterString);
            visitor = new FilterEvaluationVisitor();
        }catch (IOException e){
            throw new ParseException("Could not read input string.");
        }
    }

    public boolean matches(LogEntry entry){
        return visitor.visit(filter, entry);
    }

    @Override
    public String toString() {
        return filter.toString();
    }

    @Override
    public boolean include(Entry entry) {
        int index = (int) entry.getIdentifier();
        TableModel tableModel = (TableModel) entry.getModel();
        if(tableModel instanceof LogTableModel){
            LogEntry logEntry = ((LogTableModel) tableModel).getRow(index);
            return this.matches(logEntry);
        }
        return false;
    }

    public static class FilterSerializer implements JsonSerializer<LogFilter>, JsonDeserializer<LogFilter> {
        @Override
        public JsonElement serialize(LogFilter filter, Type type, JsonSerializationContext jsonSerializationContext) {
            JsonObject object = new JsonObject();
            object.addProperty("filter", filter.toString());
            return object;
        }

        @Override
        public LogFilter deserialize(JsonElement jsonElement, Type type, JsonDeserializationContext jsonDeserializationContext) throws JsonParseException {
            LogFilter filter = null;
            try {
                filter = new LogFilter(jsonElement.getAsJsonObject().get("filter").getAsString());
            } catch (ParseException e) {}
            return filter;
        }
    }

}
