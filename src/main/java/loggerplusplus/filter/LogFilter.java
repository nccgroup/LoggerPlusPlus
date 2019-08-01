package loggerplusplus.filter;

import com.google.gson.*;
import loggerplusplus.LogEntry;
import loggerplusplus.filter.parser.*;
import loggerplusplus.userinterface.LogTableModel;

import javax.swing.*;
import javax.swing.table.TableModel;
import java.io.IOException;
import java.lang.reflect.Type;
import java.text.DecimalFormat;
import java.text.NumberFormat;

public class LogFilter extends RowFilter<TableModel, Integer> {

    private final ASTExpression filter;
    private final FilterEvaluationVisitor visitor;
    private final String filterString;

    public LogFilter(String filterString) throws ParseException {
        try {
            filter = FilterParser.parseFilter(filterString);
            this.filterString = filterString;
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
        return filterString;
    }

    @Override
    public boolean include(Entry entry) {
        int identifier = (int) entry.getIdentifier();
        TableModel tableModel = (TableModel) entry.getModel();
        if(tableModel instanceof LogTableModel){
            LogEntry logEntry = ((LogTableModel) tableModel).getRow(identifier);
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
