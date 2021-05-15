package com.nccgroup.loggerplusplus.filter.logfilter;

import com.google.gson.*;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.filter.ComparisonOperator;
import com.nccgroup.loggerplusplus.filter.LogicalOperator;
import com.nccgroup.loggerplusplus.filter.parser.ASTExpression;
import com.nccgroup.loggerplusplus.filter.parser.FilterEvaluationVisitor;
import com.nccgroup.loggerplusplus.filter.parser.FilterParser;
import com.nccgroup.loggerplusplus.filter.parser.ParseException;
import com.nccgroup.loggerplusplus.filterlibrary.FilterLibraryController;
import com.nccgroup.loggerplusplus.logentry.LogEntry;
import com.nccgroup.loggerplusplus.logentry.LogEntryField;
import com.nccgroup.loggerplusplus.logview.logtable.LogTableModel;

import javax.swing.*;
import javax.swing.table.TableModel;
import java.lang.reflect.Type;

public class LogFilter extends RowFilter<TableModel, Integer> {

    private final ASTExpression filter;

    public LogFilter(String filterString) throws ParseException {
        filter = FilterParser.parseFilter(filterString);
    }

    public LogFilter(FilterLibraryController filterLibraryController, String filterString) throws ParseException {
        this(filterString);
        FilterParser.checkAliasesForSanity(filterLibraryController, this.filter);
    }

    public String addConditionToFilter(LogicalOperator logicalOperator, LogEntryField field,
                                       ComparisonOperator booleanOperator, String value) {
        //TODO Move functionality to LogFilter itself.
        String existing;
        if (this.getAST().getLogicalOperator() != null && !this.getAST().getLogicalOperator().equals(logicalOperator)) {
            existing = "(" + this.filter.getFilterString() + ")";
        } else {
            existing = this.filter.getFilterString();
        }

        return String.format("%s %s %s %s %s", existing, logicalOperator.toString(), field.toString(), booleanOperator, value);
    }

    public ASTExpression getAST(){
        return this.filter;
    }

    public boolean matches(LogEntry entry){
        FilterEvaluationVisitor visitor = new FilterEvaluationVisitor(LoggerPlusPlus.instance.getLibraryController());
        return visitor.visit(filter, entry);
    }

    @Override
    public String toString() {
        return filter.getFilterString();
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
