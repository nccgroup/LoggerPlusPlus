package loggerplusplus.filter;

import com.google.gson.*;
import loggerplusplus.LogEntry;
import loggerplusplus.filter.parser.*;
import loggerplusplus.userinterface.LogTableColumn;
import loggerplusplus.userinterface.LogTableModel;
import org.apache.commons.lang3.StringEscapeUtils;
import org.apache.commons.lang3.StringUtils;

import javax.swing.*;
import javax.swing.table.TableModel;
import java.lang.reflect.Type;
import java.text.DecimalFormat;
import java.text.NumberFormat;
import java.util.UUID;
import java.util.regex.Pattern;

public class LogFilter extends RowFilter<TableModel, Integer> {

    String originalString;
    SimpleNode root;
    static final NumberFormat numberFormat = new DecimalFormat("##.###");

    public LogFilter(String filterString) throws ParseException {
        this.originalString = filterString;
        try {
            root = SyntaxChecker.parseFilter(filterString);
        }catch (TokenMgrError | Exception e){
            throw new ParseException("Could not parse the filter.");
        }

        //Find identifiers, check valid
        checkIdentifiers(root);
        simplify(root);
    }

    private void checkIdentifiers(SimpleNode simpleNode) throws ParseException {
        for (int i = 0; i < simpleNode.jjtGetNumChildren(); i++) {
            SimpleNode node = (SimpleNode) simpleNode.jjtGetChild(i);
            if(node instanceof ASTIDENTIFIER){
                try {
                    LogTableColumn.ColumnIdentifier type = LogTableColumn.ColumnIdentifier.valueOf(((String) node.jjtGetValue()).toUpperCase());
                    node.jjtSetValue(type);
                }catch (IllegalArgumentException e){
                    ASTSTRING stringNode = new ASTSTRING(node.getId());
                    stringNode.jjtSetValue(node.jjtGetValue());
                    simpleNode.jjtAddChild(stringNode, i);
                }
            }else{
                checkIdentifiers(node);
            }
        }
    }

    private void simplify(SimpleNode node){
        if(node.jjtGetNumChildren() == 1){
            SimpleNode child = (SimpleNode) node.jjtGetChild(0);
            if(node.getClass().isInstance(child)){
                if((node.jjtGetValue() == null && child.jjtGetValue() == null)
                        || node.jjtGetValue().equals(child.jjtGetValue())){
                    if(node.jjtGetParent() != null){
                        int index = -1;
                        for(int i=0; i<node.jjtGetParent().jjtGetNumChildren(); i++){
                            if(node.jjtGetParent().jjtGetChild(i).equals(node)) {
                                index = i;
                                break;
                            }
                        }
                        if(index > -1) {
                            node.jjtGetParent().jjtAddChild(child, index);
                            child.jjtSetParent(node.jjtGetParent());
                            simplify((SimpleNode) child);
                        }
                        return;
                    }
                }
            }
            simplify(child);
        }else{
            for (int i = 0; i < node.jjtGetNumChildren(); i++) {
                simplify((SimpleNode) node.jjtGetChild(i));
            }
        }
    }

    private boolean evaluate(LogEntry entry){
        try {
            return evaluate(this.root, entry);
        } catch (ParseException e) {
            return false;
        }
    }

    private boolean evaluate(SimpleNode node, LogEntry entry) throws ParseException {
        if(node instanceof ASTCOMPARISON){
            return evaluateComparison(node, entry);
        }else if(node instanceof ASTEXPRESSION | node instanceof ASTFILTER){
            boolean currentResult = evaluate((SimpleNode) node.jjtGetChild(0), entry);
            SimpleNode comparison = null;
            for(int i=1; i<node.jjtGetNumChildren(); i++){
                if(i % 2 == 0){
                    boolean nodeResult = evaluate((SimpleNode) node.jjtGetChild(i), entry);
                    if(comparison instanceof ASTXOR) {
                        currentResult = nodeResult ^ currentResult;
                    }else if(comparison instanceof ASTAND){
                        currentResult = nodeResult && currentResult;
                    }else if(comparison instanceof ASTOR){
                        currentResult = nodeResult || currentResult;
                    }
                    continue;
                }else{
                    comparison = (SimpleNode) node.jjtGetChild(i);
                }
            }
            return currentResult;
        }
        return false;
    }

    private boolean evaluateComparison(SimpleNode node, LogEntry entry) throws ParseException {
        if(node instanceof ASTCOMPARISON){
            SimpleNode leftNode, rightNode;
            Object left, right;

            leftNode = (SimpleNode) node.jjtGetChild(0);
            rightNode = (SimpleNode) node.jjtGetChild(2);
            if(leftNode instanceof ASTIDENTIFIER){
                left = getEntryValue((LogTableColumn.ColumnIdentifier) (leftNode).jjtGetValue(), entry);
            }else{
                left = leftNode.jjtGetValue();
                if(left instanceof String) left = StringEscapeUtils.unescapeJava((String) left);
            }

            if(rightNode instanceof ASTIDENTIFIER){
                right = getEntryValue((LogTableColumn.ColumnIdentifier) (rightNode).jjtGetValue(), entry);
            }else{
                right = rightNode.jjtGetValue();
                if(right instanceof String) right = StringEscapeUtils.unescapeJava((String) right);
            }

            SimpleNode operator = ((SimpleNode) node.jjtGetChild(1));

            if(left instanceof String){
                if(right instanceof String){
                    return StringUtils.containsIgnoreCase((String) left, (String) right) ^ (operator instanceof ASTNEQ);
                }else if(right instanceof Pattern){
                    return ((Pattern) right).matcher((String) left).find() ^ (operator instanceof ASTNEQ);
                }else if(right instanceof Number){
                    Float leftVal;
                    try {
                        leftVal = Float.parseFloat((String) left);
                    }catch (NumberFormatException e){
                        throw new ParseException("Could not compare string \"" + left + "\" to number \"" + right +"\".");
                    }
                    if(operator instanceof ASTLEQ) return leftVal <= (Float) right;
                    if(operator instanceof ASTGEQ) return leftVal >= (Float) right;
                    if(operator instanceof ASTLT) return leftVal < (Float) right;
                    if(operator instanceof ASTGT) return leftVal > (Float) right;
                    if(operator instanceof ASTEQ) return leftVal.equals(right);
                    if(operator instanceof ASTNEQ) return !leftVal.equals(right);
                    return false;
                }
            }else if(left instanceof Pattern){
                if(right instanceof String){
                    return ((Pattern) left).matcher((String) right).find() ^ (operator instanceof ASTNEQ);
                }else{
                    return((Pattern) left).matcher(String.valueOf(right)).find() ^ (operator instanceof ASTNEQ);
                }
            }else if(left instanceof Number){
                Float leftVal, rightVal;
                if(right instanceof String || right instanceof Number){
                    try{
                        leftVal = Float.parseFloat(String.valueOf(left));
                    }catch (NumberFormatException e){
                        throw new ParseException("Could not compare \"" + left + "\" to \"" + right +"\".");
                    }
                    try{
                        rightVal = Float.parseFloat(String.valueOf(right));
                    }catch (NumberFormatException e){
                        throw new ParseException("Could not compare \"" + left + "\" to \"" + right +"\".");
                    }

                    if(operator instanceof ASTLEQ) return leftVal <= rightVal;
                    if(operator instanceof ASTGEQ) return leftVal >= rightVal;
                    if(operator instanceof ASTLT) return leftVal < rightVal;
                    if(operator instanceof ASTGT) return leftVal > rightVal;
                    if(operator instanceof ASTEQ) return leftVal.equals(rightVal);
                    if(operator instanceof ASTNEQ) return !leftVal.equals(rightVal);
                    return false;
                }else{
                    throw new ParseException("Could not compare float \"" + left + "\" to " + right.getClass().getSimpleName() + " \"" + right +"\".");
                }
            }else if(left instanceof Boolean) {
                Boolean rightVal = Boolean.parseBoolean(String.valueOf(right));
                return rightVal.equals(left)  ^ (operator instanceof ASTNEQ);
            }else{
                return String.valueOf(left).equals(String.valueOf(right));
            }

        }
        return false;
    }

    private Object getEntryValue(LogTableColumn.ColumnIdentifier identifier, LogEntry entry){
        if (entry == null) return null;
        else return entry.getValueByKey(identifier);
    }

    public boolean matches(LogEntry entry){
        return this.evaluate(entry);
    }

    @Override
    public String toString() {
        return toString(this.root);
    }

    private String toString(SimpleNode node){
        if(node.jjtGetNumChildren() == 0){
            if(node instanceof ASTSTRING){
                return "\"" + String.valueOf(node.jjtGetValue()) + "\"";
            }
            if(node instanceof ASTREGEX){
                return "/" + String.valueOf(node.jjtGetValue()) + "/";
            }
            if(node instanceof ASTNUMBER){
                return numberFormat.format(node.jjtGetValue());
            }
            return String.valueOf(node.jjtGetValue());
        }else{
            StringBuilder sb = new StringBuilder();
            if(node instanceof ASTEXPRESSION && node.jjtGetParent() != root) sb.append("(");
            for (int i = 0; i < node.jjtGetNumChildren(); i++) {
                sb.append(toString((SimpleNode) node.jjtGetChild(i)));
                if(i != node.jjtGetNumChildren()-1 && !(node.jjtGetChild(i) instanceof ASTINVERSE)){
                    sb.append(" ");
                }
            }
            if(node instanceof ASTEXPRESSION && node.jjtGetParent() != root) sb.append(")");
            return sb.toString();
        }
    }

    @Override
    public boolean include(Entry entry) {
        int identifier = (int) entry.getIdentifier();
        TableModel tableModel = (TableModel) entry.getModel();
        if(tableModel instanceof LogTableModel){
            LogEntry logEntry = ((LogTableModel) tableModel).getRow(identifier);
            return this.evaluate(logEntry);
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
