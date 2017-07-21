package burp.filter;
import burp.LogEntry;
import burp.LogTableModel;
import com.google.gson.*;
import org.apache.commons.lang3.StringUtils;

import javax.swing.*;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Type;
import java.util.regex.Pattern;

public class Filter extends RowFilter<Object, Object> {

    enum LogicalOperation {
        LT ("<"), LE ("<="), GT (">"), GE (">="), EQ ("=="), NE ("!=");
        private final String representation;
        LogicalOperation(String s) {
            representation = s;
        }
    }
    public boolean inverted;
    public Object left;
    public LogicalOperation operation;
    public Object right;

    protected Filter(){}

    protected Filter(Object left, String operation, Object right) throws FilterException {
        LogicalOperation op;
        switch (operation){
            case "=":
            case "==": op = LogicalOperation.EQ;
                break;
            case "=!":
            case "!=": op = LogicalOperation.NE;
                break;
            case "<": op = LogicalOperation.LT;
                break;
            case ">": op = LogicalOperation.GT;
                break;
            case "=<":
            case "<=": op = LogicalOperation.LE;
                break;
            case "=>":
            case ">=": op = LogicalOperation.GE;
                break;
            default:
                throw new FilterException("Invalid operator " + operation);
        }

        if(left instanceof String){
            if(StringUtils.countMatches((String) left, "(") != StringUtils.countMatches((String) left, ")")) {
                throw new FilterException("Unmatched Bracket");
            }
            this.left = FilterCompiler.parseItem((String) left);
        }else{
            this.left = left;
        }
        if(right instanceof String){
            if(StringUtils.countMatches((String) right, "(") != StringUtils.countMatches((String) right, ")")) {
                throw new FilterException("Unmatched Bracket");
            }
            this.right = FilterCompiler.parseItem((String) right);
        }else{
            this.right = right;
        }

        this.operation = op;
    }

    public boolean matches(LogEntry entry){
        Object lValue = this.left, rValue = this.right;
        try {
            lValue = entry.getValueByKey(LogEntry.columnNamesType.valueOf(this.left.toString()));
        }catch (IllegalArgumentException iAException){}
        try {
            rValue = entry.getValueByKey(LogEntry.columnNamesType.valueOf(this.right.toString()));
        }catch (IllegalArgumentException iAException){}

        return this.matches(lValue, rValue);
    }

    public boolean matches(Object lValue, Object rValue) {
        if (this.left instanceof Pattern) {
            return ((Pattern) lValue).matcher(rValue.toString()).matches();
        } else if (this.right instanceof Pattern) {
            return ((Pattern) rValue).matcher(lValue.toString()).matches();
        }

        try {
            return checkValue(lValue, this.operation, rValue);
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    @Override
    public boolean include(Entry<?, ?> entry) {
        LogTableModel tableModel = (LogTableModel) entry.getModel();
        Object lValue = this.left, rValue = this.right;
        try {
            int columnNo = tableModel.getColumnIndexByName(this.left.toString());
            lValue = entry.getValue(columnNo);
        }catch (NullPointerException nPException){}
        try {
            int columnNo = tableModel.getColumnIndexByName(this.right.toString());
            rValue = entry.getValue(tableModel.getTable().convertColumnIndexToModel(columnNo));
        }catch (NullPointerException nPException){}

        return this.matches(lValue, rValue);
    }


    private boolean checkValue(Object left, LogicalOperation op, Object right) throws NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException {
        if(!(left instanceof String)){
            right = left.getClass().getConstructor(this.right.getClass()).newInstance(this.right);
        }else if(!(right instanceof String)){
            left = right.getClass().getConstructor(this.left.getClass()).newInstance(this.left);
        }

        switch (op){
            case EQ: {
                if(left instanceof String){
                    return ((String) left).equalsIgnoreCase(right.toString());
                }
                return left.equals(right);
            }
            case NE: {
                if(left instanceof String){
                    return !((String) left).equalsIgnoreCase(right.toString());
                }
                return !left.equals(right);
            }
            case LT: {
                return (left instanceof Comparable) && (right instanceof Comparable)
                        && ((Comparable) left).compareTo(right) < 0;
            }
            case GT: {
                return (left instanceof Comparable) && (right instanceof Comparable)
                        && ((Comparable) left).compareTo(right) > 0;
            }
            case LE: {
                return (left instanceof Comparable) && (right instanceof Comparable)
                        && ((Comparable) left).compareTo(right) <= 0;
            }
            case GE: {
                return (left instanceof Comparable) && (right instanceof Comparable)
                        && ((Comparable) left).compareTo(right) >= 0;
            }
            default:
                return false;
        }
    }

    public static class FilterException extends Exception{
        public FilterException(String msg) {
            super(msg);
        }
    }

    @Override
    public String toString(){
        String lString = left.toString();
        if(left instanceof Pattern) lString = "/" + left + "/";
        String rString = right.toString();
        if(right instanceof Pattern) rString = "/" + right + "/";
        return lString + " " + operation.representation + " " + rString;
    }
}
