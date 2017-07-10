package burp.filter;
import burp.LogEntry;
import burp.LogTableModel;
import org.apache.commons.lang3.StringUtils;

import javax.swing.*;
import java.lang.reflect.InvocationTargetException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

public class Filter extends RowFilter<Object, Object> {
    enum LogicalOperation {LT,LE,GT,GE,EQ,NE}
    public boolean inverted;
    public Object left;
    public LogicalOperation operation;
    public Object right;
    private static Pattern regexPattern = Pattern.compile("\\/(.*)\\/");
    private static Pattern bracketsPattern = Pattern.compile("(.*?)(!?)(\\(.*\\))(.*?)");
    private static Pattern compoundPattern = Pattern.compile("(.*?)(\\|+|&+)(.*?)");

    protected Filter(){}

    @Override
    public boolean include(Entry<? extends Object, ? extends Object> entry) {
        LogTableModel tableModel = (LogTableModel) entry.getModel();
        Object lValue = this.left, rValue = this.right;
        if(this.left instanceof LogEntry.columnNamesType) {
            int columnNo = tableModel.getColumnIndexByName(this.left.toString());
            lValue = entry.getValue(tableModel.getTable().convertColumnIndexToModel(columnNo));
        }
        if(this.right instanceof LogEntry.columnNamesType) {
            int columnNo = tableModel.getColumnIndexByName(this.right.toString());
            rValue = entry.getValue(tableModel.getTable().convertColumnIndexToModel(columnNo));
        }
        if(this.left instanceof Pattern){
            return ((Pattern) lValue).matcher(rValue.toString()).matches();
        }else if(this.right instanceof Pattern){
            return ((Pattern) rValue).matcher(lValue.toString()).matches();
        }

        try {
            return checkValue(lValue, this.operation, rValue);
        }catch (Exception e){
            e.printStackTrace();
            return false;
        }
        //return checkValue(lValue, this.operation,
        //                lValue.getClass().getConstructor(this.right.getClass()).newInstance(this.right));
    }
//    @Override
//    public boolean include(Entry<? extends Object, ? extends Object> entry) {
//        LogTableModel tableModel = (LogTableModel) entry.getModel();
//        if(this.left instanceof LogEntry.columnNamesType){
//            int columnNo = tableModel.getColumnIndexByName(this.left.toString());
//            Object lValue = entry.getValue(tableModel.getTable().convertColumnIndexToModel(columnNo));
//            if(this.right instanceof LogEntry.columnNamesType){
//                return lValue == ((LogEntry) entry).getValueByName((String) this.right);
//            }else{
//                try {
//                    return checkValue(lValue, this.operation,
//                            lValue.getClass().getConstructor(this.right.getClass()).newInstance(this.right));
//                } catch (Exception e) {
//                    e.printStackTrace();
//                    return false;
//                }
//            }
//        }else{
//            if(this.right instanceof LogEntry.columnNamesType){
//                Object rValue = entry.getValue(tableModel.getColumnIndexByName(this.right.toString()));
//                try {
//                    return checkValue(rValue, this.operation,
//                            rValue.getClass().getConstructor(this.left.getClass()).newInstance(this.left));
//                } catch (Exception e) {
//                    return false;
//                }
//            }else{
//                return checkValue(left, this.operation, right);
//            }
//        }
//    }

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
            this.left = parseItem((String) left);
        }else{
            this.left = left;
        }
        if(right instanceof String){
            if(StringUtils.countMatches((String) right, "(") != StringUtils.countMatches((String) right, ")")) {
                throw new FilterException("Unmatched Bracket");
            }
            this.right = parseItem((String) right);
        }else{
            this.right = right;
        }

        this.operation = op;
    }

    //TODO implement type parser?
    private Object parseItem(String item) throws FilterException {
        try {
            return LogEntry.columnNamesType.valueOf(item.toUpperCase());
        }catch (IllegalArgumentException e){}

        Matcher regexMatcher = regexPattern.matcher(item);
        if(regexMatcher.matches()){
            try {
                Pattern regexItem = Pattern.compile(regexMatcher.group(1));
                return regexItem;
            }catch (PatternSyntaxException pSException){
                throw new FilterException("Invalid Regex Pattern");
            }
        }

        if(regexPattern.matcher(item).matches()){
            return item.substring(1, item.length()-1);
        }
        return item;
    }

    public static Filter parseString(String string) throws FilterException{
        String regexStripped = stripRegex(string);
        Matcher bracketMatcher = bracketsPattern.matcher(regexStripped);

        if (bracketMatcher.matches()) {
            Filter group;
            boolean inverted = "!".equals(bracketMatcher.group(2));
            group = parseString(bracketMatcher.group(3)
                    .substring(1, bracketMatcher.group(3).length() - 1));
            group.inverted = inverted;
            Pattern leftCompound = Pattern.compile("(.*?)(\\|++|&++)\\s*$");
            Pattern rightCompound = Pattern.compile("^(\\s*)(\\|++|&++)(.*)");
            String left = bracketMatcher.group(1);
            String right = bracketMatcher.group(4);
            Matcher leftMatcher = leftCompound.matcher(left);
            Matcher rightMatcher = rightCompound.matcher(right);
            if (leftMatcher.matches()) {
                group = new CompoundFilter(Filter.parseString(leftMatcher.group(1)), leftMatcher.group(2), group);
            }
            if (rightMatcher.matches()) {
                group = new CompoundFilter(group, rightMatcher.group(2), Filter.parseString(rightMatcher.group(3)));
            }
            return group;
        } else {
            Matcher compoundMatcher = compoundPattern.matcher(string);
            if (compoundMatcher.matches()) {
                return new CompoundFilter(compoundMatcher.group(1), compoundMatcher.group(2), compoundMatcher.group(3));
            } else {
                Pattern operation = Pattern.compile("(.*?)((?:=?(?:=|<|>|!)=?))(.*?)");
                Matcher operationMatcher = operation.matcher(string);
                if(operationMatcher.matches()){
                    return new Filter(operationMatcher.group(1).trim(), operationMatcher.group(2), operationMatcher.group(3).trim());
                }
            }
        }
        throw new FilterException("Could not parse filter");
    }

    private static boolean isRegex(String string){
        try{
            Pattern.compile(string);
            return true;
        }catch (PatternSyntaxException pSException){
            return false;
        }
    }

    private static String stripRegex(String string){
        string = string.replace("\\\\", "").replace("\\/", "");
        return regexPattern.matcher(string).replaceAll("");
    }

    private boolean checkValue(Object left, LogicalOperation op, Object right) throws NoSuchMethodException, IllegalAccessException, InvocationTargetException, InstantiationException {
        if(!(left instanceof String)){
            right = left.getClass().getConstructor(this.right.getClass()).newInstance(this.right);
        }else if(!(right instanceof String)){
            left = right.getClass().getConstructor(this.left.getClass()).newInstance(this.left);
        }

        switch (op){
            case EQ: {
                return left.equals(right);
            }
            case NE: {
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
}
