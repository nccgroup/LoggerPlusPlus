package burp.filter;

import burp.LogEntry;

import java.awt.event.ComponentListener;

public class CompoundFilter extends Filter {
    enum CompoundOperation {
        AND("&&"),OR("||");
        private final String representation;
        CompoundOperation(String s){representation = s;}
    }
    CompoundOperation op;

    public CompoundFilter(Object left, Object op, Object right) throws FilterException {
        if(op instanceof CompoundOperation){
            this.op = (CompoundOperation) op;
        }else if(op instanceof String){
            this.op = parseOperation((String) op);
        }else{
            throw new FilterException("Could not parse compound combinator.");
        }
        if(left instanceof Filter){
            this.left = left;
        }else if(left instanceof String){
            this.left = FilterCompiler.parseString((String) left);
        }
        if(right instanceof Filter){
            this.right = right;
        }else if(right instanceof String){
            this.right = FilterCompiler.parseString((String) right);
        }
    }

    protected CompoundOperation parseOperation(String op){
        if(op.indexOf("|") != -1) return CompoundOperation.OR;
        if(op.indexOf("&") != -1) return CompoundOperation.AND;
        else return null;
    }

    @Override
    public boolean include(Entry<?, ?> entry){
        switch (this.op){
            case AND: return ((Filter) this.left).include(entry) && ((Filter) this.right).include(entry);
            case OR: return ((Filter) this.left).include(entry) || ((Filter) this.right).include(entry);
            default: return false;
        }
    }

    @Override
    public boolean matches(LogEntry entry){
        switch (this.op){
            case AND: return ((Filter) this.left).matches(entry) && ((Filter) this.right).matches(entry);
            case OR: return ((Filter) this.left).matches(entry) || ((Filter) this.right).matches(entry);
            default: return false;
        }
    }

    @Override
    public String toString(){
        String result = "";
        if(left instanceof CompoundFilter && !((CompoundFilter) left).op.equals(op)){
            result += "(" + left.toString() + ")";
        }else{
            result += left.toString();
        }
        result += " " + op.representation + " ";
        if(right instanceof CompoundFilter && !((CompoundFilter) right).op.equals(op)){
            result += "(" + right.toString() + ")";
        }else{
            result += right.toString();
        }

        return (inverted ? "!(" + result + ")" : result);
//        return  + left.toString() + " " + op.representation + " " + right.toString() + ")";
    }
}
