package burp.filter;

import burp.LogEntry;

public class CompoundFilter extends Filter {
    enum CompoundOperation {AND,OR}
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
            this.left = Filter.parseString((String) left);
        }
        if(right instanceof Filter){
            this.right = right;
        }else if(right instanceof String){
            this.right = Filter.parseString((String) right);
        }
    }

    protected CompoundOperation parseOperation(String op){
        if(op.indexOf("|") != -1) return CompoundOperation.OR;
        if(op.indexOf("&") != -1) return CompoundOperation.AND;
        else return null;
    }

    @Override
    public boolean matchesEntry(LogEntry entry){
        switch (this.op){
            case AND: return ((Filter) this.left).matchesEntry(entry) && ((Filter) this.right).matchesEntry(entry);
            case OR: return ((Filter) this.left).matchesEntry(entry) || ((Filter) this.right).matchesEntry(entry);
            default: return false;
        }
    }

//    @Override
//    public String toString() {
//        return (this.inverted ? "INV " : "") + "(" + left + " " + op.toString() + " " + right + ")";
//    }
}
