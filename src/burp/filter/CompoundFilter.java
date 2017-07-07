package burp.filter;

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
    public boolean include(Entry<? extends Object, ? extends Object> entry){
        switch (this.op){
            case AND: return ((Filter) this.left).include(entry) && ((Filter) this.right).include(entry);
            case OR: return ((Filter) this.left).include(entry) || ((Filter) this.right).include(entry);
            default: return false;
        }
    }
}
