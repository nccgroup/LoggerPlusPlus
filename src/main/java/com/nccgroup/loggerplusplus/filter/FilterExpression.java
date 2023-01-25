package com.nccgroup.loggerplusplus.filter;

import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.filter.parser.*;
import com.nccgroup.loggerplusplus.logentry.LogEntry;
import com.nccgroup.loggerplusplus.logentry.LogEntryField;
import lombok.Getter;

import java.util.HashSet;

public class FilterExpression {

    @Getter
    protected ASTExpression ast;

    @Getter
    protected HashSet<String> snippetDependencies;

    public FilterExpression(String filterString) throws ParseException {
        this.ast = FilterParser.parseFilter(filterString);
        this.snippetDependencies = FilterParser.checkAliasesForSanity(LoggerPlusPlus.instance.getLibraryController(), this.ast);
    }

    public boolean matches(LogEntry entry){
        FilterEvaluationVisitor visitor = new FilterEvaluationVisitor(LoggerPlusPlus.instance.getLibraryController());
        return visitor.visit(ast, entry);
    }

    public void addConditionToFilter(LogicalOperator logicalOperator, LogEntryField field,
                                                 ComparisonOperator booleanOperator, String value) throws ParseException {
        String existing;
        if (this.ast.getLogicalOperator() != null && !this.ast.getLogicalOperator().equals(logicalOperator)) {
            existing = "(" + this.ast.getFilterString() + ")";
        } else {
            existing = this.ast.getFilterString();
        }

        this.ast = FilterParser.parseFilter(String.format("%s %s %s %s %s", existing, logicalOperator.toString(), field.toString(), booleanOperator, value));
        this.snippetDependencies = FilterParser.checkAliasesForSanity(LoggerPlusPlus.instance.getLibraryController(), this.ast);
    }

    @Override
    public String toString() {
        return ast.getFilterString();
    }
}
