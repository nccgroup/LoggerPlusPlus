package com.nccgroup.loggerplusplus.filter.parser;

import com.nccgroup.loggerplusplus.filter.ComparisonOperator;
import com.nccgroup.loggerplusplus.filter.LogicalOperator;
import com.nccgroup.loggerplusplus.filter.savedfilter.SavedFilter;
import com.nccgroup.loggerplusplus.filterlibrary.FilterLibraryController;
import com.nccgroup.loggerplusplus.logentry.LogEntry;
import com.nccgroup.loggerplusplus.logentry.LogEntryField;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.time.DateUtils;

import java.math.BigDecimal;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class FilterEvaluationVisitor implements FilterParserVisitor {

  private static final String LOG_ENTRY = "logEntry";
  private final FilterLibraryController filterLibraryController;

  public FilterEvaluationVisitor(FilterLibraryController filterLibraryController){
    this.filterLibraryController = filterLibraryController;
  }

  public Boolean visit(SimpleNode node, VisitorData data){
    return false;
  }

  public Boolean visit(ASTExpression node, LogEntry logEntry){
    VisitorData visitorData = new VisitorData();
    visitorData.setData(LOG_ENTRY, logEntry);
    return visit(node, visitorData);
  }

  public Boolean visit(ASTExpression node, VisitorData visitorData){
//    System.out.println("Evaluating Node: " + node);

    Node firstNode = node.children[0];
    boolean result = evaluateNode(firstNode, visitorData);

    if(node.op != null) {
      compoundEvaluation:
      {
        LogicalOperator op = node.op;

        for (int i = 1; i < node.children.length; i++) {
          //If we're processing an OR expression and the value is true.
          //Or we're processing an AND expression and the value was false. Don't bother evaluating the other nodes.
          if ((op == LogicalOperator.OR && result) || (op == LogicalOperator.AND && !result)) break compoundEvaluation;

          Node child = node.children[i];
          boolean childResult = evaluateNode(child, visitorData);

          switch (op) {
            case AND:
            case OR: {
              result = childResult;
              break;
            }
            case XOR: {
              result ^= childResult;
              break;
            }
          }
        }
      }
    }

    return result ^ node.inverse;
  }

  public Boolean visit(ASTComparison node, VisitorData visitorData){
    Object left, right;

    //Must pull the value from the entry for fields, otherwise the node itself is the value.
    left = node.left instanceof LogEntryField ? getValueForField(visitorData, (LogEntryField) node.left) : node.left;
    right = node.right instanceof LogEntryField ? getValueForField(visitorData, (LogEntryField) node.right) : node.right;

    return compare(node.comparisonOperator, left, right);
  }

  private Object getValueForField(VisitorData visitorData, LogEntryField field){
    return ((LogEntry) visitorData.getData().get(LOG_ENTRY)).getValueByKey(field);
  }

  @Override
  public Boolean visit(ASTAlias node, VisitorData data) {
    for (SavedFilter savedFilter : filterLibraryController.getFilterSnippets()) {
      if(node.identifier.equalsIgnoreCase(savedFilter.getName())){
        return visit(savedFilter.getFilterExpression().getAst(), data);
      }
    }
     return false;
  }

  private boolean evaluateNode(Node node, VisitorData visitorData){
    if(node instanceof ASTExpression) return visit((ASTExpression) node, visitorData);
    else if(node instanceof ASTComparison) return visit((ASTComparison) node, visitorData);
    else if(node instanceof ASTAlias) return visit((ASTAlias) node, visitorData);
    else {
      visitorData.addError("Node was not an expression or comparison. This shouldn't happen!");
      return false;
    }
  }

  private boolean compare(ComparisonOperator op, Object left, Object right) {
    if (left == null) left = "";
    if (right == null) right = "";
    try {
      if (Number.class.isAssignableFrom(left.getClass()) && Number.class.isAssignableFrom(right.getClass())) {
        //Numerical Comparison
        BigDecimal leftBigDecimal = new BigDecimal(String.valueOf(left));
        BigDecimal rightBigDecimal = new BigDecimal(String.valueOf(right));
        switch (op) {
          case EQUAL:
            return leftBigDecimal.compareTo(rightBigDecimal) == 0;
          case NOT_EQUAL:
            return leftBigDecimal.compareTo(rightBigDecimal) != 0;
          case GREATER_THAN:
            return leftBigDecimal.compareTo(rightBigDecimal) > 0;
          case LESS_THAN:
            return leftBigDecimal.compareTo(rightBigDecimal) < 0;
          case GREATER_THAN_EQUAL:
            return leftBigDecimal.compareTo(rightBigDecimal) >= 0;
          case LESS_THAN_EQUAL:
            return leftBigDecimal.compareTo(rightBigDecimal) <= 0;
        }
      } else if (op == ComparisonOperator.MATCHES) {
        Matcher m = ((Pattern) right).matcher(String.valueOf(left));
        return m.matches();
      } else if (right instanceof Pattern) {
        Matcher m = ((Pattern) right).matcher(String.valueOf(left));
        return m.find() ^ op == ComparisonOperator.NOT_EQUAL;
      } else if (left instanceof Date) {
        try {
          Date rightDate = DateUtils.truncate(right, Calendar.SECOND);
          switch (op) {
            case EQUAL:
              return DateUtils.truncate((Date) left, Calendar.SECOND).compareTo(rightDate) == 0;
            case NOT_EQUAL:
              return DateUtils.truncate((Date) left, Calendar.SECOND).compareTo(rightDate) != 0;
            case GREATER_THAN:
              return DateUtils.truncate((Date) left, Calendar.SECOND).compareTo(rightDate) > 0;
            case LESS_THAN:
              return DateUtils.truncate((Date) left, Calendar.SECOND).compareTo(rightDate) < 0;
            case GREATER_THAN_EQUAL:
              return DateUtils.truncate((Date) left, Calendar.SECOND).compareTo(rightDate) >= 0;
            case LESS_THAN_EQUAL:
              return DateUtils.truncate((Date) left, Calendar.SECOND).compareTo(rightDate) <= 0;
          }
        } catch (Exception e) {
          return false;
        }
      } else if (op == ComparisonOperator.IN) {
        //Request.Host IN ["https://twitter.com", "https://google.com"]
        String leftString = String.valueOf(left);
        for (Object item : (Collection) right) {
          if (leftString.equalsIgnoreCase(String.valueOf(item))) return true;
        }
        return false;
      } else if (op == ComparisonOperator.CONTAINS) {
        //Request.Parameters CONTAINS "A"
        Object finalRight = right;
        if (Collection.class.isAssignableFrom(left.getClass())) {
          return ((Collection) left).stream().anyMatch(o -> String.valueOf(o).equalsIgnoreCase(String.valueOf(finalRight)));
        } else {
          return StringUtils.containsIgnoreCase(String.valueOf(left), String.valueOf(right));
        }
      } else if (left instanceof String || right instanceof String) { //String comparison last.
        return String.valueOf(left).equalsIgnoreCase(String.valueOf(right)) ^ op != ComparisonOperator.EQUAL;
      } else {
        switch (op) {
          case EQUAL:
            return left.equals(right);
          case NOT_EQUAL:
            return !left.equals(right);
        }
      }

    }catch (Exception e){
      e.printStackTrace();
      return false;
    }

    return false;
  }
}