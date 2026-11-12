package com.nccgroup.loggerplusplus.filter.parser;

import com.nccgroup.loggerplusplus.filter.ComparisonOperator;
import com.nccgroup.loggerplusplus.filter.LogicalOperator;
import com.nccgroup.loggerplusplus.filter.savedfilter.SavedFilter;
import com.nccgroup.loggerplusplus.filterlibrary.FilterLibraryController;
import com.nccgroup.loggerplusplus.logentry.LogEntry;
import com.nccgroup.loggerplusplus.logentry.LogEntryField;
import java.math.BigDecimal;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Decides whether a log entry matches a parsed filter.
 *
 * <p>This runs for every logged message, once per colour rule and tag and for the do-not-log
 * filter, and for every row whenever the table is filtered. It therefore walks the tree directly
 * and creates nothing on the common paths: no visitor, no map of visitor data, no {@link
 * BigDecimal} to compare two whole numbers, no {@link Calendar} to compare two dates.
 */
public final class FilterEvaluator {
  private FilterEvaluator() {}

  /**
   * Whether {@code entry} matches {@code filter}.
   *
   * @param library where {@code #name} references to saved filters are looked up; may be null when
   *     the filter has none
   */
  public static boolean matches(
      ASTExpression filter, LogEntry entry, FilterLibraryController library) {
    return expression(filter, entry, library);
  }

  private static boolean expression(
      ASTExpression node, LogEntry entry, FilterLibraryController library) {
    boolean result = node(node.children[0], entry, library);
    LogicalOperator op = node.op;
    if (op != null) {
      for (int i = 1; i < node.children.length; i++) {
        // AND and OR stop at the first child that decides the result.
        if ((op == LogicalOperator.OR && result) || (op == LogicalOperator.AND && !result)) {
          break;
        }
        boolean child = node(node.children[i], entry, library);
        result = op == LogicalOperator.XOR ? result ^ child : child;
      }
    }
    return result ^ node.inverse;
  }

  private static boolean node(Node node, LogEntry entry, FilterLibraryController library) {
    if (node instanceof ASTExpression astExpression) {
      return expression(astExpression, entry, library);
    }
    if (node instanceof ASTComparison astComparison) {
      return comparison(astComparison, entry);
    }
    if (node instanceof ASTAlias astAlias) {
      return alias(astAlias, entry, library);
    }
    return false;
  }

  /** A reference to a saved filter matches when that filter does; an unknown name never does. */
  private static boolean alias(ASTAlias node, LogEntry entry, FilterLibraryController library) {
    if (library == null) {
      return false;
    }
    // By index, not by iterator: the user may edit the library while workers evaluate filters.
    List<SavedFilter> savedFilters = library.getFilterSnippets();
    for (int i = 0; i < savedFilters.size(); i++) {
      SavedFilter savedFilter;
      try {
        savedFilter = savedFilters.get(i);
      } catch (IndexOutOfBoundsException removedMeanwhile) {
        break;
      }
      if (node.identifier.equalsIgnoreCase(savedFilter.getName())) {
        return savedFilter.getFilterExpression() != null
            && expression(savedFilter.getFilterExpression().getAst(), entry, library);
      }
    }
    return false;
  }

  private static boolean comparison(ASTComparison node, LogEntry entry) {
    Object left =
        node.left instanceof LogEntryField
            ? entry.getValueByKey((LogEntryField) node.left)
            : node.left;
    Object right =
        node.right instanceof LogEntryField
            ? entry.getValueByKey((LogEntryField) node.right)
            : node.right;
    try {
      return compare(node, left == null ? "" : left, right == null ? "" : right);
    } catch (RuntimeException uncomparable) {
      // Two values that cannot be compared (a number matched against something that is not a
      // pattern, say) do not match.
      return false;
    }
  }

  private static boolean compare(ASTComparison node, Object left, Object right) {
    ComparisonOperator op = node.comparisonOperator;
    if (left instanceof Number leftNumber && right instanceof Number rightNumber) {
      return ordered(op, compareNumbers(leftNumber, rightNumber));
    }
    if (op == ComparisonOperator.MATCHES) {
      return ((Pattern) right).matcher(String.valueOf(left)).matches();
    }
    if (right instanceof Pattern pattern) {
      return pattern.matcher(String.valueOf(left)).find() ^ (op == ComparisonOperator.NOT_EQUAL);
    }
    if (left instanceof Date date) {
      return ordered(op, compareSeconds(date.getTime(), millisOf(right)));
    }
    if (op == ComparisonOperator.IN) {
      String leftString = String.valueOf(left);
      for (String item : node.rightItems((Collection<?>) right)) {
        if (leftString.equalsIgnoreCase(item)) {
          return true;
        }
      }
      return false;
    }
    if (op == ComparisonOperator.CONTAINS) {
      String rightString = String.valueOf(right);
      if (left instanceof Collection) {
        for (Object item : (Collection<?>) left) {
          if (String.valueOf(item).equalsIgnoreCase(rightString)) {
            return true;
          }
        }
        return false;
      }
      return containsIgnoreCase(String.valueOf(left), rightString);
    }
    if (left instanceof String || right instanceof String) {
      // Text compares without regard to case. Any operator but == means "differs".
      return String.valueOf(left).equalsIgnoreCase(String.valueOf(right))
          ^ (op != ComparisonOperator.EQUAL);
    }
    if (op == ComparisonOperator.EQUAL) {
      return left.equals(right);
    }
    return op == ComparisonOperator.NOT_EQUAL && !left.equals(right);
  }

  /** Turns the sign of a comparison into the answer of an ordering operator. */
  private static boolean ordered(ComparisonOperator op, int comparison) {
    return switch (op) {
      case EQUAL -> comparison == 0;
      case NOT_EQUAL -> comparison != 0;
      case GREATER_THAN -> comparison > 0;
      case LESS_THAN -> comparison < 0;
      case GREATER_THAN_EQUAL -> comparison >= 0;
      case LESS_THAN_EQUAL -> comparison <= 0;
      default -> false;
    };
  }

  /**
   * Compares two numbers by value, whatever their types. Whole numbers, which is what nearly every
   * field and literal is, are compared as longs; anything else as exact decimals.
   */
  private static int compareNumbers(Number left, Number right) {
    if (isWhole(left) && isWhole(right)) {
      return Long.compare(left.longValue(), right.longValue());
    }
    return new BigDecimal(String.valueOf(left)).compareTo(new BigDecimal(String.valueOf(right)));
  }

  private static boolean isWhole(Number number) {
    if (number instanceof Integer || number instanceof Short || number instanceof Long) {
      return true;
    }
    if (number instanceof BigDecimal decimal) {

      return decimal.scale() == 0 && decimal.precision() <= 18;
    }
    return false;
  }

  /** Dates compare to the second: the table shows no finer detail, so a filter cannot ask it. */
  private static int compareSeconds(long leftMillis, long rightMillis) {
    return Long.compare(Math.floorDiv(leftMillis, 1000L), Math.floorDiv(rightMillis, 1000L));
  }

  private static long millisOf(Object date) {
    if (date instanceof Date date2) {
      return date2.getTime();
    }
    if (date instanceof Calendar calendar) {
      return calendar.getTimeInMillis();
    }
    throw new ClassCastException("Not a date: " + date);
  }

  /**
   * Whether {@code text} contains {@code searched}, by the rule of {@link String#regionMatches}.
   */
  static boolean containsIgnoreCase(String text, String searched) {
    int length = searched.length();
    if (length == 0) {
      return true;
    }
    // Most positions are ruled out by their first character alone, with three comparisons.
    char first = searched.charAt(0);
    char firstUpper = Character.toUpperCase(first);
    char firstLower = Character.toLowerCase(firstUpper);
    int last = text.length() - length;
    for (int i = 0; i <= last; i++) {
      char c = text.charAt(i);
      if (c != first && c != firstUpper && c != firstLower) {
        // An ASCII character has no other way to match. Others are folded as regionMatches does.
        if (c < 0x80) {
          continue;
        }
        char upper = Character.toUpperCase(c);
        if (upper != firstUpper && Character.toLowerCase(upper) != firstLower) {
          continue;
        }
      }
      if (text.regionMatches(true, i, searched, 0, length)) {
        return true;
      }
    }
    return false;
  }
}
