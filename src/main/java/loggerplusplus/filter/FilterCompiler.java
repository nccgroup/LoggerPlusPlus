package loggerplusplus.filter;

import loggerplusplus.LogEntry;
import org.apache.commons.lang3.StringUtils;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Created by corey on 19/07/17.
 */
public class FilterCompiler {
    private static Pattern regexPattern = Pattern.compile("\\/(.*)\\/");
    private static Pattern bracketsPattern = Pattern.compile("(.*?)(!?)(\\(.*\\))(.*?)");
    private static Pattern compoundPattern = Pattern.compile("(.*?)(\\|+|&+)(.*?)");
    private static Pattern inQuotes = Pattern.compile("([\"'])(.*)(\\1)");

    //TODO implement type parser?
    public static Object parseItem(String item) throws Filter.FilterException {
        try {
            return LogEntry.columnNamesType.valueOf(item.toUpperCase());
        }catch (IllegalArgumentException e){}

        Matcher regexMatcher = regexPattern.matcher(item);
        if(regexMatcher.matches()){
            try {
                Pattern regexItem = Pattern.compile(regexMatcher.group(1), Pattern.DOTALL | Pattern.CASE_INSENSITIVE);
                return regexItem;
            }catch (PatternSyntaxException pSException){
                throw new Filter.FilterException("Invalid Regex Pattern");
            }
        }

        if(regexPattern.matcher(item).matches()){
            return item.substring(1, item.length()-1);
        }

        Matcher inQuotesMatcher = inQuotes.matcher(item);
        if(inQuotesMatcher.matches()){
            item = inQuotesMatcher.group(2);
        }

        if(item.trim().equalsIgnoreCase("true")) return true;
        if(item.trim().equalsIgnoreCase("false")) return false;
        return item.trim();
    }

    public static Filter parseString(String string) throws Filter.FilterException {
        String regexStripped = stripRegex(string);
        Matcher bracketMatcher = bracketsPattern.matcher(regexStripped);

        if (bracketMatcher.matches()) {
            Filter group;
            boolean inverted = "!".equals(bracketMatcher.group(2));
            int startBracket = regexStripped.indexOf("(");
            int endBracket = getBracketMatch(regexStripped, startBracket);
            group = parseString(string.substring(startBracket+1, endBracket));
            group.inverted = inverted;
            Pattern leftCompound = Pattern.compile("(.*?)(\\|++|&++)\\s*$");
            Pattern rightCompound = Pattern.compile("^(\\s*)(\\|++|&++)(.*)");
            String left = string.substring(0, inverted ? startBracket-1 : startBracket);
            String right = string.substring(endBracket+1, regexStripped.length());
            Matcher leftMatcher = leftCompound.matcher(left);
            Matcher rightMatcher = rightCompound.matcher(right);
            if (leftMatcher.matches()) {
                group = new CompoundFilter(parseString(leftMatcher.group(1)), leftMatcher.group(2), group);
            }
            if (rightMatcher.matches()) {
                group = new CompoundFilter(group, rightMatcher.group(2), parseString(rightMatcher.group(3)));
            }
            return group;
        } else {
            Matcher compoundMatcher = compoundPattern.matcher(regexStripped);
            if (compoundMatcher.matches()) {
                String left = string.substring(0, compoundMatcher.group(1).length()).trim();
                String right = string.substring(compoundMatcher.group(1).length() + compoundMatcher.group(2).length()).trim();
                return new CompoundFilter(left, compoundMatcher.group(2), right);
            } else {
                Pattern operation = Pattern.compile("(.*?)((?:=?(?:[=<>!])=?))(.*?)");
                Matcher operationMatcher = operation.matcher(regexStripped);
                if(operationMatcher.matches()){
                    if(operationMatcher.group(2).equals("!")){
                        try{
                            LogEntry.columnNamesType col = LogEntry.columnNamesType.valueOf(operationMatcher.group(3));
                            return new Filter(col, Filter.LogicalOperation.EQ, false);
                        }catch (IllegalArgumentException iAException){}
                    }else {
                        String left = string.substring(0, operationMatcher.group(1).length()).trim();
                        String right = string.substring(operationMatcher.group(1).length() + operationMatcher.group(2).length()).trim();
                        return new Filter(left, operationMatcher.group(2), right);
                    }
                }else if(!regexPattern.matcher(string).matches() && !string.trim().contains(" ")){
                    try{
                        LogEntry.columnNamesType col = LogEntry.columnNamesType.valueOf(string);
                        return new Filter(col, Filter.LogicalOperation.EQ, true);
                    }catch (IllegalArgumentException iAException){}
                }
            }
        }
        throw new Filter.FilterException("Could not parse filter");
    }

    private static int getBracketMatch(String string, int start) {
        int end = start;
        int count = 1;
        while (count > 0){
            char c = string.charAt(++end);
            if (c == '('){ count++; }
            else if(c == ')'){ count--; }
        }
        return end;
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
        Pattern hasRegex = Pattern.compile("(.*)(\\/.*\\/)(.*)");
        string = string.replace("\\\\", "  ").replace("\\/", "  ");
        Matcher matcher;
        while((matcher = hasRegex.matcher(string)).matches()) {
            string = matcher.group(1) + StringUtils.repeat(" ", matcher.group(2).length()) + matcher.group(3);
        }
        return string;
    }
}
