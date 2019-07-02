import loggerplusplus.filter.parser.FilterParser;
import org.junit.Assert;
import org.junit.Test;

import java.util.HashMap;

public class FilterTest {

    @Test
    public void testBoolean() throws Exception {
        HashMap<String, Boolean> expectedResults = new HashMap<>();
        expectedResults.put("true", true);
        expectedResults.put("false", false);
        expectedResults.put("!false", true);
        expectedResults.put("!true", false);

        for (String string : expectedResults.keySet()) {
            boolean expected = expectedResults.get(string);
            Assert.assertEquals(expected, new FilterParser(string).Boolean());
        }
    }

    @Test
    public void testString() throws Exception {
        HashMap<String, String> expectedResults = new HashMap<>();
        expectedResults.put("\"Hello World\"", "Hello World");
        expectedResults.put("'Hello World'", "Hello World");
        expectedResults.put("\"Hello \\\"World\"", "Hello \"World");
        expectedResults.put("'Hello \\'World'", "Hello \'World");

        for (String string : expectedResults.keySet()) {
            String expected = expectedResults.get(string);
            String result = new FilterParser(string).String();
            Assert.assertEquals(expected, result);
        }
    }
}
