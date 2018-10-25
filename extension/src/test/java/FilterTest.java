import loggerplusplus.filter.Filter;
import loggerplusplus.filter.parser.ParseException;
import org.junit.Test;

import java.io.IOException;

import static org.junit.Assert.assertTrue;

public class FilterTest {

    @Test
    public void test() throws IOException, ParseException {
        String filterString[] = new String[]{
                "\"a\" != \"b\"",
                "\"a\" != \"b\" && \"b\" != \"c\"",
                "\"a\" != \"b\" && \"b\" != \"c\" && \"c\" != \"d\"",
                "\"a\" == \"b\" && \"b\" != \"c\" && \"c\" != \"d\" || \"a\" == \"a\"",
                "\"a\" == \"b\" || \"a\" == \"a\"",
                "(\"a\" != \"b\") && (\"a\" != \"a\" || \"b\" == \"b\")",
                "4 == 4",
                "4 != 5",
                "\"ace\" == /(a|b)(c|d)(e|f)/",
                "\"acf\" == /(a|b)(c|d)(e|f)/",
                "\"ade\" == /(a|b)(c|d)(e|f)/",
                "\"badfa\" == /(a|b)(c|d)(e|f)/",
                "\"4\" == 4",
        };
        for (String filter : filterString) {
            assertTrue(new Filter(filter).evaluate(null));
        }
    }
}
