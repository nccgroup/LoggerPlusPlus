import com.coreyd97.BurpExtenderUtilities.DefaultGsonProvider;
import com.nccgroup.loggerplusplus.filter.parser.FilterParser;
import com.nccgroup.loggerplusplus.logentry.LogEntry;
import com.nccgroup.loggerplusplus.filter.parser.ASTExpression;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class TestParser {

    public static void main(String[] args) throws IOException {
        String logEntryJson = "{\"isImported\":false,\"uuid\":\"61c95665-db54-4191-b419-ef7711bd9ce9\",\"tool\":4,\"toolName\":\"Proxy\",\"host\":\"example.com\",\"method\":\"GET\",\"url\":\"http://example.com:80/\",\"relativeURL\":\"/\",\"params\":false,\"status\":200,\"hasBodyParam\":false,\"hasCookieParam\":false,\"title\":\"n\",\"newCookies\":\"\",\"sentCookies\":\"\",\"listenerInterface\":\"\",\"isSSL\":false,\"urlExtension\":\"\",\"referrerURL\":\"\",\"requestContentType\":\"\",\"protocol\":\"http\",\"targetPort\":80,\"requestLength\":0,\"clientIP\":\"\",\"hasSetCookies\":false,\"responseTime\":\"2019/07/31 08:56:18\",\"responseMimeType\":\"HTML\",\"responseInferredMimeType\":\"HTML\",\"responseLength\":1270,\"responseContentType\":\"text/html; charset\\u003dutf-8\",\"complete\":true,\"usesCookieJar\":\"NO\",\"regexAllReq\":[\"\",\"\",\"\",\"\",\"\"],\"regexAllResp\":[\"\",\"\",\"\",\"\",\"\"],\"matchingColorFilters\":[],\"requestBodyOffset\":492,\"responseBodyOffset\":357,\"requestTime\":\"2019/07/31 08:56:18\",\"responseDateTime\":\"Jul 31, 2019 8:56:18 AM\",\"requestDateTime\":\"Jul 31, 2019 8:56:18 AM\",\"requestResponseDelay\":289,\"responseHeaders\":\"HTTP/1.1 200 OK, Accept-Ranges: bytes, Cache-Control: max-age\\u003d604800, Content-Type: text/html; charset\\u003dUTF-8, Date: Wed, 31 Jul 2019 07:56:20 GMT, Etag: \\\"1541025663\\\", Expires: Wed, 07 Aug 2019 07:56:20 GMT, Last-Modified: Fri, 09 Aug 2013 23:54:35 GMT, Server: ECS (nyb/1D20), Vary: Accept-Encoding, X-Cache: HIT, Content-Length: 1270, Connection: close\",\"requestHeaders\":\"GET / HTTP/1.1, Host: example.com, Cache-Control: max-age\\u003d0, Upgrade-Insecure-Requests: 1, User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/72.0.3626.81 Safari/537.36, Accept: text/html,application/xhtml+xml,application/xml;q\\u003d0.9,image/webp,image/apng,*/*;q\\u003d0.8, Accept-Encoding: gzip, deflate, Accept-Language: en-GB,en-US;q\\u003d0.9,en;q\\u003d0.8, If-None-Match: \\\"1541025663+gzip+ident\\\", If-Modified-Since: Fri, 09 Aug 2013 23:54:35 GMT, Connection: close\",\"requestProcessed\":true,\"responseProcessed\":true}";

        LogEntry logEntry = new DefaultGsonProvider().getGson().fromJson(logEntryJson, LogEntry.class);

        String str;
        BufferedReader in = new BufferedReader(new InputStreamReader(System.in));
        while(!(str = in.readLine()).equalsIgnoreCase("END")) {
            try {
                ASTExpression root = FilterParser.parseFilter(str);
                System.out.println("Filter: " + root.getFilterString());
                root.dump("   ");
//                Boolean visitorData = new FilterEvaluationVisitor(null).visit(root, logEntry);
//                System.out.println("Result: " + visitorData);
            } catch (Throwable e) {
                System.out.println("Syntax check failed: " + e.getMessage());
                e.printStackTrace();
            }
        }
    }
}
