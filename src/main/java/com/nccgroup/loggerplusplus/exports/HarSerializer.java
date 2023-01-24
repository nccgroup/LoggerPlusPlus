package com.nccgroup.loggerplusplus.exports;

import burp.api.montoya.http.message.Cookie;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.params.HttpParameter;
import burp.api.montoya.http.message.params.HttpParameterType;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import com.nccgroup.loggerplusplus.logentry.LogEntry;
import com.nccgroup.loggerplusplus.logentry.LogEntryField;

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.List;
import java.util.stream.Collectors;

public class HarSerializer extends TypeAdapter<List<LogEntry>> {

    private final String version;
    private final String creator;

    public HarSerializer(String version, String creator) {
        this.version = version;
        this.creator = creator;
    }

    @Override
    public void write(JsonWriter writer, List<LogEntry> logEntries) throws IOException {
        // Top level log object
        writer.beginObject();
        writer.name("log").beginObject();

        writer.name("version").value("1.2");

        // Creator object
        writer.name("creator").beginObject();
        writer.name("name").value(this.creator);
        writer.name("version").value(this.version);
        writer.endObject(); // end creator object

        //Workaround for https://bugzilla.mozilla.org/show_bug.cgi?id=1691240
        writer.name("pages").beginArray().endArray();
        //End

        // Entries
        writer.name("entries").beginArray();

        for (LogEntry logEntry : logEntries) {
            // Individual entry object
            writer.beginObject();

            final String pattern = "yyyy-MM-dd'T'HH:mm:ss.SSSZ";
            SimpleDateFormat simpleDateFormat = new SimpleDateFormat(pattern);
            writer.name("startedDateTime").value(simpleDateFormat.format(logEntry.getRequestDateTime()));

            long time = logEntry.getResponseDateTime().getTime() - logEntry.getRequestDateTime().getTime();
            time = time < 0 ? 0 : time;
            writer.name("time").value(time);
            writer.name("request").beginObject();
            writer.name("method").value(logEntry.getMethod());
            writer.name("url").value(logEntry.getUrlString().toString());
            writer.name("httpVersion").value(logEntry.getRequestHttpVersion());
            writer.name("origin").value(logEntry.getOrigin());

            writer.name("cookies").beginArray();
            if (logEntry.isHasCookieParam()) {
                List<HttpParameter> cookies = getRequestParametersByType(logEntry.getRequest(), HttpParameterType.COOKIE);
                for (HttpParameter cookie : cookies) {
                    writer.beginObject();
                    writer.name("name").value(cookie.name());
                    writer.name("value").value(cookie.value());
                    writer.endObject();
                }
            }
            writer.endArray(); // end request cookies array

            writer.name("headers").beginArray();
            for (HttpHeader header : logEntry.getRequestHeaders()) {
                writer.beginObject();
                writer.name("name").value(header.name());
                writer.name("value").value(header.value());
                writer.endObject();
            }
            writer.endArray(); // end request headers array

            writer.name("queryString").beginArray();
            if (logEntry.getUrl().getQuery() != null) {
                for (HttpParameter queryParam : getRequestParametersByType(logEntry.getRequest(), HttpParameterType.URL)) {
                    writer.beginObject();
                    writer.name("name").value(queryParam.name());
                    writer.name("value").value(queryParam.value());
                    writer.endObject();
                }
            }
            writer.endArray(); // end request queryString array

            if (logEntry.isHasBodyParam()) {
                writer.name("postData").beginObject();
                writer.name("mimeType").value(logEntry.getRequestContentType());
                writer.name("params").beginArray();
                for (HttpParameter bodyParam : getRequestParametersByType(logEntry.getRequest(), HttpParameterType.BODY)) {
                    writer.beginObject();
                    writer.name("name").value(bodyParam.name());
                    writer.name("value").value(bodyParam.value());
                    writer.endObject();
                }
                writer.endArray(); // end params array
                writer.name("text").value((String) logEntry.getValueByKey(LogEntryField.REQUEST_BODY));
                writer.endObject(); // end postData object
            }

            writer.name("headersSize").value(logEntry.getRequestBytes().length - logEntry.getRequestBodyLength());
            writer.name("bodySize").value(logEntry.getRequestBodyLength());

            writer.endObject(); // end request object

            writer.name("response").beginObject();
            writer.name("status").value(logEntry.getResponseStatus());
            writer.name("statusText").value(logEntry.getResponseStatusText());
            writer.name("httpVersion").value(logEntry.getResponseHttpVersion());

            writer.name("cookies").beginArray();
            if (logEntry.isHasSetCookies()) {
                List<Cookie> cookies = logEntry.getResponse().cookies();

                for (Cookie cookie : cookies) {
                    writer.beginObject();
                    writer.name("name").value(cookie.name());
                    writer.name("value").value(cookie.value());
                    writer.name("path").value(cookie.path());
                    writer.name("domain").value(cookie.domain());
                    writer.endObject();
                }
            }
            writer.endArray(); // end response cookies array

            writer.name("headers").beginArray();
            if (logEntry.getResponseHeaders() != null) {
                for (HttpHeader header : logEntry.getResponseHeaders()) {
                    writer.beginObject();
                    writer.name("name").value(header.name());
                    writer.name("value").value(header.value());
                    writer.endObject();
                }
            }
            writer.endArray(); // end response headers array

            writer.name("redirectURL").value(String.valueOf(logEntry.getValueByKey(LogEntryField.REDIRECT_URL)));
            if (logEntry.getResponseBytes() != null) {
                writer.name("headersSize").value(logEntry.getResponseBytes().length - logEntry.getResponseBodyLength());
                writer.name("bodySize").value(logEntry.getResponseBodyLength());
            } else {
                writer.name("headersSize").value(0);
                writer.name("bodySize").value(0);
            }


            writer.name("content").beginObject(); // start content object
            writer.name("size").value(logEntry.getResponseBodyLength());
            writer.name("mimeType").value(logEntry.getResponseContentType());
            writer.name("text").value(String.valueOf(logEntry.getValueByKey(LogEntryField.RESPONSE_BODY)));
            writer.endObject(); //end content object

            writer.endObject(); // end response object

            writer.name("cache").beginObject();
            writer.endObject();

            writer.name("timings").beginObject();
            writer.name("send").value(0);
            writer.name("wait").value((Integer) logEntry.getValueByKey(LogEntryField.RTT));
            writer.name("receive").value(0);
            writer.endObject();

            writer.endObject(); // end entry object
        }

        writer.endArray(); // end entries array

        writer.endObject(); // end top level log object

        writer.endObject(); // end top level object

    }

    private List<HttpParameter> getRequestParametersByType(HttpRequest request, HttpParameterType paramType) {
        return request.parameters().stream()
                .filter(iParameter -> iParameter.type().equals(paramType))
                .collect(Collectors.toList());
    }


    @Override
    public List<LogEntry> read(JsonReader reader) throws IOException {
        // TODO Implement HAR Import logic
        return null;
    }

}
