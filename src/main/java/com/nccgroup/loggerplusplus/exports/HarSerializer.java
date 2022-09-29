package com.nccgroup.loggerplusplus.exports;

import burp.ICookie;
import burp.IParameter;
import burp.IRequestInfo;
import burp.IResponseInfo;
import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
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
            writer.name("url").value(logEntry.getUrl().toString());
            writer.name("httpVersion").value(logEntry.getRequestHttpVersion());
            writer.name("origin").value(logEntry.getOrigin());

            writer.name("cookies").beginArray();
            if (logEntry.isHasCookieParam()) {
                List<IParameter> cookies = getRequestParametersByType(logEntry.getRequest(),
                        IParameter.PARAM_COOKIE);
                for (IParameter cookie : cookies) {
                    writer.beginObject();
                    writer.name("name").value(cookie.getName());
                    writer.name("value").value(cookie.getValue());
                    writer.endObject();
                }
            }
            writer.endArray(); // end request cookies array

            writer.name("headers").beginArray();
            for (String headerString : logEntry.getRequestHeaders()) {
                if (headerString.contains(":")) {
                    writer.beginObject();
                    String headerArray[] = headerString.split(":", 2);
                    writer.name("name").value(headerArray[0]);
                    writer.name("value").value(headerArray[1].trim());
                    writer.endObject();
                }
            }
            writer.endArray(); // end request headers array

            writer.name("queryString").beginArray();
            if (logEntry.getUrl().getQuery() != null) {
                List<IParameter> queryParams = getRequestParametersByType(logEntry.getRequest(),
                        IParameter.PARAM_URL);
                for (IParameter queryParam : queryParams) {
                    writer.beginObject();
                    writer.name("name").value(queryParam.getName());
                    writer.name("value").value(queryParam.getValue());
                    writer.endObject();
                }
            }
            writer.endArray(); // end request queryString array

            if (logEntry.isHasBodyParam()) {
                writer.name("postData").beginObject();
                writer.name("mimeType").value(logEntry.getRequestContentType());
                List<IParameter> bodyParams = getRequestBodyParameters(logEntry.getRequest());
                writer.name("params").beginArray();
                for (IParameter bodyParam : bodyParams) {
                    writer.beginObject();
                    writer.name("name").value(bodyParam.getName());
                    writer.name("value").value(bodyParam.getValue());
                    writer.endObject();
                }
                writer.endArray(); // end params array
                writer.name("text").value((String) logEntry.getValueByKey(LogEntryField.REQUEST_BODY));
                writer.endObject(); // end postData object
            }

            writer.name("headersSize").value(logEntry.getRequest().length - logEntry.getRequestBodyLength());
            writer.name("bodySize").value(logEntry.getRequestBodyLength());

            writer.endObject(); // end request object

            writer.name("response").beginObject();
            writer.name("status").value(logEntry.getResponseStatus());
            writer.name("statusText").value(logEntry.getResponseStatusText());
            writer.name("httpVersion").value(logEntry.getResponseHttpVersion());

            writer.name("cookies").beginArray();
            if (logEntry.isHasSetCookies()) {
                List<ICookie> cookies = getResponseCookies(logEntry.getResponse());

                for (ICookie cookie : cookies) {
                    writer.beginObject();
                    writer.name("name").value(cookie.getName());
                    writer.name("value").value(cookie.getValue());
                    writer.name("path").value(cookie.getPath());
                    writer.name("domain").value(cookie.getDomain());
                    writer.endObject();
                }
            }
            writer.endArray(); // end response cookies array

            writer.name("headers").beginArray();
            if (logEntry.getResponseHeaders() != null) {
                for (String headerString : logEntry.getResponseHeaders()) {
                    if (headerString.contains(":")) {
                        writer.beginObject();
                        String headerArray[] = headerString.split(":", 2);
                        writer.name("name").value(headerArray[0]);
                        writer.name("value").value(headerArray[1].trim());
                        writer.endObject();
                    }
                }
            }
            writer.endArray(); // end response headers array

            writer.name("redirectURL").value(String.valueOf(logEntry.getValueByKey(LogEntryField.REDIRECT_URL)));
            if (logEntry.getResponse() != null) {
                writer.name("headersSize").value(logEntry.getResponse().length - logEntry.getResponseBodyLength());
                writer.name("bodySize").value(logEntry.getResponseBodyLength());
            } else {
                writer.name("headersSize").value(0);
                writer.name("bodySize").value(0);
            }


            writer.name("content").beginObject(); // start content object
            writer.name("size").value(logEntry.getResponseBodyLength());
            writer.name("mimeType").value(logEntry.getResponseMimeType());
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

    private List<IParameter> getRequestParametersByType(byte[] request, byte paramType) {
        IRequestInfo tempAnalyzedReq = LoggerPlusPlus.callbacks.getHelpers().analyzeRequest(request);
        List<IParameter> params = tempAnalyzedReq.getParameters().stream()
                .filter(iParameter -> iParameter.getType() == paramType).collect(Collectors.toList());
        return params;
    }

    private List<IParameter> getRequestBodyParameters(byte[] request) {
        IRequestInfo tempAnalyzedReq = LoggerPlusPlus.callbacks.getHelpers().analyzeRequest(request);
        List<IParameter> params = tempAnalyzedReq.getParameters().stream()
                .filter(iParameter -> iParameter.getType() != IParameter.PARAM_COOKIE
                        && iParameter.getType() != IParameter.PARAM_URL)
                .collect(Collectors.toList());
        return params;
    }

    @Override
    public List<LogEntry> read(JsonReader reader) throws IOException {
        // TODO Implement HAR Import logic
        return null;
    }

    private List<ICookie> getResponseCookies(byte[] responseMessage) {
        IResponseInfo tempAnalyzedResp = LoggerPlusPlus.callbacks.getHelpers().analyzeResponse(responseMessage);

        return tempAnalyzedResp.getCookies();
    }

}
