package com.nccgroup.loggerplusplus.exports;

import java.io.IOException;
import java.net.HttpCookie;
import java.text.SimpleDateFormat;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import javax.swing.Icon;

import com.google.gson.TypeAdapter;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.logentry.LogEntry;
import com.nccgroup.loggerplusplus.logentry.LogEntryField;

import org.apache.commons.lang3.StringUtils;

import burp.ICookie;
import burp.IParameter;
import burp.IRequestInfo;
import burp.IResponseInfo;

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

        // Entries
        writer.name("entries").beginArray();

        for (LogEntry logEntry : logEntries) {
            // Individual entry object
            writer.beginObject();

            final String pattern = "yyyy-MM-dd'T'HH:mm:ss.SSSZ";
            SimpleDateFormat simpleDateFormat = new SimpleDateFormat(pattern);
            writer.name("startedDateTime").value(simpleDateFormat.format(logEntry.requestDateTime));

            long time = logEntry.responseDateTime.getTime() - logEntry.requestDateTime.getTime();
            writer.name("time").value(time);
            writer.name("request").beginObject();
            writer.name("method").value(logEntry.method);
            writer.name("url").value(logEntry.url.toString());
            writer.name("httpVersion").value(logEntry.requestHttpVersion);

            writer.name("cookies").beginArray();
            if (logEntry.hasCookieParam) {
                List<IParameter> cookies = getRequestParametersByType(logEntry.requestResponse.getRequest(),
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
            for (String headerString : logEntry.requestHeaders) {
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
            if (logEntry.url.getQuery() != null) {
                List<IParameter> queryParams = getRequestParametersByType(logEntry.requestResponse.getRequest(),
                        IParameter.PARAM_URL);
                for (IParameter queryParam : queryParams) {
                    writer.beginObject();
                    writer.name("name").value(queryParam.getName());
                    writer.name("value").value(queryParam.getValue());
                    writer.endObject();
                }
            }
            writer.endArray(); // end request queryString array

            if (logEntry.hasBodyParam) {
                writer.name("postData").beginObject();
                writer.name("mimeType").value(logEntry.requestContentType);
                List<IParameter> bodyParams = getRequestBodyParameters(logEntry.requestResponse.getRequest());
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

            writer.name("headersSize").value(logEntry.requestResponse.getRequest().length - logEntry.requestLength);
            writer.name("bodySize").value(logEntry.requestLength);

            writer.endObject(); // end request object

            writer.name("response").beginObject();
            writer.name("status").value(logEntry.responseStatus);
            writer.name("statusText").value(logEntry.responseStatusText);
            writer.name("httpVersion").value(logEntry.responseHttpVersion);

            writer.name("cookies").beginArray();
            if (logEntry.hasSetCookies) {
                List<ICookie> cookies = getResponseCookies(logEntry.requestResponse.getResponse());

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
            for (String headerString : logEntry.responseHeaders) {
                if (headerString.contains(":")) {
                    writer.beginObject();
                    String headerArray[] = headerString.split(":", 2);
                    writer.name("name").value(headerArray[0]);
                    writer.name("value").value(headerArray[1].trim());
                    writer.endObject();
                }
            }
            writer.endArray(); // end response headers array

            writer.name("headersSize").value(logEntry.requestResponse.getResponse().length - logEntry.responseLength);
            writer.name("bodySize").value(logEntry.responseLength);

            writer.endObject(); // end response object

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
