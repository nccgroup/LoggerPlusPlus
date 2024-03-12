package com.nccgroup.loggerplusplus.logentry;

import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.log4j.Log4j2;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Date;

@Getter
@Log4j2
public class ImportingLogEntryHttpRequestResponse {
    // example: Nov 15, 2023, 6:30:46 PM
    // ...btw wt is this date time format, it is not common at all!
    // ...ffs, there is also a '0x202f' (Narrow no-break space) char in the date sometime..
    private static final SimpleDateFormat dtFormatter = new SimpleDateFormat("MMM d, y, K:m:s a");
    private static final SimpleDateFormat longDtFormatter = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    private final HttpRequestResponse httpReqRes;

    private Date requestTime = null;

    private Date responseTime = null;

    @Setter
    private Integer RTT = null;

    @Setter
    private String comment = null;

    private ToolType tool = null;

    @Setter
    private String listenInterface = null;

    public ImportingLogEntryHttpRequestResponse(HttpRequestResponse hrr) {
        this.httpReqRes = hrr;
    }

    public HttpRequest request() {
        return httpReqRes.request();
    }

    public HttpResponse response() {
        return httpReqRes.response();
    }

    private Date formattedTimeParser(String dateTimeString) throws ParseException {
        if (dateTimeString.indexOf(',') > -1)
        {
            return dtFormatter.parse(dateTimeString.replace('\u202F', ' '));
        }
        return longDtFormatter.parse(dateTimeString);
    }

    public void setRequestTime(String dateTimeString) {
        try {
            this.requestTime = formattedTimeParser(dateTimeString);
        } catch (ParseException e) {
            log.error("Failed to parse requestTime: " + dateTimeString);
            throw new RuntimeException(e);
        }
    }

    public void setResponseTime(String dateTimeString) {
        try {
            this.responseTime = formattedTimeParser(dateTimeString);
        } catch (ParseException e) {
            log.error("Failed to parse responseTime: " + dateTimeString);
            throw new RuntimeException(e);
        }
    }

    public void setTool(String toolName) {
        try {
            this.tool = ToolType.valueOf(toolName.toUpperCase());
        } catch (Exception e) {
            log.error("Error at setTool: " + toolName);
        }
    }
}
