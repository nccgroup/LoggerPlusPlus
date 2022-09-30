package com.nccgroup.loggerplusplus.logview.processor;

import burp.IHttpRequestResponse;
import com.nccgroup.loggerplusplus.util.Globals;

import java.util.regex.Matcher;

public class LogProcessorHelper {

    public static void addIdentifierInComment(Integer identifier, IHttpRequestResponse requestResponse) {
        String originalComment = requestResponse.getComment() != null ? requestResponse.getComment() : "";
        requestResponse.setComment(originalComment + "$LPP:" + identifier + "$");
    }

    public static Integer extractAndRemoveIdentifierFromRequestResponseComment(IHttpRequestResponse requestResponse) {
        Integer identifier = null;
        if (requestResponse.getComment() != null) {
            Matcher matcher = Globals.LOG_ENTRY_ID_PATTERN.matcher(requestResponse.getComment());
            if (matcher.find()) {
                identifier = Integer.parseInt(matcher.group(1));
                requestResponse.setComment(matcher.replaceAll(""));
            }
        }

        return identifier;
    }
}
