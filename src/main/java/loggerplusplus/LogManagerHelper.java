package loggerplusplus;

import burp.IHttpRequestResponse;

import java.util.UUID;
import java.util.regex.Matcher;

public class LogManagerHelper {

    public static void tagRequestResponseWithUUID(String instanceIdentifier, UUID uuid, IHttpRequestResponse requestResponse){
        String originalComment = requestResponse.getComment() != null ? requestResponse.getComment() : "";
        requestResponse.setComment(originalComment + "$LPP:" + instanceIdentifier + ":" + uuid + "$");
    }

    public static UUID extractUUIDFromRequestResponse(String instanceIdentifier, IHttpRequestResponse requestResponse){
        UUID uuid = null;
        if(requestResponse.getComment() != null) {
            Matcher matcher = Globals.UUID_COMMENT_PATTERN.matcher(requestResponse.getComment());
            if (matcher.find() && matcher.group(1).equals(instanceIdentifier)) {
                uuid = UUID.fromString(matcher.group(2));
                requestResponse.setComment(matcher.replaceAll(""));
            }
        }

        return uuid;
    }
}
