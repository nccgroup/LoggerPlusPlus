package com.nccgroup.loggerplusplus.logview.processor;

import burp.api.montoya.core.Annotations;
import com.nccgroup.loggerplusplus.util.Globals;
import org.apache.commons.lang3.StringUtils;

import java.util.regex.Matcher;

public class LogProcessorHelper {

    public static Annotations addIdentifierInComment(Integer identifier, Annotations annotations) {
        String originalComment = annotations.notes() != null ? annotations.notes() : "";
        annotations = annotations.withNotes(originalComment + "$LPP:" + identifier + "$");
        return annotations;
    }

    public static Object[] extractAndRemoveIdentifierFromRequestResponseComment(Annotations annotations) {
        Integer identifier = null;
        if (!StringUtils.isEmpty(annotations.notes())) {
            Matcher matcher = Globals.LOG_ENTRY_ID_PATTERN.matcher(annotations.notes());
            if (matcher.find()) {
                identifier = Integer.parseInt(matcher.group(1));
                annotations = annotations.withNotes(matcher.replaceAll(""));
            }
        }

        return new Object[]{identifier,annotations};
    }
}
