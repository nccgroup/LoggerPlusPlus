package com.nccgroup.loggerplusplus.logview.processor;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Date;

/**
 * The form dates take in the log table, in filters and in exports: {@code yyyy/MM/dd HH:mm:ss} in
 * the machine's time zone. Safe to share between threads, unlike the {@link SimpleDateFormat} it
 * replaces, which every worker thread used at once.
 *
 * <p>Parsing still goes through a {@link SimpleDateFormat}, one thread at a time, so a date a
 * filter accepted before is accepted now, however loosely it was written.
 */
public final class LogDateFormat {
    private static final String PATTERN = "yyyy/MM/dd HH:mm:ss";

    private final DateTimeFormatter formatter =
            DateTimeFormatter.ofPattern(PATTERN).withZone(ZoneId.systemDefault());
    private final SimpleDateFormat parser = new SimpleDateFormat(PATTERN);

    public String format(Date date) {
        return formatter.format(date.toInstant());
    }

    /** As {@link java.text.Format#format(Object)}: a date, or milliseconds since the epoch. */
    public String format(Object date) {
        if (date instanceof Date date2) {
            return format(date2);
        }
        if (date instanceof Number number) {
            return format(new Date(number.longValue()));
        }
        throw new IllegalArgumentException("Cannot format given Object as a Date");
    }

    public String format(long epochMillis) {
        return formatter.format(java.time.Instant.ofEpochMilli(epochMillis));
    }

    public Date parse(String text) throws ParseException {
        synchronized (parser) {
            return parser.parse(text);
        }
    }
}
