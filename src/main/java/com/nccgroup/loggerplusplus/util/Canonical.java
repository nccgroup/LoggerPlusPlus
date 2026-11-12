package com.nccgroup.loggerplusplus.util;

import java.util.concurrent.ConcurrentHashMap;

/**
 * One shared instance for each distinct short string that many log entries repeat: host names,
 * methods, content types, file extensions. Burp hands out a new string per message, so without this
 * a table of a million entries would hold a million copies of the same host name.
 *
 * <p>The table stops growing at its limit of distinct values; beyond that a value is returned as
 * given, which is still correct and only saves no memory.
 */
public final class Canonical {
    private static final Canonical SHARED = new Canonical(8192);

    private final int limit;
    private final ConcurrentHashMap<String, String> values = new ConcurrentHashMap<>();

    /** A table of its own, holding at most {@code limit} distinct values. */
    public Canonical(int limit) {
        this.limit = limit;
    }

    /** The process-wide shared instance equal to {@code value}; null stays null. */
    public static String of(String value) {
        return SHARED.shared(value);
    }

    /** This table's instance equal to {@code value}, or {@code value} itself; null stays null. */
    public String shared(String value) {
        if (value == null) {
            return null;
        }
        String shared = values.get(value);
        if (shared != null) {
            return shared;
        }
        if (values.size() >= limit) {
            return value;
        }
        shared = values.putIfAbsent(value, value);
        return shared != null ? shared : value;
    }
}
