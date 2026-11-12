package com.nccgroup.loggerplusplus.util;

import java.nio.charset.StandardCharsets;

/**
 * Case folding of the letters A to Z only, leaving every other character as it is. This is what a
 * case-insensitive regular expression does unless told otherwise, and it is the rule reflection
 * detection has always used: {@code é} does not match {@code É}.
 */
public final class AsciiCase {
    private static final int CASE_BIT = 'a' - 'A';

    private AsciiCase() {}

    /** Texts at least this long take the bulk path; shorter ones are not worth its three copies. */
    private static final int BULK_LENGTH = 64;

    /** {@code text} with A to Z lowered; the same instance when it is short and has none. */
    public static String lower(String text) {
        if (text.length() < BULK_LENGTH) {
            return lowerChars(text);
        }
        // The JVM stores text whose characters all fit a byte as bytes. Such text survives a round
        // trip through ISO-8859-1 unchanged, and all three steps here are bulk copies or compares.
        byte[] bytes = text.getBytes(StandardCharsets.ISO_8859_1);
        if (!new String(bytes, StandardCharsets.ISO_8859_1).equals(text)) {
            return lowerChars(text);
        }
        lowerInPlace(bytes);
        return new String(bytes, StandardCharsets.ISO_8859_1);
    }

    /**
     * Lowers A to Z without a branch per byte and without carrying anything from one byte to the
     * next, so the JIT compiler can turn the loop into vector instructions: a whole response body
     * goes through here for every message with parameters.
     */
    private static void lowerInPlace(byte[] bytes) {
        for (int i = 0; i < bytes.length; i++) {
            int b = bytes[i];
            // Negative unless 'A' <= b <= 'Z'; its sign, spread over the int, masks the case bit
            // off.
            int notUpper = ((b - 'A') | ('Z' - b)) >> 31;
            bytes[i] = (byte) (b | (~notUpper & CASE_BIT));
        }
    }

    private static String lowerChars(String text) {
        char[] chars = text.toCharArray();
        boolean changed = false;
        for (int i = 0; i < chars.length; i++) {
            char c = chars[i];
            if (c >= 'A' && c <= 'Z') {
                chars[i] = (char) (c + CASE_BIT);
                changed = true;
            }
        }
        return changed ? new String(chars) : text;
    }
}
