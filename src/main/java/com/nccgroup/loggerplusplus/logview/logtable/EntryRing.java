package com.nccgroup.loggerplusplus.logview.logtable;

import com.nccgroup.loggerplusplus.logentry.LogEntry;
import java.util.Arrays;

/**
 * The log table's rows, oldest first, in an array used as a ring. A full table drops its oldest row
 * for every row it gains: in a ring that moves one index instead of shifting every row down, as
 * removing the first element of a list does.
 *
 * <p>Rows are kept in the order of their {@linkplain LogEntry#getArrivalNumber() arrival numbers},
 * so the row of an entry is found by binary search. Not thread-safe: the model guards it.
 */
final class EntryRing {
    private LogEntry[] rows = new LogEntry[16];
    private int head;
    private int size;

    int size() {
        return size;
    }

    LogEntry get(int index) {
        if (index < 0 || index >= size) {
            throw new IndexOutOfBoundsException("Row " + index + " of " + size);
        }
        return rows[slot(index)];
    }

    void addLast(LogEntry entry) {
        if (size == rows.length) {
            grow();
        }
        rows[slot(size)] = entry;
        size++;
    }

    /** Drops the {@code count} oldest rows. */
    void removeFirst(int count) {
        for (int i = 0; i < count; i++) {
            rows[head] = null;
            head = head + 1 == rows.length ? 0 : head + 1;
        }
        size -= count;
    }

    /** Drops one row, closing the gap by moving the newer rows down. */
    void remove(int index) {
        get(index);
        for (int i = index; i < size - 1; i++) {
            rows[slot(i)] = rows[slot(i + 1)];
        }
        rows[slot(size - 1)] = null;
        size--;
    }

    void clear() {
        Arrays.fill(rows, null);
        head = 0;
        size = 0;
    }

    /** The row holding {@code entry}, or -1 when it is not (or no longer) in the table. */
    int indexOf(LogEntry entry) {
        long arrivalNumber = entry.getArrivalNumber();
        int low = 0;
        int high = size - 1;
        while (low <= high) {
            int middle = (low + high) >>> 1;
            long candidate = rows[slot(middle)].getArrivalNumber();
            if (candidate < arrivalNumber) {
                low = middle + 1;
            } else if (candidate > arrivalNumber) {
                high = middle - 1;
            } else {
                return rows[slot(middle)] == entry ? middle : -1;
            }
        }
        return -1;
    }

    /** Every row, oldest first, in a new array. */
    LogEntry[] toArray() {
        LogEntry[] copy = new LogEntry[size];
        for (int i = 0; i < size; i++) {
            copy[i] = rows[slot(i)];
        }
        return copy;
    }

    private int slot(int index) {
        int slot = head + index;
        return slot >= rows.length ? slot - rows.length : slot;
    }

    private void grow() {
        LogEntry[] larger = new LogEntry[rows.length * 2];
        for (int i = 0; i < size; i++) {
            larger[i] = rows[slot(i)];
        }
        rows = larger;
        head = 0;
    }
}
