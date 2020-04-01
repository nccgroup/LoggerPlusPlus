package com.nccgroup.loggerplusplus.logentry;

/**
 * Created by corey on 21/08/17.
 */
public interface LogEntryListener {
    void onRequestAdded(final int modelIndex, final LogEntry logEntry, final boolean isComplete);
    void onResponseUpdated(final int modelIndex, final LogEntry existingEntry);
    void onRequestRemoved(final int modelIndex, final LogEntry logEntry);
    void onLogsCleared();
}
