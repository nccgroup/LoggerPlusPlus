package com.nccgroup.loggerplusplus.logentry;

/**
 * Created by corey on 21/08/17.
 */
public interface LogEntryListener {
    void onRequestAdded(int index, LogEntry logEntry, boolean isComplete);
    void onResponseUpdated(int modelIndex, LogEntry existingEntry);
    void onRequestRemoved(int index, final LogEntry logEntry);
    void onLogsCleared();
}
