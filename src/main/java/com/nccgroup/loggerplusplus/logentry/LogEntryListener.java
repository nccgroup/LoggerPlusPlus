package com.nccgroup.loggerplusplus.logentry;

/**
 * Created by corey on 21/08/17.
 */
public interface LogEntryListener {
    void onRequestAdded(int modelIndex, LogEntry logEntry, boolean isComplete);
    void onResponseUpdated(int modelIndex, LogEntry existingEntry);
    void onRequestRemoved(int modelIndex, final LogEntry logEntry);
    void onLogsCleared();
}
