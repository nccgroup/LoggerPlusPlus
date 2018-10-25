package loggerplusplus;

/**
 * Created by corey on 21/08/17.
 */
public interface LogEntryListener {
    void onRequestAdded(LogEntry logEntry, boolean isComplete);
    void onResponseUpdated(LogEntry existingEntry);
    void onRequestRemoved(int index, final LogEntry logEntry);
}
