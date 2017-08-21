package burp;

/**
 * Created by corey on 21/08/17.
 */
public interface LogEntryListener {
    void onRequestReceived(LogEntry logEntry);
    void onResponseReceived(LogEntry logEntry);
}
