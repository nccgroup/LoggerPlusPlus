package loggerplusplus;

import burp.IHttpRequestResponse;

import java.util.Date;
import java.util.UUID;

public class EntryPendingResponse {

    private final LogEntry logEntry;
    private int modelIndex = -1;

    public EntryPendingResponse(LogEntry logEntry){
        this.logEntry = logEntry;
    }

    public LogEntry getLogEntry() {
        return logEntry;
    }

    public int getModelIndex() {
        return modelIndex;
    }

    public void setModelIndex(int modelIndex) {
        this.modelIndex = modelIndex;
    }
}
