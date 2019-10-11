package com.nccgroup.loggerplusplus.logentry;

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
