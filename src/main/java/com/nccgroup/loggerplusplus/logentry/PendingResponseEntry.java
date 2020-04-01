package com.nccgroup.loggerplusplus.logentry;

public class PendingResponseEntry {

    private final LogEntry logEntry;
    private int modelIndex = -1;

    public PendingResponseEntry(LogEntry logEntry){
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
