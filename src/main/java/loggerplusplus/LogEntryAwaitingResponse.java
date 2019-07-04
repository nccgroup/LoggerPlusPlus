package loggerplusplus;

import java.util.Date;
import java.util.UUID;

public class LogEntryAwaitingResponse extends LogEntry {

    private int modelIndex = -1;
    private UUID reference;

    public LogEntryAwaitingResponse(Date requestTime){
        super(requestTime);
        this.reference = UUID.randomUUID();
    }


    public static LogEntryAwaitingResponse createEntry(Date arrivalTime){
        return new LogEntryAwaitingResponse(arrivalTime);
    }

    public static LogEntryAwaitingResponse createImportedEntry(){
        throw new IllegalStateException();
    }

    public UUID getReference() {
        return reference;
    }

    public int getModelIndex() {
        return modelIndex;
    }

    public void setModelIndex(int modelIndex) {
        this.modelIndex = modelIndex;
    }
}
