package com.nccgroup.loggerplusplus.grepper;

import java.util.regex.Pattern;

public interface GrepperListener {
    void onSearchStarted(Pattern pattern, int searchEntries);
    void onEntryProcessed(GrepResults entryResults);
    void onResetRequested();
    void onSearchComplete();
    void onShutdownInitiated();
    void onShutdownComplete();
}
