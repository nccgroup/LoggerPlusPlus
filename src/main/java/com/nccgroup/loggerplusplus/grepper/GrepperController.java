package com.nccgroup.loggerplusplus.grepper;

import burp.api.montoya.core.Marker;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.HttpRequestResponse;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.logentry.LogEntry;
import com.nccgroup.loggerplusplus.logview.logtable.LogTableController;
import com.nccgroup.loggerplusplus.preferences.PreferencesController;
import com.nccgroup.loggerplusplus.util.Globals;
import com.nccgroup.loggerplusplus.util.NamedThreadFactory;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class GrepperController {

    private final LogTableController logTableController;
    private final Preferences preferences;
    private final GrepperPanel grepPanel;
    private final ArrayList<GrepperListener> listeners;
    private final AtomicInteger remainingEntries;

    private ExecutorService searchExecutor;

    public GrepperController(LogTableController logTableController, PreferencesController preferencesController){
        this.logTableController = logTableController;
        this.preferences = preferencesController.getPreferences();
        this.listeners = new ArrayList<>();
        this.remainingEntries = new AtomicInteger(0);
        this.grepPanel = new GrepperPanel(this, preferences);
    }

    public LogTableController getLogTableController() {
        return logTableController;
    }

    public GrepperPanel getGrepperPanel() {
        return grepPanel;
    }

    public boolean isSearching(){
        return remainingEntries.get() > 0;
    }

    public void reset() { //TODO SwingWorker
        for (GrepperListener listener : this.listeners) {
            try {
                listener.onResetRequested();
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    public HttpRequestResponse addMarkers(HttpRequestResponse requestResponse, List<GrepResults.Match> matches) {
        List<Marker> requestMarkers = new ArrayList<>(), responseMarkers = new ArrayList<>();
        for (GrepResults.Match match : matches) {
            Marker marker = Marker.marker(match.startIndex, match.endIndex);
            if (match.isRequest) requestMarkers.add(marker);
            else responseMarkers.add(marker);
        }

        return requestResponse.withRequestMarkers(requestMarkers).withResponseMarkers(responseMarkers);
    }

    public void beginSearch(final Pattern pattern, final boolean inScopeOnly, final boolean searchRequests, final boolean searchResponses) {
        int searchThreads = this.preferences.getSetting(Globals.PREF_SEARCH_THREADS);
        this.searchExecutor = Executors.newFixedThreadPool(searchThreads, new NamedThreadFactory("LPP-Grepper"));

        new Thread(() -> {
            ArrayList<LogEntry> logEntries = new ArrayList<>(LoggerPlusPlus.instance.getLogViewController().getLogTableController().getLogTableModel().getData());
            remainingEntries.getAndSet(logEntries.size());

            this.listeners.forEach(listener -> {
                listener.onSearchStarted(pattern, logEntries.size());
            });

            for (LogEntry logEntry : logEntries) {
                searchExecutor.submit(createProcessThread(logEntry, pattern, inScopeOnly, searchRequests, searchResponses));
            }
        }).start();
    }

    private GrepResults processEntry(LogEntry entry, Pattern pattern, final boolean searchRequests, final boolean searchResponses) {
        GrepResults grepResults = null;
        if (entry != null) {
            grepResults = new GrepResults(entry);
            if (entry.getRequestBytes() != null && searchRequests) {
                processMatches(grepResults, pattern, entry.getRequestBytes(), true);
            }
            if (entry.getResponseBytes() != null && searchResponses) {
                processMatches(grepResults, pattern, entry.getResponseBytes(), false);
            }
        }
        return grepResults;
    }

    private void processMatches(GrepResults grepResults, Pattern pattern, byte[] content, boolean isRequest) {
        final Matcher respMatcher = pattern.matcher(new String(content));
        while (respMatcher.find() && !Thread.currentThread().isInterrupted()) {
            String[] groups = new String[respMatcher.groupCount() + 1];
            for (int i = 0; i < groups.length; i++) {
                groups[i] = respMatcher.group(i);
            }

            if (isRequest) {
                grepResults.addRequestMatch(new GrepResults.Match(groups, true, respMatcher.start(), respMatcher.end()));
            } else {
                grepResults.addResponseMatch(new GrepResults.Match(groups, false, respMatcher.start(), respMatcher.end()));
            }
        }
    }

    private Runnable createProcessThread(final LogEntry logEntry, final Pattern pattern,
                                         final boolean inScopeOnly, final boolean searchRequests, final boolean searchResponses) {
        return () -> {
            try {
                if (Thread.currentThread().isInterrupted()) return;
                GrepResults grepResults = null;
                if (!inScopeOnly || LoggerPlusPlus.isUrlInScope(logEntry.getUrlString())) {
                    grepResults = processEntry(logEntry, pattern, searchRequests, searchResponses);
                }
                for (GrepperListener listener : this.listeners) {
                    try {
                        listener.onEntryProcessed(grepResults);
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }finally {
                int remaining = remainingEntries.decrementAndGet();
                if (remaining == 0) {
                    for (GrepperListener listener : listeners) {
                        try {
                            listener.onSearchComplete();
                        } catch (Exception e) {
                            e.printStackTrace();
                        }
                    }
                }
            }
        };
    }

    public void cancelSearch(){
        new Thread(() -> {
            for (GrepperListener listener : listeners) {
                listener.onShutdownInitiated();
            }

            searchExecutor.shutdownNow();
            while (!searchExecutor.isTerminated()){
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException e) {
                    e.printStackTrace();
                }
            }

            for (GrepperListener listener : listeners) {
                try {
                    listener.onShutdownComplete();
                }catch (Exception e){
                    e.printStackTrace();
                }
            }

            remainingEntries.set(0);
        }).start();

    }

    public void addListener(GrepperListener listener){
        synchronized (this.listeners) {
            this.listeners.add(listener);
        }
    }

    public void removeListener(GrepperListener listener){
        synchronized (this.listeners){
            this.listeners.remove(listener);
        }
    }
}
