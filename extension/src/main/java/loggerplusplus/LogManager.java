package loggerplusplus;

import burp.*;
import loggerplusplus.filter.ColorFilter;
import loggerplusplus.userinterface.LogViewPanel;

import javax.swing.*;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import static loggerplusplus.Globals.*;
import static loggerplusplus.LoggerPlusPlus.callbacks;
import static loggerplusplus.LoggerPlusPlus.preferences;

/**
 * Created by corey on 07/09/17.
 */
public class LogManager implements IHttpListener, IProxyListener {
    public static final SimpleDateFormat sdf = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
    private final String instanceIdentifier = String.format("%02d", (int)Math.floor((Math.random()*100)));

    private final ArrayList<LogEntry> logEntries;
    private AtomicInteger pendingImport;

    private HashMap<Integer, LogEntryAwaitingResponse> pendingProxyRequests;
    private HashMap<UUID, LogEntryAwaitingResponse> pendingToolRequests;
    private ArrayList<LogEntryListener> logEntryListeners;
    private ExecutorService executorService;
    //Stats
    private int totalRequests = 0;
    private short lateResponses = 0;

    private Future importFuture;

    LogManager(){
        logEntries = new ArrayList<>();
        pendingImport = new AtomicInteger(0);
        logEntryListeners = new ArrayList<>();
        pendingProxyRequests = new HashMap<>();
        pendingToolRequests = new HashMap<>();
        LoggerPlusPlus.callbacks.getProxyHistory();

        executorService = Executors.newCachedThreadPool();

        //Create incomplete request cleanup thread so map doesn't get too big.
        ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();
        executor.scheduleAtFixedRate(new Runnable() {
            @Override
            public void run() {
                long timeNow = new Date().getTime();
                Set<Integer> keys = new HashSet<>(pendingProxyRequests.keySet());
                synchronized (pendingProxyRequests){
                    for (Integer reference : keys) { //Remove expired proxy requests from map
                        long entryTime = pendingProxyRequests.get(reference).requestDateTime.getTime();
                        long responseTimeout = (long) LoggerPlusPlus.preferences.getSetting(PREF_RESPONSE_TIMEOUT);
                        if(timeNow - entryTime > responseTimeout){
                            pendingProxyRequests.remove(reference);
                        }
                    }
                }
                Set<UUID> toolKeys = new HashSet<>(pendingToolRequests.keySet());
                synchronized (pendingToolRequests){
                    for (UUID reference : toolKeys) { //Remove expired requests from other tools from map
                        long entryTime = pendingToolRequests.get(reference).requestDateTime.getTime();
                        long responseTimeout = (long) LoggerPlusPlus.preferences.getSetting(PREF_RESPONSE_TIMEOUT);
                        if(timeNow - entryTime > responseTimeout){
                            pendingToolRequests.remove(reference);
                        }
                    }
                }
            }
        },30000, 30000, TimeUnit.MILLISECONDS);
    }


    /**
     * Process messages from all tools but proxy.
     * Adds to queue for later processing.
     * @param toolFlag
     * @param messageIsRequest
     * @param requestResponse
     */
    @Override
    public void processHttpMessage(final int toolFlag, final boolean messageIsRequest, final IHttpRequestResponse requestResponse) {
        if(toolFlag == IBurpExtenderCallbacks.TOOL_PROXY) return; //Proxy messages handled by proxy method
        if(requestResponse == null || !(Boolean) preferences.getSetting(PREF_ENABLED) || !isValidTool(toolFlag)) return;
        Date arrivalTime = new Date();

        if(!(Boolean) LoggerPlusPlus.preferences.getSetting(PREF_LOG_OTHER_LIVE)){
            //Submit normally, we're not tracking requests and responses separately.
            if(!messageIsRequest) { //But only add entries with responses.
                logRequestWithResponse(arrivalTime, toolFlag, requestResponse, false);
            }
            return;
        }

        final LogEntryAwaitingResponse logEntry;
        if(messageIsRequest){
            logEntry = logRequestAwaitingResponse(arrivalTime, toolFlag, requestResponse);
        }else{
            //Pull the uuid we stored in the comment
            UUID uuid = LogManagerHelper.extractUUIDFromRequestResponse(instanceIdentifier, requestResponse);
            if(uuid != null){
                logEntry = retrievePendingToolEntry(uuid);
                if (logEntry != null) {
                    updateRequestWithResponse(arrivalTime, logEntry, requestResponse);
                }else{
                    handleExpiredResponse(requestResponse);
                }
            }
        }
    }

    /**
     * Process messages received from the proxy tool
     * @param messageIsRequest
     * @param proxyMessage
     */
    @Override
    public void processProxyMessage(final boolean messageIsRequest, final IInterceptedProxyMessage proxyMessage) {
        //REQUEST AND RESPONSE SEPARATE
        final int toolFlag = LoggerPlusPlus.callbacks.TOOL_PROXY;
        if(proxyMessage == null || !(Boolean) preferences.getSetting(PREF_ENABLED) || !isValidTool(toolFlag)) return;
        Date arrivalTime = new Date();

        final LogEntryAwaitingResponse logEntry;
        if(messageIsRequest){
            logEntry = logRequestAwaitingResponse(arrivalTime, proxyMessage.getMessageReference(),
                                                    toolFlag, proxyMessage.getMessageInfo());
        }else{
            logEntry = retrievePendingProxyEntry(proxyMessage.getMessageReference());
            if(logEntry == null){
                handleExpiredResponse(proxyMessage.getMessageInfo());
            }else {
                updateRequestWithResponse(arrivalTime, logEntry, proxyMessage.getMessageInfo());
            }
        }
    }

    private LogEntry logRequestWithResponse(final Date arrivalTime, final int toolFlag,
                                            final IHttpRequestResponse requestResponse, final boolean isImported){
        final LogEntry logEntry;
        logEntry = isImported ? LogEntry.createImportedEntry() : LogEntry.createEntry(arrivalTime);

        executorService.submit(() -> {
            //Do this in the runnable because it can be slow for big responses, slowing the main thread.
            try {
                IRequestInfo analyzedReq = LoggerPlusPlus.callbacks.getHelpers().analyzeRequest(requestResponse);
                URL uUrl = analyzedReq.getUrl();
                if (!shouldLog(uUrl)) return; //Do not log out of scope items.

                logEntry.processRequest(toolFlag, requestResponse, uUrl, analyzedReq, null);
                if (requestResponse.getResponse() != null) logEntry.processResponse(requestResponse);
                addNewRequest(logEntry, true);
            }finally {
                if(isImported) pendingImport.getAndDecrement();
            }
        });

        return logEntry;
    }

    private LogEntryAwaitingResponse logRequestAwaitingResponse(final Date arrivalTime,
                                                                final int toolFlag,
                                                                final IHttpRequestResponse requestResponse){
        return logRequestAwaitingResponse(arrivalTime, -1, toolFlag, requestResponse);
    }

    private LogEntryAwaitingResponse logRequestAwaitingResponse(final Date arrivalTime,
                                                                final int proxyReference,
                                                                final int toolFlag,
                                                                final IHttpRequestResponse requestResponse){
        final LogEntryAwaitingResponse logEntry = new LogEntryAwaitingResponse(arrivalTime);
        if(toolFlag == IBurpExtenderCallbacks.TOOL_PROXY){
            storePendingProxyEntry(proxyReference, logEntry);
        }else {
            LogManagerHelper.tagRequestResponseWithUUID(instanceIdentifier, logEntry.getReference(), requestResponse);
            storePendingToolEntry(logEntry);
        }

        executorService.submit(() -> {
            //Do this in the runnable because it can be slow for big responses, slowing the main thread.
            IRequestInfo analyzedReq = LoggerPlusPlus.callbacks.getHelpers().analyzeRequest(requestResponse);
            URL uUrl = analyzedReq.getUrl();
            if (!shouldLog(uUrl)) return; //Do not log out of scope items.

            logEntry.processRequest(toolFlag, requestResponse, uUrl, analyzedReq, null);
            addNewRequest(logEntry, false);
        });
        return logEntry;
    }

    private void updateRequestWithResponse(final Date arrivalTime, final LogEntryAwaitingResponse logEntry,
                                           final IHttpRequestResponse requestResponse){
        executorService.submit(() -> {
            logEntry.setResponseTime(arrivalTime);
            logEntry.processResponse(requestResponse);

            //TODO Move color filter checks into separate class
            HashMap<UUID, ColorFilter> colorFilters = (HashMap<UUID, ColorFilter>) LoggerPlusPlus.preferences.getSetting(PREF_COLOR_FILTERS);
            for (ColorFilter colorFilter : colorFilters.values()) {
                logEntry.testColorFilter(colorFilter, true);
            }

            for (LogEntryListener logEntryListener : logEntryListeners) {
                logEntryListener.onResponseUpdated(logEntry.getModelIndex(), logEntry);
            }
        });
    }

    private void handleExpiredResponse(IHttpRequestResponse requestResponse){
        lateResponses++;
        if(totalRequests > 100 && ((float)lateResponses)/totalRequests > 0.17){
            MoreHelp.showWarningMessage(lateResponses + " responses have been delivered after the Logger++ timeout. Consider increasing this value.");
            //Reset late responses to prevent message being displayed again so soon.
            lateResponses = 0;
        }
    }

    private void addNewRequest(LogEntry logEntry, boolean hasResponse){
        //After handling request / response logEntries generation.

        int modelIndex;
        synchronized (logEntries) {
            int removedEntries = 0;
            while (logEntries.size() >= getMaximumEntries()) {
                final LogEntry removed = logEntries.remove(0);
                removedEntries++;
                for (LogEntryListener listener : logEntryListeners) {
                    listener.onRequestRemoved(0, removed);
                }
            }

            if(removedEntries > 0) {
                //Update model indices of entries pending their responses
                for (LogEntryAwaitingResponse entry : this.pendingProxyRequests.values()) {
                    entry.setModelIndex(entry.getModelIndex() - removedEntries);
                }
                for (LogEntryAwaitingResponse entry : this.pendingToolRequests.values()) {
                    entry.setModelIndex(entry.getModelIndex() - removedEntries);
                }
            }

            logEntries.add(logEntry);
            modelIndex = logEntries.size()-1;

            //If we haven't got its response yet, store its model index for table row update later!
            if(logEntry instanceof LogEntryAwaitingResponse){
                ((LogEntryAwaitingResponse) logEntry).setModelIndex(modelIndex);
            }
        }

        //Add to grepTable / modify existing entry.
        HashMap<UUID,ColorFilter> colorFilters =
                (HashMap<UUID, ColorFilter>) LoggerPlusPlus.preferences.getSetting(PREF_COLOR_FILTERS);
        for (ColorFilter colorFilter : colorFilters.values()) {
            logEntry.testColorFilter(colorFilter, false);
        }

        for (LogEntryListener listener : logEntryListeners) {
            listener.onRequestAdded(modelIndex, logEntry, hasResponse);
        }
        totalRequests++;
    }

    private void storePendingProxyEntry(int messageID, LogEntryAwaitingResponse logEntry) {
        synchronized (pendingProxyRequests){
            pendingProxyRequests.put(messageID, logEntry);
        }
    }

    private void storePendingToolEntry(LogEntryAwaitingResponse logEntry) {
        synchronized (pendingToolRequests){
            pendingToolRequests.put(((LogEntryAwaitingResponse) logEntry).getReference(), logEntry);
        }
    }

    private LogEntryAwaitingResponse retrievePendingToolEntry(UUID uuid){
        synchronized (pendingToolRequests) {
            return pendingToolRequests.remove(uuid);
        }
    }

    private LogEntryAwaitingResponse retrievePendingProxyEntry(int messageId){
        synchronized (pendingProxyRequests) {
            return pendingProxyRequests.remove(messageId);
        }
    }

    public ArrayList<LogEntry> getLogEntries() {
        return logEntries;
    }

    private boolean isValidTool(int toolFlag){
        return ((Boolean) preferences.getSetting(PREF_LOG_GLOBAL) ||
                ((Boolean) preferences.getSetting(PREF_LOG_PROXY) && toolFlag== IBurpExtenderCallbacks.TOOL_PROXY) ||
                ((Boolean) preferences.getSetting(PREF_LOG_INTRUDER) && toolFlag== IBurpExtenderCallbacks.TOOL_INTRUDER) ||
                ((Boolean) preferences.getSetting(PREF_LOG_REPEATER) && toolFlag== IBurpExtenderCallbacks.TOOL_REPEATER) ||
                ((Boolean) preferences.getSetting(PREF_LOG_SCANNER) && toolFlag== IBurpExtenderCallbacks.TOOL_SCANNER) ||
                ((Boolean) preferences.getSetting(PREF_LOG_SEQUENCER) && toolFlag== IBurpExtenderCallbacks.TOOL_SEQUENCER) ||
                ((Boolean) preferences.getSetting(PREF_LOG_SPIDER) && toolFlag== IBurpExtenderCallbacks.TOOL_SPIDER) ||
                ((Boolean) preferences.getSetting(PREF_LOG_EXTENDER) && toolFlag== IBurpExtenderCallbacks.TOOL_EXTENDER) ||
                ((Boolean) preferences.getSetting(PREF_LOG_TARGET_TAB) && toolFlag== IBurpExtenderCallbacks.TOOL_TARGET));
    }

    private boolean shouldLog(URL url){
        return (!(Boolean) preferences.getSetting(PREF_RESTRICT_TO_SCOPE)
                || LoggerPlusPlus.callbacks.isInScope(url));
    }

    public void reset() {
        synchronized (this.logEntries) {
            this.logEntries.clear();
        }
        synchronized (this.pendingProxyRequests) {
            this.pendingProxyRequests.clear();
        }
        this.lateResponses = 0;
        this.totalRequests = 0;
    }

    public void addLogListener(LogEntryListener listener) {
        logEntryListeners.add(listener);
    }
    public void removeLogListener(LogEntryListener listener) {
        logEntryListeners.remove(listener);
    }
    public ArrayList<LogEntryListener> getLogEntryListeners() {
        return logEntryListeners;
    }

    public int getTotalRequests() {
        return totalRequests;
    }

    public int getMaximumEntries() {
        return (int) LoggerPlusPlus.preferences.getSetting(PREF_MAXIMUM_ENTRIES);
    }

    public void importExisting(IHttpRequestResponse requestResponse) {
        int toolFlag = IBurpExtenderCallbacks.TOOL_PROXY;
        pendingImport.getAndIncrement();
        logRequestWithResponse(null, toolFlag, requestResponse, true);
    }

    public void importProxyHistory(boolean askConfirmation){
        int result = JOptionPane.OK_OPTION;
        int historySize = callbacks.getProxyHistory().length;
        int maxEntries = (int) LoggerPlusPlus.preferences.getSetting(PREF_MAXIMUM_ENTRIES);
        if(askConfirmation) {
            String message = "Import " + historySize + " items from burp suite proxy history? This will clear the current entries." +
                    "\nLarge imports may take a few minutes to process.";
            if(historySize > maxEntries) {
                message += "\nNote: History will be truncated to " + maxEntries + " entries.";
            }

            result = MoreHelp.askConfirmMessage("Burp Proxy Import",
                    message, new String[]{"Import", "Cancel"});
        }
        if(result == JOptionPane.OK_OPTION) {
            importFuture = executorService.submit(() -> {
                LoggerPlusPlus.instance.getLogManager().reset();
                LogViewPanel logViewPanel = LoggerPlusPlus.instance.getLogViewPanel();
                IHttpRequestResponse[] history = callbacks.getProxyHistory();

                int startIndex = Math.max(0, history.length-maxEntries);
                int importCount = historySize - startIndex;
                logViewPanel.showImportProgress(importCount);

                for (int index = startIndex; index < history.length; index++) {
                    importExisting(history[index]);
                }
                int pending;
                while((pending = pendingImport.get()) != 0 && !Thread.currentThread().isInterrupted()){
                    try {
                        Thread.sleep(500);
                        LoggerPlusPlus.instance.logOutput("Importing logs, " + pending + " entries remaining.");
                        logViewPanel.setProgressValue(importCount - pending);
                    } catch (InterruptedException e) {}
                }
                //All imported
                LoggerPlusPlus.instance.getLogViewPanel().showLogTable();
            });
        }
        reset();
    }

    public ExecutorService getExecutorService() {
        return executorService;
    }

    public Future getImportFuture() {
        return importFuture;
    }
}
