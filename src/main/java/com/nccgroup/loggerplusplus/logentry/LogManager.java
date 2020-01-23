package com.nccgroup.loggerplusplus.logentry;

import burp.*;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.util.MoreHelp;
import com.nccgroup.loggerplusplus.filter.colorfilter.ColorFilter;
import com.nccgroup.loggerplusplus.logview.LogViewPanel;
import com.nccgroup.loggerplusplus.util.NamedThreadFactory;

import javax.swing.*;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;

import static com.nccgroup.loggerplusplus.util.Globals.*;

/**
 * Created by corey on 07/09/17.
 */
public class LogManager implements IHttpListener, IProxyListener {
    public static final SimpleDateFormat sdf = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
    private final String instanceIdentifier = String.format("%02d", (int)Math.floor((Math.random()*100)));

    private final ArrayList<LogEntry> logEntries;
    private AtomicInteger pendingImport;

    private final ConcurrentHashMap<Integer, UUID> proxyIdToUUIDMap;
    private final ConcurrentHashMap<UUID, LogEntry> pendingRequests;
    private final ConcurrentHashMap<UUID, EntryPendingResponse> requestsAwaitingResponse;
    private final ArrayList<LogEntryListener> logEntryListeners;
    private final ExecutorService executorService;
    private final ScheduledExecutorService cleanupExecutor;
    private final ScheduledFuture cleanupFuture;
    //Stats
    private AtomicInteger totalRequests;
    private short lateResponses = 0;

    private Future importFuture;

    public LogManager(){
        this.totalRequests = new AtomicInteger(0);
        logEntries = new ArrayList<>();
        pendingImport = new AtomicInteger(0);
        logEntryListeners = new ArrayList<>();
        proxyIdToUUIDMap = new ConcurrentHashMap<>();
        pendingRequests = new ConcurrentHashMap<>();
        requestsAwaitingResponse = new ConcurrentHashMap<>();
        LoggerPlusPlus.callbacks.getProxyHistory();

        //TODO Customizable LogManager thread count.
        executorService = Executors.newFixedThreadPool(20, new NamedThreadFactory("LPP-LogManager"));

        //Create incomplete request cleanup thread so map doesn't get too big.
        cleanupExecutor = Executors.newSingleThreadScheduledExecutor(new NamedThreadFactory("LPP-LogManager-Cleanup"));
        cleanupFuture = cleanupExecutor.scheduleAtFixedRate(() -> {
            long timeNow = new Date().getTime();
            synchronized (requestsAwaitingResponse){
                try {
                    HashSet<UUID> removedUUIDs = new HashSet<>();
                    Iterator<Map.Entry<UUID, EntryPendingResponse>> iter
                            = requestsAwaitingResponse.entrySet().iterator();

                    while (iter.hasNext()) {
                        Map.Entry<UUID, EntryPendingResponse> value = iter.next();
                        LogEntry logEntry = value.getValue().getLogEntry();
                        if(logEntry.requestDateTime == null) return;
                        long entryTime = logEntry.requestDateTime.getTime();
                        long responseTimeout = 1000 * ((Integer) LoggerPlusPlus.preferences.getSetting(PREF_RESPONSE_TIMEOUT)).longValue();
                        if (timeNow - entryTime > responseTimeout) {
                            iter.remove();
                            removedUUIDs.add(value.getKey());
                        }
                    }

                    Iterator<Map.Entry<Integer, UUID>> proxyMapIter = proxyIdToUUIDMap.entrySet().iterator();
                    while (proxyMapIter.hasNext()) {
                        Map.Entry<Integer, UUID> entry = proxyMapIter.next();
                        if (removedUUIDs.contains(entry.getValue())) {
                            iter.remove();
                        }
                    }

                    if (removedUUIDs.size() > 0) {
                        LoggerPlusPlus.instance.logOutput("Cleaned Up " + removedUUIDs.size()
                                + " proxy requests without a response after the specified timeout.");
                    }
                }catch (Exception e){
                    e.printStackTrace();
                }
            }
        },120000L, 120000L, TimeUnit.MILLISECONDS);
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
        if(requestResponse == null || !(Boolean) LoggerPlusPlus.preferences.getSetting(PREF_ENABLED) || !isValidTool(toolFlag)) return;
        Date arrivalTime = new Date();

        if(!(Boolean) LoggerPlusPlus.preferences.getSetting(PREF_LOG_OTHER_LIVE)){
            //Submit normally, we're not tracking requests and responses separately.
            if(!messageIsRequest) { //But only add entries with responses.
                logRequestWithResponse(arrivalTime, toolFlag, requestResponse, false);
            }
            return;
        }

        final LogEntry logEntry;
        if(messageIsRequest){
            logEntry = logRequestWithoutResponse(arrivalTime, null, toolFlag, requestResponse);
        }else{
            UUID uuid = LogManagerHelper.extractUUIDFromRequestResponse(instanceIdentifier, requestResponse);
            if(uuid != null) {
                updateRequestWithResponse(uuid, arrivalTime, requestResponse);
            }
        }
    }

    /**
     * Process messages received from the proxy tool.
     * Adds to queue for later processing.
     * @param messageIsRequest
     * @param proxyMessage
     */
    @Override
    public void processProxyMessage(final boolean messageIsRequest, final IInterceptedProxyMessage proxyMessage) {
        //REQUEST AND RESPONSE SEPARATE
        final int toolFlag = LoggerPlusPlus.callbacks.TOOL_PROXY;
        if(proxyMessage == null || !(Boolean) LoggerPlusPlus.preferences.getSetting(PREF_ENABLED) || !isValidTool(toolFlag)) return;
        Date arrivalTime = new Date();

        final LogEntry logEntry;
        if(messageIsRequest){
            logEntry = logRequestWithoutResponse(arrivalTime, proxyMessage.getMessageReference(),
                                                    toolFlag, proxyMessage.getMessageInfo());
            //Store our proxy specific info now.
            logEntry.clientIP = String.valueOf(proxyMessage.getClientIpAddress());
            logEntry.listenerInterface = proxyMessage.getListenerInterface();
        }else{
            //We're handling a response.
            UUID identifier = proxyIdToUUIDMap.remove(proxyMessage.getMessageReference());
            if(identifier != null){
                updateRequestWithResponse(identifier, arrivalTime, proxyMessage.getMessageInfo());
            }
        }
    }

    private LogEntry logRequestWithResponse(final Date arrivalTime, final int toolFlag,
                                            final IHttpRequestResponse requestResponse, boolean isImported){
        final LogEntry logEntry = new LogEntry(toolFlag, true, arrivalTime, requestResponse);
        logEntry.isImported = isImported;
        executorService.submit(createNewEntryRunnable(logEntry));
        return logEntry;
    }

    private LogEntry logRequestWithoutResponse(final Date arrivalTime,
                                               final Integer proxyReference,
                                               final int toolFlag,
                                               final IHttpRequestResponse requestResponse){

        //We do not have the response for the request yet.
        final LogEntry logEntry = new LogEntry(toolFlag, false, arrivalTime, requestResponse);

        if(toolFlag == IBurpExtenderCallbacks.TOOL_PROXY){
            //Make a note of the entry UUID corresponding to the message identifier.
            proxyIdToUUIDMap.put(proxyReference, logEntry.getIdentifier());
        }else {
            //Tag the request with the UUID in the comment field, as this persists for when we get the response back!
            LogManagerHelper.tagRequestResponseWithUUID(instanceIdentifier, logEntry.getIdentifier(), requestResponse);
        }

        pendingRequests.put(logEntry.getIdentifier(), logEntry);
        //Create a task to be executed at some point in the future, and queue it.
        executorService.submit(createNewEntryRunnable(logEntry));
        return logEntry;
    }

    private Runnable createNewEntryRunnable(final LogEntry logEntry){
        return () -> {
            //Do this in the runnable because it can be slow for big responses, slowing the main thread.
            synchronized (logEntry) {
                try {
                    IRequestInfo analyzedReq = LoggerPlusPlus.callbacks.getHelpers().analyzeRequest(logEntry.requestResponse);
                    URL uUrl = analyzedReq.getUrl();
                    if (!shouldLog(uUrl)) return; //Do not log out of scope items.

                    //We will always have a request to work with at least.
                    logEntry.processRequest(analyzedReq);

                    if (logEntry.requestResponse.getResponse() == null) {
                        //We're waiting on the response, move the entry from pending to the waitingForResponse list
                        LoggerPlusPlus.instance.logOutput("Processing without response.");
                        EntryPendingResponse entryPendingResponse = moveEntryToPendingResponse(logEntry);
                        int modelIndex = addNewRequest(logEntry, false);
                        entryPendingResponse.setModelIndex(modelIndex);
                    } else {
                        //Either we got the initial request with the response
                        //Or the response was received before we started processing.
                        logEntry.processResponse();

                        //We have our request, and our response!
                        addNewRequest(logEntry, true);

                        //We're done with processing the entry. We can finalize it.
                        finalizeEntry(logEntry);
                    }
                }catch (Exception e){
                    e.printStackTrace();
                } finally {
                    if (logEntry.isImported) pendingImport.getAndDecrement();
                }
            }
        };
    }

    private void updateRequestWithResponse(UUID entryIdentifier, Date arrivalTime, IHttpRequestResponse requestResponse){
        if(pendingRequests.containsKey(entryIdentifier)){
            //The entry has not been processed yet! We can add its response data before its processed.

            //We must remove it from the pendingRequests list to prevent memory leaks.
            final LogEntry logEntry = pendingRequests.remove(entryIdentifier);

            synchronized (logEntry) {
                //Update the requestResponse with the new one, and tell it when it arrived.
                logEntry.addResponse(arrivalTime, requestResponse);
            }

            //Do nothing now, there's already a runnable submitted to process it in the queue.

        }else if(requestsAwaitingResponse.containsKey(entryIdentifier)){

            //The entry has already been processed, we must update it with the response.
            //Remove it from the table to prevent a memory leak.
            EntryPendingResponse entryPendingResponse = requestsAwaitingResponse.remove(entryIdentifier);

            //Create and submit a job for the processing of its response.
            Runnable process = createEntryUpdateRunnable(arrivalTime, entryPendingResponse, requestResponse);
            executorService.submit(process);
        }else{
            //Unknown UUID. Potentially for a request which was cleaned up already.
            handleExpiredResponse(requestResponse);
        }
    }

    /**
     * Used to update entries which have already been added to the table, but were waiting on a response.
     * @param arrivalTime
     * @param entryAwaitingResponse
     * @param requestResponse
     * @return
     */
    private Runnable createEntryUpdateRunnable(final Date arrivalTime, final EntryPendingResponse entryAwaitingResponse,
                                               final IHttpRequestResponse requestResponse){
        return () -> {
            LogEntry logEntry = entryAwaitingResponse.getLogEntry();
            synchronized (logEntry) {
                logEntry.addResponse(arrivalTime, requestResponse);
                logEntry.processResponse();

                HashMap<UUID, ColorFilter> colorFilters = LoggerPlusPlus.preferences.getSetting(PREF_COLOR_FILTERS);
                for (ColorFilter colorFilter : colorFilters.values()) {
                    logEntry.testColorFilter(colorFilter, true);
                }

                for (LogEntryListener logEntryListener : logEntryListeners) {
                    logEntryListener.onResponseUpdated(entryAwaitingResponse.getModelIndex(), logEntry);
                }

                //We're done processing the entry now. We can finalize it.
                finalizeEntry(logEntry);
            }
        };
    }

    private void finalizeEntry(LogEntry logEntry){
        //Clean the entry up and remove any leftover processing artifacts.

    }

    private synchronized void handleExpiredResponse(IHttpRequestResponse requestResponse){
        lateResponses++;
        int totalReqs = totalRequests.get();
        if(totalReqs > 100 && ((float)lateResponses)/totalReqs > 0.17){
            MoreHelp.showWarningMessage(lateResponses + " responses have been delivered after the Logger++ timeout. Consider increasing this value.");
            //Reset late responses to prevent message being displayed again so soon.
            lateResponses = 0;
        }
    }

    /**
     * Adds the new request
     * @param logEntry
     * @param hasResponse
     */
    private int addNewRequest(LogEntry logEntry, boolean hasResponse){
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
                for (EntryPendingResponse entry : this.requestsAwaitingResponse.values()) {
                    entry.setModelIndex(entry.getModelIndex() - removedEntries);
                }
            }

            logEntries.add(logEntry);
            modelIndex = logEntries.size()-1;

            //Add to grepTable / modify existing entry.
            HashMap<UUID,ColorFilter> colorFilters = LoggerPlusPlus.preferences.getSetting(PREF_COLOR_FILTERS);
            for (ColorFilter colorFilter : colorFilters.values()) {
                logEntry.testColorFilter(colorFilter, false);
            }

            for (LogEntryListener listener : logEntryListeners) {
                listener.onRequestAdded(modelIndex, logEntry, hasResponse);
            }

        }

        totalRequests.getAndIncrement();

        //Finally, return the model index for the entry so we can
        //use it later if we're dealing with an incomplete request.
        return modelIndex;
    }

    private EntryPendingResponse moveEntryToPendingResponse(LogEntry logEntry){
        EntryPendingResponse entryAwaitingResponse = new EntryPendingResponse(logEntry);
        pendingRequests.remove(logEntry.getIdentifier());
        requestsAwaitingResponse.put(logEntry.getIdentifier(), entryAwaitingResponse);
        return entryAwaitingResponse;
    }

    public ArrayList<LogEntry> getLogEntries() {
        return logEntries;
    }

    private boolean isValidTool(int toolFlag){
        return ((Boolean) LoggerPlusPlus.preferences.getSetting(PREF_LOG_GLOBAL) ||
                ((Boolean) LoggerPlusPlus.preferences.getSetting(PREF_LOG_PROXY) && toolFlag== IBurpExtenderCallbacks.TOOL_PROXY) ||
                ((Boolean) LoggerPlusPlus.preferences.getSetting(PREF_LOG_INTRUDER) && toolFlag== IBurpExtenderCallbacks.TOOL_INTRUDER) ||
                ((Boolean) LoggerPlusPlus.preferences.getSetting(PREF_LOG_REPEATER) && toolFlag== IBurpExtenderCallbacks.TOOL_REPEATER) ||
                ((Boolean) LoggerPlusPlus.preferences.getSetting(PREF_LOG_SCANNER) && toolFlag== IBurpExtenderCallbacks.TOOL_SCANNER) ||
                ((Boolean) LoggerPlusPlus.preferences.getSetting(PREF_LOG_SEQUENCER) && toolFlag== IBurpExtenderCallbacks.TOOL_SEQUENCER) ||
                ((Boolean) LoggerPlusPlus.preferences.getSetting(PREF_LOG_SPIDER) && toolFlag== IBurpExtenderCallbacks.TOOL_SPIDER) ||
                ((Boolean) LoggerPlusPlus.preferences.getSetting(PREF_LOG_EXTENDER) && toolFlag== IBurpExtenderCallbacks.TOOL_EXTENDER) ||
                ((Boolean) LoggerPlusPlus.preferences.getSetting(PREF_LOG_TARGET_TAB) && toolFlag== IBurpExtenderCallbacks.TOOL_TARGET));
    }

    private boolean shouldLog(URL url){
        return (!(Boolean) LoggerPlusPlus.preferences.getSetting(PREF_RESTRICT_TO_SCOPE)
                || LoggerPlusPlus.callbacks.isInScope(url));
    }

    public void reset() {
        synchronized (this.logEntries) {
            this.logEntries.clear();
        }
        synchronized (this.proxyIdToUUIDMap) {
            this.proxyIdToUUIDMap.clear();
        }
        this.lateResponses = 0;
        this.totalRequests.set(0);

        for (LogEntryListener logEntryListener : logEntryListeners) {
            logEntryListener.onLogsCleared();
        }
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

    public int getMaximumEntries() {
        return (int) LoggerPlusPlus.preferences.getSetting(PREF_MAXIMUM_ENTRIES);
    }

    public void importExisting(IHttpRequestResponse requestResponse) {
        int toolFlag = IBurpExtenderCallbacks.TOOL_PROXY;
        pendingImport.getAndIncrement();
        //Null arrival time as we cannot know when the request was sent!
        logRequestWithResponse(null, toolFlag, requestResponse, true);
    }

    public void importProxyHistory(boolean askConfirmation){
        int result = JOptionPane.OK_OPTION;
        int historySize = LoggerPlusPlus.callbacks.getProxyHistory().length;
        int maxEntries = LoggerPlusPlus.preferences.getSetting(PREF_MAXIMUM_ENTRIES);
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
                IHttpRequestResponse[] history = LoggerPlusPlus.callbacks.getProxyHistory();

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

    public void shutdown(){
        this.cleanupExecutor.shutdownNow();
        this.executorService.shutdownNow();
        if(!importFuture.isDone()){
            importFuture.cancel(true);
        }
    }
}
