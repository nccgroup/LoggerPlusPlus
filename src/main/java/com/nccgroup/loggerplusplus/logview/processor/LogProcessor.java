package com.nccgroup.loggerplusplus.logview.processor;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.proxy.http.*;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.exports.ExportController;
import com.nccgroup.loggerplusplus.filter.FilterExpression;
import com.nccgroup.loggerplusplus.filter.colorfilter.TableColorRule;
import com.nccgroup.loggerplusplus.filter.tag.Tag;
import com.nccgroup.loggerplusplus.logentry.FieldGroup;
import com.nccgroup.loggerplusplus.logentry.LogEntry;
import com.nccgroup.loggerplusplus.logentry.Status;
import com.nccgroup.loggerplusplus.logview.logtable.LogTableController;
import com.nccgroup.loggerplusplus.util.NamedThreadFactory;
import com.nccgroup.loggerplusplus.util.PausableThreadPoolExecutor;
import lombok.Getter;
import lombok.extern.log4j.Log4j2;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.swing.*;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.*;

import static com.nccgroup.loggerplusplus.util.Globals.*;

/**
 * Created by corey on 07/09/17.
 */
@Log4j2
public class LogProcessor {
    public static final SimpleDateFormat LOGGER_DATE_FORMAT = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
    public static final SimpleDateFormat SERVER_DATE_FORMAT = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss zzz");
    private final LogTableController logTableController;
    private final ExportController exportController;
    private final Preferences preferences;
    private final ConcurrentHashMap<Integer, LogEntry> entriesPendingProcessing;
    private final ConcurrentHashMap<Integer, Future<LogEntry>> entryProcessingFutures;
    private final PausableThreadPoolExecutor entryProcessExecutor;
    private final PausableThreadPoolExecutor entryImportExecutor;
    private final ScheduledExecutorService cleanupExecutor;

    @Getter
    private final HttpHandler httpHandler;
    @Getter
    private final ProxyResponseHandler proxyResponseHandler;

    Logger logger = LogManager.getLogger(this);

    /**
     * Capture incoming requests and responses.
     * Logic to allow requests independently and match them to responses once received.
     * TODO SQLite integration
     */
    public LogProcessor(LogTableController logTableController, ExportController exportController) {
        this.logTableController = logTableController;
        this.exportController = exportController;
        this.preferences = LoggerPlusPlus.instance.getPreferencesController().getPreferences();

        this.entriesPendingProcessing = new ConcurrentHashMap<>();
        this.entryProcessingFutures = new ConcurrentHashMap<>();
        this.entryProcessExecutor = new PausableThreadPoolExecutor(0, 2147483647,
                30L, TimeUnit.SECONDS, new SynchronousQueue<>(), new NamedThreadFactory("LPP-LogManager"));
        this.entryImportExecutor = new PausableThreadPoolExecutor(0, 10, 60L,
                TimeUnit.MILLISECONDS, new LinkedBlockingQueue<>(), new NamedThreadFactory("LPP-Import"));

        //Create incomplete request cleanup thread so map doesn't get too big.
        this.cleanupExecutor = Executors.newSingleThreadScheduledExecutor(new NamedThreadFactory("LPP-LogManager-Cleanup"));
        this.cleanupExecutor.scheduleAtFixedRate(new AbandonedRequestCleanupRunnable(),30, 30, TimeUnit.SECONDS);

        //TODO Enable new logging API when support for matching requests and their responses improves...
        this.httpHandler = createHttpHandler();
        this.proxyResponseHandler = createProxyResponseHandler();
    }

    private HttpHandler createHttpHandler(){
        return new HttpHandler() {
            @Override
            public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent requestToBeSent) {
                if (!(Boolean) preferences.getSetting(PREF_ENABLED) || !isValidTool(requestToBeSent.toolSource().toolType())
                        || !LoggerPlusPlus.isUrlInScope(requestToBeSent.url())){
                    return RequestToBeSentAction.continueWith(requestToBeSent);
                }
                Date arrivalTime = new Date();

                //If we're handling a new request, create a log entry.
                //We must also handle proxy messages here, since the HTTP listener operates after the proxy listener
                final LogEntry logEntry = new LogEntry(requestToBeSent.toolSource().toolType(), requestToBeSent, arrivalTime);

                //Set the entry's identifier to the HTTP request's hashcode.
                // For non-proxy messages, this doesn't change when we receive the response
                Integer identifier = System.identityHashCode(requestToBeSent);

                logEntry.setIdentifier(identifier);
                Annotations annotations = LogProcessorHelper.addIdentifierInComment(identifier, requestToBeSent.annotations());
                //Submit a new task to process the entry
                submitNewEntryProcessingRunnable(logEntry);

                return RequestToBeSentAction.continueWith(requestToBeSent, annotations);
            }

            @Override
            public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {
                if (!(Boolean) preferences.getSetting(PREF_ENABLED) || !isValidTool(responseReceived.toolSource().toolType())
                        || !LoggerPlusPlus.isUrlInScope(responseReceived.initiatingRequest().url())){
                    return ResponseReceivedAction.continueWith(responseReceived);
                }
                Date arrivalTime = new Date();

                Annotations annotations = responseReceived.annotations();
                if (responseReceived.toolSource().isFromTool(ToolType.PROXY)) {
                    //If the request came from the proxy, the response isn't final yet.
                    //Instead, the response must be taken from the proxy response handler.
                    //Just tag the comment with the identifier so we can match it up later.
//                    Integer identifier = System.identityHashCode(responseReceived.initiatingRequest());
//                    annotations = LogProcessorHelper.addIdentifierInComment(identifier, annotations);
//                    return ResponseResult.responseResult(response, annotations); //Process proxy responses using processProxyMessage
                } else {
                    //Otherwise, we have the final HTTP response, and can use the request hashcode to match it up with the log entry.
                    Object[] identifierAndAnnotation = LogProcessorHelper.extractAndRemoveIdentifierFromRequestResponseComment(responseReceived.annotations());
                    Integer identifier = (Integer) identifierAndAnnotation[0]; //TODO Ew.
                    annotations = (Annotations) identifierAndAnnotation[1];
                    updateRequestWithResponse(identifier, arrivalTime, responseReceived);
                }
                return ResponseReceivedAction.continueWith(responseReceived, annotations);
            }
        };
    }

    private ProxyResponseHandler createProxyResponseHandler(){
        return new ProxyResponseHandler() {
            @Override
            public ProxyResponseReceivedAction handleResponseReceived(InterceptedResponse interceptedResponse) {
                return ProxyResponseReceivedAction.continueWith(interceptedResponse); //Do nothing
            }

            @Override
            public ProxyResponseToBeSentAction handleResponseToBeSent(InterceptedResponse interceptedResponse) {
                if(!((boolean) preferences.getSetting(PREF_ENABLED)) || !((boolean) preferences.getSetting(PREF_LOG_PROXY))
                        || !LoggerPlusPlus.isUrlInScope(interceptedResponse.initiatingRequest().url())) {
                    return ProxyResponseToBeSentAction.continueWith(interceptedResponse);
                }

                Date arrivalTime = new Date();
                Object[] identifierAndAnnotation = LogProcessorHelper.extractAndRemoveIdentifierFromRequestResponseComment(interceptedResponse.annotations());
                Integer identifier = (Integer) identifierAndAnnotation[0]; //TODO Ew.
                Annotations annotations = (Annotations) identifierAndAnnotation[1];

                updateRequestWithResponse(identifier, arrivalTime, interceptedResponse);
                return ProxyResponseToBeSentAction.continueWith(interceptedResponse, annotations);
            }
        };
    }


//    /**
//     * Process messages from all tools.
//     * Adds to queue for later processing.
//     * Note: processProxyMessage runs *after* processHttpMessage, responses from the proxy tool are left for that method.
//     *
//     * @param toolFlag      Tool used to make request
//     * @param isRequestOnly If the message is request only or complete with response
//     * @param httpMessage   The request and potentially response received.
//     */
//    @Override
//    public void processHttpMessage(final int toolFlag, final boolean isRequestOnly, final IHttpRequestResponse httpMessage) {
//        if (httpMessage == null || !(Boolean) preferences.getSetting(PREF_ENABLED) || !isValidTool(toolFlag)) return;
//        Date arrivalTime = new Date();
//
//        if (isRequestOnly) {
//            //If we're handling a new request, create a log entry.
//            //We must also handle proxy messages here, since the HTTP listener operates after the proxy listener
//            final LogEntry logEntry = new LogEntry(toolFlag, arrivalTime, httpMessage);
//
//            //Set the entry's identifier to the HTTP request's hashcode.
//            // For non-proxy messages, this doesn't change when we receive the response
//            logEntry.setIdentifier(System.identityHashCode(httpMessage.getRequest()));
//            //Submit a new task to process the entry
//            submitNewEntryProcessingRunnable(logEntry);
//        } else {
//            if (toolFlag == IBurpExtendermontoya.TOOL_PROXY) {
//                //If the request came from the proxy, the response isn't final yet.
//                //Just tag the comment with the identifier so we can match it up later.
//                Integer identifier = System.identityHashCode(httpMessage.getRequest());
//                LogProcessorHelper.addIdentifierInComment(identifier, httpMessage);
//                return; //Process proxy responses using processProxyMessage
//            } else {
//                //Otherwise, we have the final HTTP response, and can use the request hashcode to match it up with the log entry.
//                Integer identifier = System.identityHashCode(httpMessage.getRequest());
//                updateRequestWithResponse(identifier, arrivalTime, httpMessage);
//            }
//        }
//    }
//
//    /**
//     * Since this method runs after processHttpMessage, we must use it to get the final response for proxy tool requests
//     * otherwise, changes to the message by other tools using processProxyMessage would not be seen!
//     *
//     * @param isRequestOnly
//     * @param proxyMessage
//     */
//    @Override
//    public void processProxyMessage(final boolean isRequestOnly, final IInterceptedProxyMessage proxyMessage) {
//        final int toolFlag = IBurpExtendermontoya.TOOL_PROXY;
//        if (proxyMessage == null || !(Boolean) preferences.getSetting(PREF_ENABLED) || !isValidTool(toolFlag)) return;
//        Date arrivalTime = new Date();
//
//        if (isRequestOnly) {
//
//        } else { //We only want to handle responses.
//            Integer identifier = LogProcessorHelper.extractAndRemoveIdentifierFromRequestResponseComment(proxyMessage.getMessageInfo());
//            updateRequestWithResponse(identifier, arrivalTime, proxyMessage.getMessageInfo());
//        }
//    }

    /**
     * When a response comes in, determine if the request has already been processed or not.
     * If it has not yet been processed, add the response information to the entry and let the original job handle it.
     * Otherwise, create a new job to process the response.
     * Unknown UUID's signify the response arrived after the pending request was cleaned up.
     *
     * @param entryIdentifier The unique UUID for the log entry.
     * @param arrivalTime     The arrival time of the response.
     * @param response The HTTP request response object.
     */
    private void updateRequestWithResponse(Integer entryIdentifier, Date arrivalTime, HttpResponse response) {
        log.debug("Updating entry with response for ID: " + entryIdentifier);
        if (entriesPendingProcessing.containsKey(entryIdentifier)) {
            //Not yet started processing the entry, we can add the response so it is processed in the first pass
            final LogEntry logEntry = entriesPendingProcessing.get(entryIdentifier);
            //Update the response with the new one, and tell it when it arrived.
            logEntry.addResponse(response, arrivalTime);

            //Do nothing now, there's already a runnable submitted to process it somewhere in the queue.
            return;

        } else if (entryProcessingFutures.containsKey(entryIdentifier)) {
            //Already started processing.

            //Get the processing thread
            Future<LogEntry> processingFuture = entryProcessingFutures.get(entryIdentifier);

            //Submit a job for the processing of its response.
            //This will block on the request finishing processing, then update the response and process it separately.
            entryProcessExecutor.submit(createEntryUpdateRunnable(processingFuture, response, arrivalTime));
        } else {
            //Unknown Identifier. Potentially for a request which was ignored or cleaned up already?
        }
    }

    /**
     * Create a runnable to be used in an executor which will process a
     * HTTP object and store the results in the provided LogEntry object.
     * @param logEntry The LogEntry object which will store the processed results
     * @return LogEntry Stores the processed results
     */
    LogEntry processEntry(final LogEntry logEntry){
        synchronized (logEntry) {
            logEntry.process();

            //If the status has been changed
            if (logEntry.getStatus() != logEntry.getPreviousStatus()) {
                FilterExpression doNotLogExpression = preferences.getSetting(PREF_DO_NOT_LOG_IF_MATCH);
                if(doNotLogExpression != null){
                    if (logEntry.getStatus() == Status.PROCESSED || !doNotLogExpression.getRequiredContexts().contains(FieldGroup.RESPONSE)) {
                        //If we're dealing with a complete entry, or if the filter doesn't need the response.
                        if(doNotLogExpression.matches(logEntry)){
                            return null;
                        }
                    }
                }

                //Check against color filters
                HashMap<UUID, TableColorRule> colorFilters = preferences.getSetting(PREF_COLOR_FILTERS);
                for (TableColorRule tableColorRule : colorFilters.values()) {
                    logEntry.testColorFilter(tableColorRule, true);
                }

                //Check against tags
                HashMap<UUID, Tag> tagMap = preferences.getSetting(PREF_TAG_FILTERS);
                for (Tag tag : tagMap.values()) {
                    logEntry.testTag(tag, true);
                }
            }
        }
        return logEntry;
    }

    private void submitNewEntryProcessingRunnable(final LogEntry logEntry){
        log.debug("Adding log process request for ID: " + logEntry.getIdentifier());
        entriesPendingProcessing.put(logEntry.getIdentifier(), logEntry);
        RunnableFuture<LogEntry> processingRunnable = new FutureTask<>(() -> {
            entriesPendingProcessing.remove(logEntry.getIdentifier());
            LogEntry result = processEntry(logEntry);

            if(result == null) {
                entryProcessingFutures.remove(logEntry.getIdentifier());
                return null; //Ignored entry. Skip it.
            }else{
                addNewEntry(logEntry, true);

                if(result.getStatus() == Status.PROCESSED){
                    //If the entry was fully processed, remove it from the processing list.
                    entryProcessingFutures.remove(logEntry.getIdentifier());
                }else{
                    //We're waiting on the response, we'll use this future to know we're done later.
                }
                return result;
            }
        });
        entryProcessingFutures.put(logEntry.getIdentifier(), processingRunnable);
        entryProcessExecutor.submit(processingRunnable);
    }

    private RunnableFuture<LogEntry> createEntryUpdateRunnable(final Future<LogEntry> processingFuture,
                                                              final HttpResponse requestResponse,
                                                              final Date arrivalTime){
        return new FutureTask<>(() -> {
            //Block until initial processing is complete.
            LogEntry logEntry = processingFuture.get();
            if (logEntry == null) {
                //Request was filtered during response processing. We can just ignore the response.
                return null;
            }

            //Request was processed successfully... now process the response.
            logEntry.addResponse(requestResponse, arrivalTime);
            LogEntry updatedEntry = processEntry(logEntry);

            if(updatedEntry == null){
                //Response must have been filtered out. Delete the existing entry and stop processing
                removeExistingEntry(logEntry);
                entryProcessingFutures.remove(logEntry.getIdentifier());
                return null;
            }

            if (logEntry.getStatus() == Status.PROCESSED) {
                //If the entry was fully processed, remove it from the processing list.
                entryProcessingFutures.remove(logEntry.getIdentifier());
            }

            updateExistingEntry(logEntry);

            return logEntry;
        });
    }

    public EntryImportWorker.Builder createEntryImportBuilder(){
        return new EntryImportWorker.Builder(this);
    }

    public void importProxyHistory(boolean sendToAutoExporters) {
        //TODO Fix time bug for imported results. Multithreading means results will likely end up mixed.
        //TODO Remove to more suitable UI class and show dialog

        //Build list of entries to import
        List<ProxyHttpRequestResponse> proxyHistory = LoggerPlusPlus.montoya.proxy().history();
        int maxEntries = preferences.getSetting(PREF_MAXIMUM_ENTRIES);
        int startIndex = Math.max(proxyHistory.size() - maxEntries, 0);
        List<ProxyHttpRequestResponse> entriesToImport = proxyHistory.subList(startIndex, proxyHistory.size());

        //Build and start import worker
        EntryImportWorker importWorker = new EntryImportWorker.Builder(this)
                .setOriginatingTool(ToolType.PROXY)
                .setProxyEntries(entriesToImport)
                .setSendToAutoExporters(sendToAutoExporters).build();

        importWorker.execute();
    }

    private boolean isValidTool(ToolType toolType){
        if(preferences.getSetting(PREF_LOG_GLOBAL)) return true;

        switch (toolType){
            case PROXY -> {return preferences.getSetting(PREF_LOG_PROXY);}
            case INTRUDER -> {return preferences.getSetting(PREF_LOG_INTRUDER);}
            case REPEATER -> {return preferences.getSetting(PREF_LOG_REPEATER);}
            case EXTENSIONS -> {return preferences.getSetting(PREF_LOG_EXTENSIONS);}
            case SCANNER -> {return preferences.getSetting(PREF_LOG_SCANNER);}
            case SEQUENCER -> {return preferences.getSetting(PREF_LOG_SEQUENCER);}
            case SUITE -> {return preferences.getSetting(PREF_LOG_SUITE);}
            case RECORDED_LOGIN_REPLAYER -> {return preferences.getSetting(PREF_LOG_RECORDED_LOGINS);}
            default -> {return false;}
        }
    }

    public void shutdown() {
        this.cleanupExecutor.shutdownNow();
        this.entryProcessExecutor.shutdownNow();
        this.entryImportExecutor.shutdownNow();
    }

    void addNewEntry(LogEntry logEntry, boolean sendToAutoExporters) {
        FilterExpression doNotLogExpression = preferences.getSetting(PREF_DO_NOT_LOG_IF_MATCH);
        SwingUtilities.invokeLater(() -> {
            if (sendToAutoExporters) exportController.exportNewEntry(logEntry);
            logTableController.getLogTableModel().addEntry(logEntry);
        });
    }

    void updateExistingEntry(LogEntry logEntry) {
        exportController.exportUpdatedEntry(logEntry);
        SwingUtilities.invokeLater(() -> {
            logTableController.getLogTableModel().updateEntry(logEntry);
        });
    }

    void removeExistingEntry(LogEntry logEntry){
        SwingUtilities.invokeLater(() -> {
            logTableController.getLogTableModel().removeLogEntry(logEntry);
        });
    }

    PausableThreadPoolExecutor getEntryImportExecutor() {
        return entryImportExecutor;
    }

    public PausableThreadPoolExecutor getEntryProcessExecutor() {
        return entryProcessExecutor;
    }


    /*************************
     *
     * Private worker implementations
     *
     *************************/

    private class AbandonedRequestCleanupRunnable implements Runnable {

        @Override
        public void run() {
            long timeNow = new Date().getTime();
            synchronized (entryProcessingFutures){
                try {
                    Iterator<Map.Entry<Integer, Future<LogEntry>>> iter
                            = entryProcessingFutures.entrySet().iterator();

                    while (iter.hasNext()) {
                        Map.Entry<Integer, Future<LogEntry>> abandonedEntry = iter.next();
                        if(abandonedEntry.getValue().isDone()){
                            LogEntry logEntry = abandonedEntry.getValue().get();
                            if (logEntry.getRequestDateTime() == null) {
                                //Should never be the case.
                                //Entries should always have request times unless they are imported,
                                //In which case they will never be awaiting a response so never in this list.
                                continue;
                            }
                            long entryTime = logEntry.getRequestDateTime().getTime();
                            long responseTimeout = 1000 * ((Integer) preferences.getSetting(PREF_RESPONSE_TIMEOUT)).longValue();
                            if (timeNow - entryTime > responseTimeout) {
                                iter.remove();
                                if (logEntry.getTool() == ToolType.PROXY) {
                                    //Remove the identifier from the comment.
                                    //TODO Fix Comment cleanup
//                                    LogEntry.extractAndRemoveIdentifierFromComment(logEntry);
                                }
                                logEntry.setComment(logEntry.getComment() + " Timed Out");
                            }
                        }
                    }
                }catch (Exception e){
                    e.printStackTrace();
                }
            }
        }
    }
}
