package com.nccgroup.loggerplusplus.logview.processor;

import static com.nccgroup.loggerplusplus.util.Globals.*;

import burp.api.montoya.core.Annotations;
import burp.api.montoya.core.ToolType;
import burp.api.montoya.http.handler.HttpHandler;
import burp.api.montoya.http.handler.HttpRequestToBeSent;
import burp.api.montoya.http.handler.HttpResponseReceived;
import burp.api.montoya.http.handler.RequestToBeSentAction;
import burp.api.montoya.http.handler.ResponseReceivedAction;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.proxy.ProxyHttpRequestResponse;
import burp.api.montoya.proxy.http.InterceptedResponse;
import burp.api.montoya.proxy.http.ProxyResponseHandler;
import burp.api.montoya.proxy.http.ProxyResponseReceivedAction;
import burp.api.montoya.proxy.http.ProxyResponseToBeSentAction;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.exports.ExportController;
import com.nccgroup.loggerplusplus.filter.FilterExpression;
import com.nccgroup.loggerplusplus.filter.colorfilter.TableColorRule;
import com.nccgroup.loggerplusplus.filter.tag.Tag;
import com.nccgroup.loggerplusplus.logentry.FieldGroup;
import com.nccgroup.loggerplusplus.logentry.LogEntry;
import com.nccgroup.loggerplusplus.logentry.Status;
import com.nccgroup.loggerplusplus.logging.Log;
import com.nccgroup.loggerplusplus.logview.logtable.LogTableController;
import com.nccgroup.loggerplusplus.logview.logtable.LogTableModel;
import com.nccgroup.loggerplusplus.util.NamedThreadFactory;
import com.nccgroup.loggerplusplus.util.PausableThreadPoolExecutor;
import java.util.ConcurrentModificationException;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.FutureTask;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Consumer;
import javax.swing.SwingUtilities;
import lombok.Getter;

/**
 * Turns the requests and responses Burp reports into log entries.
 *
 * <p>Burp calls the handlers on its own threads, once for each message of every tool, so they do
 * the least possible: decide whether the message is logged, note when it arrived, and queue it. A
 * fixed pool of worker threads reads the messages, tests the filters and feeds the exporters; a
 * {@link TableFeed} then hands the entries to the table on the event dispatch thread.
 *
 * <p>A request and its response are reported separately. They are matched by an identifier that the
 * request carries in its comment until its response arrives.
 */
public class LogProcessor {
    public static final LogDateFormat LOGGER_DATE_FORMAT = new LogDateFormat();

    private final ExportController exportController;
    private final Preferences preferences;
    private final TableFeed tableFeed;

    /** Entries whose request no worker has started reading; a response can still be attached. */
    private final ConcurrentHashMap<Integer, LogEntry> entriesPendingProcessing =
            new ConcurrentHashMap<>();

    /** Entries being read, or read and waiting for their response, by identifier. */
    private final ConcurrentHashMap<Integer, Future<LogEntry>> entryProcessingFutures =
            new ConcurrentHashMap<>();

    private final AtomicInteger lastIdentifier = new AtomicInteger();
    private final PausableThreadPoolExecutor entryProcessExecutor;
    private final PausableThreadPoolExecutor entryImportExecutor;
    private final ScheduledExecutorService cleanupExecutor;

    @Getter private final HttpHandler httpHandler;
    @Getter private final ProxyResponseHandler proxyResponseHandler;

    public LogProcessor(LogTableController logTableController, ExportController exportController) {
        this(
                logTableController.getLogTableModel(),
                exportController,
                LoggerPlusPlus.instance.getPreferencesController().getPreferences(),
                SwingUtilities::invokeLater);
    }

    /**
     * @param eventThread runs a task on the event dispatch thread, later; a caller that has no
     *     user interface passes its own
     */
    LogProcessor(
            LogTableModel table,
            ExportController exportController,
            Preferences preferences,
            Executor eventThread) {
        this.exportController = exportController;
        this.preferences = preferences;
        this.tableFeed = new TableFeed(table, eventThread);

        // As many workers as processors, and a queue. One thread per message in flight, as before,
        // meant thousands of threads during a scan, each taking memory and processor time from
        // Burp.
        // Tasks start in the order they were queued, which the matching of responses relies on.
        int workers = Math.max(2, Runtime.getRuntime().availableProcessors());
        this.entryProcessExecutor =
                new PausableThreadPoolExecutor(
                        workers,
                        workers,
                        30L,
                        TimeUnit.SECONDS,
                        new LinkedBlockingQueue<>(),
                        new NamedThreadFactory("LPP-LogManager"));
        this.entryProcessExecutor.allowCoreThreadTimeOut(true);
        this.entryImportExecutor =
                new PausableThreadPoolExecutor(
                        0,
                        10,
                        60L,
                        TimeUnit.MILLISECONDS,
                        new LinkedBlockingQueue<>(),
                        new NamedThreadFactory("LPP-Import"));

        // Forget requests whose response never came, so that the map of them does not grow forever.
        this.cleanupExecutor =
                Executors.newSingleThreadScheduledExecutor(
                        new NamedThreadFactory("LPP-LogManager-Cleanup"));
        this.cleanupExecutor.scheduleAtFixedRate(
                this::forgetAbandonedRequests, 30, 30, TimeUnit.SECONDS);

        this.httpHandler = createHttpHandler();
        this.proxyResponseHandler = createProxyResponseHandler();
    }

    private HttpHandler createHttpHandler() {
        return new HttpHandler() {
            @Override
            public RequestToBeSentAction handleHttpRequestToBeSent(
                    HttpRequestToBeSent requestToBeSent) {
                ToolType tool = requestToBeSent.toolSource().toolType();
                if (!isLogged(tool, requestToBeSent.url())) {
                    return RequestToBeSentAction.continueWith(requestToBeSent);
                }
                // Proxy requests are logged here too: this handler runs after the proxy's own.
                Integer identifier = logRequest(tool, requestToBeSent, new Date());
                Annotations annotations =
                        LogProcessorHelper.addIdentifierInComment(
                                identifier, requestToBeSent.annotations());
                return RequestToBeSentAction.continueWith(requestToBeSent, annotations);
            }

            @Override
            public ResponseReceivedAction handleHttpResponseReceived(
                    HttpResponseReceived responseReceived) {
                ToolType tool = responseReceived.toolSource().toolType();
                if (!isLogged(tool, responseReceived.initiatingRequest().url())) {
                    return ResponseReceivedAction.continueWith(responseReceived);
                }
                Date arrivalTime = new Date();
                Annotations annotations = responseReceived.annotations();
                // A proxy response is not final here: other extensions may still change it. It is
                // logged by the proxy response handler below, and keeps its identifier until then.
                if (!responseReceived.toolSource().isFromTool(ToolType.PROXY)) {
                    Object[] identifierAndAnnotations =
                            LogProcessorHelper.extractAndRemoveIdentifierFromRequestResponseComment(
                                    annotations);
                    annotations = (Annotations) identifierAndAnnotations[1];
                    logResponse(
                            (Integer) identifierAndAnnotations[0], responseReceived, arrivalTime);
                }
                return ResponseReceivedAction.continueWith(responseReceived, annotations);
            }
        };
    }

    private ProxyResponseHandler createProxyResponseHandler() {
        return new ProxyResponseHandler() {
            @Override
            public ProxyResponseReceivedAction handleResponseReceived(
                    InterceptedResponse interceptedResponse) {
                return ProxyResponseReceivedAction.continueWith(interceptedResponse);
            }

            @Override
            public ProxyResponseToBeSentAction handleResponseToBeSent(
                    InterceptedResponse interceptedResponse) {
                if (!isLogged(ToolType.PROXY, interceptedResponse.initiatingRequest().url())) {
                    return ProxyResponseToBeSentAction.continueWith(interceptedResponse);
                }
                Date arrivalTime = new Date();
                Object[] identifierAndAnnotations =
                        LogProcessorHelper.extractAndRemoveIdentifierFromRequestResponseComment(
                                interceptedResponse.annotations());
                logResponse(
                        (Integer) identifierAndAnnotations[0], interceptedResponse, arrivalTime);
                return ProxyResponseToBeSentAction.continueWith(
                        interceptedResponse, (Annotations) identifierAndAnnotations[1]);
            }
        };
    }

    private boolean isLogged(ToolType tool, String url) {
        return (Boolean) preferences.getSetting(PREF_ENABLED)
                && isValidTool(tool)
                && LoggerPlusPlus.isUrlInScope(url);
    }

    /**
     * Queues a request for logging.
     *
     * @return the identifier to pass to {@link #logResponse} when its response arrives
     */
    Integer logRequest(ToolType tool, HttpRequest request, Date arrivalTime) {
        LogEntry logEntry = new LogEntry(tool, request, arrivalTime);
        // A counter, not the request object's identity hash as before: two live objects can share
        // a hash, and two requests sharing an identifier would get each other's responses.
        Integer identifier = lastIdentifier.incrementAndGet();
        logEntry.setIdentifier(identifier);

        entriesPendingProcessing.put(identifier, logEntry);
        FutureTask<LogEntry> processing = new FutureTask<>(() -> processNewEntry(logEntry));
        entryProcessingFutures.put(identifier, processing);
        entryProcessExecutor.execute(processing);
        return identifier;
    }

    /**
     * Attaches a response to the request logged under {@code identifier}. If no worker has started
     * on the request, both are read in one pass; otherwise the response is read once the request
     * has been. An identifier that is null or unknown (the request was not logged, or was given up
     * on after the response timeout) is ignored.
     */
    void logResponse(Integer identifier, HttpResponse response, Date arrivalTime) {
        if (identifier == null) {
            return;
        }
        // The map runs this while holding the entry's place in it, and the worker takes the entry
        // out of the map before reading it: so either the worker has not started and will see the
        // response, or the entry is no longer pending and the response is queued behind it below.
        LogEntry stillPending =
                entriesPendingProcessing.computeIfPresent(
                        identifier,
                        (id, pending) -> {
                            attachResponse(pending, response, arrivalTime);
                            return pending;
                        });
        if (stillPending != null) {
            return;
        }
        Future<LogEntry> processing = entryProcessingFutures.get(identifier);
        if (processing != null) {
            entryProcessExecutor.execute(() -> processResponse(processing, response, arrivalTime));
        }
    }

    /** Gives the entry its response and, for a proxied one, the proxy listener it came through. */
    private static void attachResponse(LogEntry logEntry, HttpResponse response, Date arrivalTime) {
        if (response instanceof InterceptedResponse intercepted) {
            logEntry.setListenerInterface(intercepted.listenerInterface());
        }
        logEntry.addResponse(response, arrivalTime);
    }

    /** On a worker: reads a new entry and, unless a filter says not to log it, shows it. */
    private LogEntry processNewEntry(LogEntry logEntry) {
        Integer identifier = logEntry.getIdentifier();
        try {
            entriesPendingProcessing.remove(identifier);
            LogEntry result = processEntry(logEntry);
            if (result == null) {
                entryProcessingFutures.remove(identifier);
                return null;
            }
            addNewEntry(logEntry, true);
            if (result.getStatus() == Status.PROCESSED) {
                entryProcessingFutures.remove(identifier);
            }
            // Otherwise the future stays, for the response to find the entry by.
            return result;
        } catch (RuntimeException e) {
            entryProcessingFutures.remove(identifier);
            Log.error("Could not log a request to " + logEntry.getUrlString(), e);
            return null;
        }
    }

    /** On a worker: reads the response of an entry whose request another task has read. */
    private void processResponse(
            Future<LogEntry> processing, HttpResponse response, Date arrivalTime) {
        LogEntry logEntry;
        try {
            logEntry = processing.get();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return;
        } catch (ExecutionException e) {
            return;
        }
        if (logEntry == null) {
            return; // The request was filtered out, so its response is not wanted either.
        }

        Integer identifier = logEntry.getIdentifier();
        try {
            LogEntry updated;
            synchronized (logEntry) {
                attachResponse(logEntry, response, arrivalTime);
                updated = processEntry(logEntry);
            }
            if (updated == null) {
                // With its response, the entry now matches the do-not-log filter.
                removeExistingEntry(logEntry);
                entryProcessingFutures.remove(identifier);
                return;
            }
            if (logEntry.getStatus() == Status.PROCESSED) {
                entryProcessingFutures.remove(identifier);
            }
            updateExistingEntry(logEntry);
        } catch (RuntimeException e) {
            entryProcessingFutures.remove(identifier);
            Log.error("Could not log the response from " + logEntry.getUrlString(), e);
        }
    }

    /**
     * Reads what has arrived of an entry and tests it against the do-not-log filter, the colour
     * rules and the tags.
     *
     * @return the entry, or null if the do-not-log filter matches it
     */
    LogEntry processEntry(final LogEntry logEntry) {
        synchronized (logEntry) {
            logEntry.process();

            if (logEntry.getStatus() != logEntry.getPreviousStatus()) {
                FilterExpression doNotLogExpression =
                        preferences.getSetting(PREF_DO_NOT_LOG_IF_MATCH);
                // A filter that looks at the response can only be tested once the response is here.
                if (doNotLogExpression != null
                        && (logEntry.getStatus() == Status.PROCESSED
                                || !doNotLogExpression
                                        .getRequiredContexts()
                                        .contains(FieldGroup.RESPONSE))
                        && doNotLogExpression.matches(logEntry)) {
                    return null;
                }

                Map<UUID, TableColorRule> colorFilters = preferences.getSetting(PREF_COLOR_FILTERS);
                forEachRule(colorFilters, rule -> logEntry.testColorFilter(rule, true));
                Map<UUID, Tag> tags = preferences.getSetting(PREF_TAG_FILTERS);
                forEachRule(tags, tag -> logEntry.testTag(tag, true));
            }
        }
        return logEntry;
    }

    /**
     * Applies a test to every rule. The user may add or remove a rule on another thread while this
     * runs; the tests can safely be repeated, so they are, a few times at most.
     */
    private static <T> void forEachRule(Map<UUID, T> rules, Consumer<T> test) {
        for (int attempt = 0; attempt < 3; attempt++) {
            try {
                for (T rule : rules.values()) {
                    test.accept(rule);
                }
                return;
            } catch (ConcurrentModificationException editedMeanwhile) {
                // Try again with the rules as they are now.
            }
        }
    }

    public EntryImportWorker.Builder createEntryImportBuilder() {
        return new EntryImportWorker.Builder(this);
    }

    public void importProxyHistory(boolean sendToAutoExporters) {
        List<ProxyHttpRequestResponse> proxyHistory = LoggerPlusPlus.montoya.proxy().history();
        int maxEntries = preferences.getSetting(PREF_MAXIMUM_ENTRIES);
        int startIndex = Math.max(proxyHistory.size() - maxEntries, 0);
        List<ProxyHttpRequestResponse> entriesToImport =
                proxyHistory.subList(startIndex, proxyHistory.size());

        EntryImportWorker importWorker =
                new EntryImportWorker.Builder(this)
                        .setOriginatingTool(ToolType.PROXY)
                        .setProxyEntries(entriesToImport)
                        .setSendToAutoExporters(sendToAutoExporters)
                        .build();

        importWorker.execute();
    }

    private boolean isValidTool(ToolType toolType) {
        if (preferences.getSetting(PREF_LOG_GLOBAL)) return true;

        switch (toolType) {
            case PROXY -> {
                return preferences.getSetting(PREF_LOG_PROXY);
            }
            case INTRUDER -> {
                return preferences.getSetting(PREF_LOG_INTRUDER);
            }
            case REPEATER -> {
                return preferences.getSetting(PREF_LOG_REPEATER);
            }
            case EXTENSIONS -> {
                return preferences.getSetting(PREF_LOG_EXTENSIONS);
            }
            case SCANNER -> {
                return preferences.getSetting(PREF_LOG_SCANNER);
            }
            case SEQUENCER -> {
                return preferences.getSetting(PREF_LOG_SEQUENCER);
            }
            case SUITE -> {
                return preferences.getSetting(PREF_LOG_SUITE);
            }
            case RECORDED_LOGIN_REPLAYER -> {
                return preferences.getSetting(PREF_LOG_RECORDED_LOGINS);
            }
            default -> {
                return false;
            }
        }
    }

    public void shutdown() {
        this.cleanupExecutor.shutdownNow();
        this.entryProcessExecutor.shutdownNow();
        this.entryImportExecutor.shutdownNow();
    }

    /** From a worker: hands a new entry to the exporters that run by themselves, and the table. */
    void addNewEntry(LogEntry logEntry, boolean sendToAutoExporters) {
        if (sendToAutoExporters) {
            exportController.exportNewEntry(logEntry);
        }
        tableFeed.added(logEntry);
    }

    void updateExistingEntry(LogEntry logEntry) {
        exportController.exportUpdatedEntry(logEntry);
        tableFeed.updated(logEntry);
    }

    void removeExistingEntry(LogEntry logEntry) {
        tableFeed.removed(logEntry);
    }

    PausableThreadPoolExecutor getEntryImportExecutor() {
        return entryImportExecutor;
    }

    public PausableThreadPoolExecutor getEntryProcessExecutor() {
        return entryProcessExecutor;
    }

    /** How many requests are waiting for a worker or for their response. */
    int requestsInFlight() {
        return entryProcessingFutures.size();
    }

    /**
     * Gives up on requests that were read longer ago than the response timeout and still have no
     * response: they are marked as timed out, and a response arriving later is ignored.
     */
    void forgetAbandonedRequests() {
        long now = System.currentTimeMillis();
        long responseTimeout =
                TimeUnit.SECONDS.toMillis(
                        ((Integer) preferences.getSetting(PREF_RESPONSE_TIMEOUT)));
        for (Map.Entry<Integer, Future<LogEntry>> waiting : entryProcessingFutures.entrySet()) {
            Future<LogEntry> processing = waiting.getValue();
            if (!processing.isDone()) {
                continue;
            }
            LogEntry logEntry;
            try {
                logEntry = processing.get();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } catch (ExecutionException e) {
                logEntry = null;
            }
            if (logEntry == null) {
                entryProcessingFutures.remove(waiting.getKey(), processing);
            } else if (now - logEntry.getRequestDateTime().getTime() > responseTimeout) {
                entryProcessingFutures.remove(waiting.getKey(), processing);
                String comment = logEntry.getComment();
                logEntry.setComment(comment == null ? "Timed Out" : comment + " Timed Out");
                tableFeed.updated(logEntry);
            }
        }
    }
}
