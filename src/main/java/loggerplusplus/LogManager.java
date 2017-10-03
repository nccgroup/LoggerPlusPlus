package loggerplusplus;

import burp.*;
import loggerplusplus.filter.ColorFilter;

import java.net.URL;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Created by corey on 07/09/17.
 */
public class LogManager implements IHttpListener, IProxyListener {
    private final LoggerPreferences prefs;
    private ArrayList<LogEntry> logEntries;
    private HashMap<Integer, LogEntry.PendingRequestEntry> pendingRequests;
    private ArrayList<LogEntryListener> logEntryListeners;
    private ExecutorService executorService;
    //Stats
    private int totalRequests = 0;
    private short lateResponses = 0;

    LogManager(LoggerPreferences prefs){
        this.prefs = prefs;
        logEntries = new ArrayList<>();
        logEntryListeners = new ArrayList<>();
        pendingRequests = new HashMap<>();
        LoggerPlusPlus.getCallbacks().getProxyHistory();

        executorService = Executors.newSingleThreadExecutor();

        //Create incomplete request cleanup thread so map doesn't get too big.
        ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();
        executor.scheduleAtFixedRate(new Runnable() {
            @Override
            public void run() {
                SimpleDateFormat dateFormat = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
                Set<Integer> keys = new HashSet<>(pendingRequests.keySet());
                synchronized (pendingRequests){
                    for (Integer reference : keys) {
                        try {
                            Date date = dateFormat.parse(pendingRequests.get(reference).requestTime);
                            if(new Date().getTime() - date.getTime() > LoggerPlusPlus.getInstance().getLoggerPreferences().getResponseTimeout()){
                                pendingRequests.remove(reference);
                            }
                        } catch (ParseException e) {
                            pendingRequests.remove(reference);
                        }
                    }
                }
            }
        },30000, 30000, TimeUnit.MILLISECONDS);
    }

    @Override
    public void processHttpMessage(final int toolFlag, final boolean messageIsRequest, final IHttpRequestResponse requestResponse) {
        //REQUEST AND RESPONSE SINGLE MESSAGE
        executorService.submit(new Runnable() {
            @Override
            public void run() {
                if(toolFlag != IBurpExtenderCallbacks.TOOL_PROXY){
                    if(requestResponse == null || !prefs.isEnabled()) return;
                    LogEntry logEntry = new LogEntry();
                    IRequestInfo analyzedReq = LoggerPlusPlus.getCallbacks().getHelpers().analyzeRequest(requestResponse);
                    URL uUrl = analyzedReq.getUrl();
                    if (isValidTool(toolFlag) && (!prefs.isRestrictedToScope() || LoggerPlusPlus.getCallbacks().isInScope(uUrl))){
                        //We will not need to change messageInfo so save to temp file
                        IHttpRequestResponse savedReqResp = LoggerPlusPlus.getCallbacks().saveBuffersToTempFiles(requestResponse);
                        logEntry.processRequest(toolFlag, savedReqResp, uUrl, analyzedReq, null);
                        logEntry.processResponse(savedReqResp);
                        //Check entry against colorfilters.
                        for (ColorFilter colorFilter : prefs.getColorFilters().values()) {
                            logEntry.testColorFilter(colorFilter, false);
                        }
                        addNewRequest(logEntry);
                    }
                }
            }
        });
    }

    @Override
    public void processProxyMessage(final boolean messageIsRequest, final IInterceptedProxyMessage proxyMessage) {
        //REQUEST AND RESPONSE SEPARATE
        executorService.submit(new Runnable() {
            @Override
            public void run() {
                if(proxyMessage == null || !prefs.isEnabled()) return;
                LogEntry.PendingRequestEntry logEntry;
                if(messageIsRequest){
                    logEntry = new LogEntry.PendingRequestEntry();
                }else{
                    synchronized (pendingRequests) {
                        logEntry = pendingRequests.remove(proxyMessage.getMessageReference());
                    }
                }
                IHttpRequestResponse requestResponse = proxyMessage.getMessageInfo();
                IRequestInfo analyzedReq = LoggerPlusPlus.getCallbacks().getHelpers().analyzeRequest(requestResponse);
                URL uUrl = analyzedReq.getUrl();
                int toolFlag = LoggerPlusPlus.getCallbacks().TOOL_PROXY;
                if (isValidTool(toolFlag) && (!prefs.isRestrictedToScope() || LoggerPlusPlus.getCallbacks().isInScope(uUrl))){
                    if(messageIsRequest){
                        //New Proxy Request
                        //We need to change messageInfo when we get a response so do not save to buffers
                        logEntry.processRequest(toolFlag, requestResponse, uUrl, analyzedReq, proxyMessage);
                        for (ColorFilter colorFilter : prefs.getColorFilters().values()) {
                            logEntry.testColorFilter(colorFilter, false);
                        }
                        synchronized (pendingRequests) {
                            pendingRequests.put(proxyMessage.getMessageReference(), logEntry);
                        }
                        addNewRequest(logEntry);
                    }else{
                        //Existing Proxy Request, update existing
                        if (logEntry != null) {
                            updatePendingRequest(logEntry, requestResponse);
                        } else {
                            lateResponses++;
                            if(totalRequests > 100 && ((float)lateResponses)/totalRequests > 0.1){
                                MoreHelp.showWarningMessage(lateResponses + " responses have been delivered after the Logger++ timeout. Consider increasing this value.");
                            }
                        }
                    }
                }
            }
        });
    }

    private void addNewRequest(LogEntry logEntry){
        //After handling request / response logEntries generation.
        //Add to grepTable / modify existing entry.
        synchronized (logEntries) {
            while(logEntries.size() >= getMaximumEntries()){
                final LogEntry removed = logEntries.remove(0);
                for (LogEntryListener listener : logEntryListeners) {
                    listener.onRequestRemoved(0, removed);
                }
            }
            logEntries.add(logEntry);
            for (LogEntryListener listener : logEntryListeners) {
                listener.onRequestAdded(logEntry);
            }
            totalRequests++;
            if(logEntry instanceof LogEntry.PendingRequestEntry){
                ((LogEntry.PendingRequestEntry) logEntry).setLogRow(totalRequests-1);
            }
        }
    }

    private void updatePendingRequest(LogEntry.PendingRequestEntry pendingRequest, IHttpRequestResponse messageInfo) {
        //Fill in gaps of request with response
        pendingRequest.processResponse(messageInfo);

        for (ColorFilter colorFilter : prefs.getColorFilters().values()) {
            pendingRequest.testColorFilter(colorFilter, true);
        }
        for (LogEntryListener logEntryListener : logEntryListeners) {
            logEntryListener.onResponseUpdated(pendingRequest);
        }
    }

    public ArrayList<LogEntry> getLogEntries() {
        return logEntries;
    }

    private boolean isValidTool(int toolFlag){
        return (prefs.isEnabled4All() ||
                (prefs.isEnabled4Proxy() && toolFlag== IBurpExtenderCallbacks.TOOL_PROXY) ||
                (prefs.isEnabled4Intruder() && toolFlag== IBurpExtenderCallbacks.TOOL_INTRUDER) ||
                (prefs.isEnabled4Repeater() && toolFlag== IBurpExtenderCallbacks.TOOL_REPEATER) ||
                (prefs.isEnabled4Scanner() && toolFlag== IBurpExtenderCallbacks.TOOL_SCANNER) ||
                (prefs.isEnabled4Sequencer() && toolFlag== IBurpExtenderCallbacks.TOOL_SEQUENCER) ||
                (prefs.isEnabled4Spider() && toolFlag== IBurpExtenderCallbacks.TOOL_SPIDER) ||
                (prefs.isEnabled4Extender() && toolFlag== IBurpExtenderCallbacks.TOOL_EXTENDER) ||
                (prefs.isEnabled4TargetTab() && toolFlag== IBurpExtenderCallbacks.TOOL_TARGET));
    }

    public void reset() {
        this.logEntries.clear();
        this.pendingRequests.clear();
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
        return prefs.getMaximumEntries();
    }
}
