package loggerplusplus;

import burp.*;
import loggerplusplus.filter.ColorFilter;

import java.net.URL;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;
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
    //Stats
    private int totalRequests = 0;
    private short lateResponses = 0;

    LogManager(LoggerPreferences prefs){
        this.prefs = prefs;
        logEntries = new ArrayList<>();
        logEntryListeners = new ArrayList<>();
        pendingRequests = new HashMap<>();
        BurpExtender.getCallbacks().getProxyHistory();

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
                            if(new Date().getTime() - date.getTime() > BurpExtender.getLoggerInstance().getLoggerPreferences().getResponseTimeout()){
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
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse requestResponse) {
//        if(toolFlag != IBurpExtenderCallbacks.TOOL_PROXY) logIt(toolFlag, messageIsRequest, requestResponse, null);
        if(toolFlag != IBurpExtenderCallbacks.TOOL_PROXY){
            if(requestResponse == null || !prefs.isEnabled()) return;
            IRequestInfo analyzedReq = BurpExtender.getCallbacks().getHelpers().analyzeRequest(requestResponse);
            URL uUrl = analyzedReq.getUrl();
            if (isValidTool(toolFlag) && (!prefs.isRestrictedToScope() || BurpExtender.getCallbacks().isInScope(uUrl))){
                //We will not need to change messageInfo so save to temp file
                LogEntry logEntry = new LogEntry(toolFlag, false, BurpExtender.getCallbacks().saveBuffersToTempFiles(requestResponse), uUrl, analyzedReq, null);
                //Check entry against colorfilters.
                for (ColorFilter colorFilter : prefs.getColorFilters().values()) {
                    logEntry.testColorFilter(colorFilter, false);
                }
                addNewRequest(logEntry);
            }
        }
    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage proxyMessage) {
//        logIt(IBurpExtenderCallbacks.TOOL_PROXY, messageIsRequest, null, proxyMessage);
        if(proxyMessage == null || !prefs.isEnabled()) return;
        IHttpRequestResponse requestResponse = proxyMessage.getMessageInfo();
        IRequestInfo analyzedReq = BurpExtender.getCallbacks().getHelpers().analyzeRequest(requestResponse);
        URL uUrl = analyzedReq.getUrl();
        int toolFlag = BurpExtender.getCallbacks().TOOL_PROXY;
        if (isValidTool(toolFlag) && (!prefs.isRestrictedToScope() || BurpExtender.getCallbacks().isInScope(uUrl))){
            if(messageIsRequest){
                //New Proxy Request
                //We need to change messageInfo when we get a response so do not save to buffers
                LogEntry logEntry = new LogEntry.PendingRequestEntry(toolFlag, messageIsRequest, requestResponse, uUrl, analyzedReq, proxyMessage);
                for (ColorFilter colorFilter : prefs.getColorFilters().values()) {
                    logEntry.testColorFilter(colorFilter, false);
                }
                synchronized (pendingRequests) {
                    pendingRequests.put(proxyMessage.getMessageReference(), (LogEntry.PendingRequestEntry) logEntry);
                }
                addNewRequest(logEntry);
            }else{
                //Existing Proxy Request, update existing
                LogEntry.PendingRequestEntry pendingRequest;
                synchronized (pendingRequests) {
                    pendingRequest = pendingRequests.remove(proxyMessage.getMessageReference());
                }
                if (pendingRequest != null) {
                    updatePendingRequest(pendingRequest, requestResponse);
                } else {
                    lateResponses++;
                    if(totalRequests > 100 && ((float)lateResponses)/totalRequests > 0.1){
                        MoreHelp.showWarningMessage(lateResponses + " responses have been delivered after the Logger++ timeout. Consider increasing this value.");
                    }
                }
            }
        }
    }

    private void logProxyRequest(IInterceptedProxyMessage proxyMessage, boolean messageIsRequest){

    }

    private void logOtherRequest(int toolFlag, IHttpRequestResponse requestResponse){

    }

    private void addNewRequest(LogEntry logEntry){
        //After handling request / response logEntries generation.
        //Add to grepTable / modify existing entry.
        synchronized (logEntries) {
            while(logEntries.size() >= getMaximumEntries()){
                final LogEntry removed = logEntries.remove(0);
                for (LogEntryListener listener : logEntryListeners) {
                    listener.onRequestRemoved(removed);
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
