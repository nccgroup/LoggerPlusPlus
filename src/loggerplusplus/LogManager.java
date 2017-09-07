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
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if(toolFlag != IBurpExtenderCallbacks.TOOL_PROXY) logIt(toolFlag, messageIsRequest, messageInfo, null);
    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message) {
        logIt(IBurpExtenderCallbacks.TOOL_PROXY, messageIsRequest, null, message);
    }

    private void logIt(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo,IInterceptedProxyMessage message){
        // Is it enabled?
        if(prefs.isEnabled()){
            // When it comes from the proxy listener "messageInfo" is null and "message" is available.
            if(messageInfo==null && message!=null){
                messageInfo = message.getMessageInfo();
            }

            IRequestInfo analyzedReq = BurpExtender.getCallbacks().getHelpers().analyzeRequest(messageInfo);
            URL uUrl = analyzedReq.getUrl();

            // Check for the scope if it is restricted to scope
            if (isValidTool(toolFlag) && (!prefs.isRestrictedToScope() || BurpExtender.getCallbacks().isInScope(uUrl))){
                LogEntry logEntry = null;
                if (messageIsRequest){
                    // Burp does not provide any way to trace a request to its response - only in proxy there is a unique reference
                    if(toolFlag== IBurpExtenderCallbacks.TOOL_PROXY) {
                        //We need to change messageInfo when we get a response so do not save to buffers
                        logEntry = new LogEntry.PendingRequestEntry(toolFlag, messageIsRequest, messageInfo, uUrl, analyzedReq, message);
                        for (ColorFilter colorFilter : prefs.getColorFilters().values()) {
                            logEntry.testColorFilter(colorFilter, false);
                        }
                        synchronized (pendingRequests) {
                            pendingRequests.put(message.getMessageReference(), (LogEntry.PendingRequestEntry) logEntry);
                        }
                    }
                }else{
                    if(toolFlag== IBurpExtenderCallbacks.TOOL_PROXY){
                        //Get from pending list
                        LogEntry.PendingRequestEntry pendingRequest;
                        synchronized (pendingRequests) {
                            pendingRequest = pendingRequests.remove(message.getMessageReference());
                        }
                        if (pendingRequest != null) {
                            updatePendingRequest(pendingRequest, messageInfo);
                        } else {
                            lateResponses++;
                            if(totalRequests > 100 && ((float)lateResponses)/totalRequests > 0.1){
                                MoreHelp.showWarningMessage(lateResponses + " responses have been delivered after the Logger++ timeout. Consider increasing this value.");
                            }
                        }
                        return;
                    }else {
                        //We will not need to change messageInfo so save to temp file
                        logEntry = new LogEntry(toolFlag, messageIsRequest, BurpExtender.getCallbacks().saveBuffersToTempFiles(messageInfo), uUrl, analyzedReq, message);
                        //Check entry against colorfilters.
                        for (ColorFilter colorFilter : prefs.getColorFilters().values()) {
                            logEntry.testColorFilter(colorFilter, false);
                        }
                    }
                }

                if(logEntry != null) {
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
