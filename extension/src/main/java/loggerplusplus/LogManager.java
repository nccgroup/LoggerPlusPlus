package loggerplusplus;

import burp.*;
import loggerplusplus.filter.ColorFilter;

import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Created by corey on 07/09/17.
 */
public class LogManager implements IHttpListener, IProxyListener {
    private final LoggerPreferences prefs;
    private ArrayList<LogEntry> logEntries;
    private HashMap<Integer, LogEntry.PendingRequestEntry> pendingProxyRequests;
    private HashMap<UUID, LogEntry.PendingRequestEntry> pendingToolRequests;
    private ArrayList<LogEntryListener> logEntryListeners;
    private ExecutorService executorService;
    static final SimpleDateFormat sdf = new SimpleDateFormat("yyyy/MM/dd HH:mm:ss");
    private final String randIdentifier;
    private final Pattern uuidPattern;
    //Stats
    private int totalRequests = 0;
    private short lateResponses = 0;

    LogManager(LoggerPreferences prefs){
        this.prefs = prefs;
        logEntries = new ArrayList<>();
        logEntryListeners = new ArrayList<>();
        pendingProxyRequests = new HashMap<>();
        pendingToolRequests = new HashMap<>();
        LoggerPlusPlus.getCallbacks().getProxyHistory();

        randIdentifier = String.format("%02d", (int)Math.floor((Math.random()*100)));
        uuidPattern = Pattern.compile("\\$LPP:(\\d\\d):(.*?)\\$");

        executorService = Executors.newCachedThreadPool();

        //Create incomplete request cleanup thread so map doesn't get too big.
        ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor();
        executor.scheduleAtFixedRate(new Runnable() {
            @Override
            public void run() {
                long timeNow = new Date().getTime();
                Set<Integer> keys = new HashSet<>(pendingProxyRequests.keySet());
                synchronized (pendingProxyRequests){
                    for (Integer reference : keys) {
                        long entryTime = pendingProxyRequests.get(reference).requestDateTime.getTime();
                        if(timeNow - entryTime > LoggerPlusPlus.getInstance().getLoggerPreferences().getResponseTimeout()){
                            pendingProxyRequests.remove(reference);
                        }
                    }
                }
                Set<UUID> toolKeys = new HashSet<>(pendingToolRequests.keySet());
                synchronized (pendingToolRequests){
                    for (UUID reference : toolKeys) {
                        long entryTime = pendingToolRequests.get(reference).requestDateTime.getTime();
                        if(timeNow - entryTime > LoggerPlusPlus.getInstance().getLoggerPreferences().getResponseTimeout()){
                            pendingToolRequests.remove(reference);
                        }
                    }
                }
            }
        },30000, 30000, TimeUnit.MILLISECONDS);
    }



    @Override
    public void processHttpMessage(final int toolFlag, final boolean messageIsRequest, final IHttpRequestResponse requestResponse) {
        if(toolFlag == IBurpExtenderCallbacks.TOOL_PROXY) return;
        if(requestResponse == null || !prefs.isEnabled()) return;
        Date nowDate = new Date();

        if(!prefs.getOtherToolLiveLogging()){
            //Submit normally, we're not tracking requests and responses separately.
            if(!messageIsRequest) {
                processHttpMessage(new LogEntry(), toolFlag, false, requestResponse);
            }
            return;
        }

        final LogEntry logEntry;
        if(messageIsRequest){
            UUID uuid = UUID.randomUUID();
            logEntry = new LogEntry.PendingRequestEntry(uuid);
            requestResponse.setComment(requestResponse.getComment() + ";$LPP:" + randIdentifier + ":" + uuid + "$");
            synchronized (pendingToolRequests){
                pendingToolRequests.put(uuid, (LogEntry.PendingRequestEntry) logEntry);
            }
            processHttpMessage(logEntry, toolFlag, true, requestResponse);
        }else{
            //Pull the uuid we stored in the comment
            Matcher matcher = uuidPattern.matcher(requestResponse.getComment());
            if(matcher.find() && matcher.group(1).equals(randIdentifier)){
                UUID uuid = UUID.fromString(matcher.group(2));
                synchronized (pendingToolRequests){
                    logEntry = pendingToolRequests.remove(uuid);
                }
                if(logEntry != null) {
                    logEntry.setResponseDateTime(nowDate);
                    processHttpMessage(logEntry, toolFlag, false, requestResponse);
                }
            }else{
                //No longer in the map. Perhaps got cleaned out? Drop the response...
            }
        }
    }

    //Wrapper to allow a custom LogEntry to be passed as a parameter
    //Custom LogEntry used when importing proxy history.
    //messageIsRequest is removed as not needed.
    public void processHttpMessage(final LogEntry logEntry, final int toolFlag, final boolean messageIsRequest, final IHttpRequestResponse requestResponse){
        executorService.submit(() -> {
            if(toolFlag != IBurpExtenderCallbacks.TOOL_PROXY || logEntry.isImported){
                IRequestInfo analyzedReq = LoggerPlusPlus.getCallbacks().getHelpers().analyzeRequest(requestResponse);
                URL uUrl = analyzedReq.getUrl();
                if (!isValidTool(toolFlag) || (prefs.isRestrictedToScope() && !LoggerPlusPlus.getCallbacks().isInScope(uUrl)))
                    return;
                if(!prefs.getOtherToolLiveLogging()) { //If we're not tracking req/resp separate
                    IHttpRequestResponsePersisted savedReqResp = LoggerPlusPlus.getCallbacks().saveBuffersToTempFiles(requestResponse);
                    logEntry.processRequest(toolFlag, savedReqResp, uUrl, analyzedReq, null);
                    if(requestResponse.getResponse() != null) logEntry.processResponse(savedReqResp);
                    addNewRequest(logEntry, true);
                }else{
                    if(messageIsRequest){
                        logEntry.processRequest(toolFlag, requestResponse, uUrl, analyzedReq, null);
                        addNewRequest(logEntry, false);
                    }else{
                        updatePendingRequest((LogEntry.PendingRequestEntry) logEntry, requestResponse);
                    }
                }
            }
        });
    }


    @Override
    public void processProxyMessage(final boolean messageIsRequest, final IInterceptedProxyMessage proxyMessage) {
        //REQUEST AND RESPONSE SEPARATE
        if(proxyMessage == null || !prefs.isEnabled()) return;
        Date nowDate = new Date();

        final LogEntry.PendingRequestEntry logEntry;
        if(messageIsRequest){
            logEntry = new LogEntry.PendingRequestEntry();
            synchronized (pendingProxyRequests) {
                pendingProxyRequests.put(proxyMessage.getMessageReference(), logEntry);
            }
        }else{
            synchronized (pendingProxyRequests) {
                logEntry = pendingProxyRequests.remove(proxyMessage.getMessageReference());
            }
            if(logEntry == null){
                lateResponses++;
                if(totalRequests > 100 && ((float)lateResponses)/totalRequests > 0.17){
                    MoreHelp.showWarningMessage(lateResponses + " responses have been delivered after the Logger++ timeout. Consider increasing this value.");
                    //Reset late responses to prevent message being displayed again so soon.
                    lateResponses = 0;
                }
                return;
            }
            logEntry.setResponseDateTime(nowDate);
        }

        executorService.submit(new Runnable() {
            @Override
            public void run() {
                IHttpRequestResponse requestResponse = proxyMessage.getMessageInfo();
                IRequestInfo analyzedReq = LoggerPlusPlus.getCallbacks().getHelpers().analyzeRequest(requestResponse);
                URL uUrl = analyzedReq.getUrl();
                int toolFlag = LoggerPlusPlus.getCallbacks().TOOL_PROXY;
                if (isValidTool(toolFlag) && (!prefs.isRestrictedToScope() || LoggerPlusPlus.getCallbacks().isInScope(uUrl))){
                    if(messageIsRequest){
                        //New Proxy Request
                        //We need to change messageInfo when we get a response so do not save to buffers
                        logEntry.processRequest(toolFlag, requestResponse, uUrl, analyzedReq, proxyMessage);
                        addNewRequest(logEntry, false); //Request added without response
                    }else{
                        //Existing Proxy Request, update existing
                        updatePendingRequest(logEntry, requestResponse);
                    }
                }
            }
        });
    }

    private void addNewRequest(LogEntry logEntry, boolean hasResponse){
        //After handling request / response logEntries generation.
        //Add to grepTable / modify existing entry.
        for (ColorFilter colorFilter : prefs.getColorFilters().values()) {
            logEntry.testColorFilter(colorFilter, false);
        }

        synchronized (logEntries) {
            while(logEntries.size() >= getMaximumEntries()){
                final LogEntry removed = logEntries.remove(0);
                for (LogEntryListener listener : logEntryListeners) {
                    listener.onRequestRemoved(0, removed);
                }
            }
            logEntries.add(logEntry);
            for (LogEntryListener listener : logEntryListeners) {
                listener.onRequestAdded(logEntry, hasResponse);
            }
            totalRequests++;
            if(logEntry instanceof LogEntry.PendingRequestEntry){
                ((LogEntry.PendingRequestEntry) logEntry).setLogRow(totalRequests-1);
            }
        }
    }

    private void updatePendingRequest(LogEntry.PendingRequestEntry pendingRequest, IHttpRequestResponse messageInfo) {
        //Fill in gaps of request with response
        if(messageInfo == null) {
            LoggerPlusPlus.getCallbacks().printError("Warning: Response received with null messageInfo.");
            return;
        }
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
        this.pendingProxyRequests.clear();
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

    public void importExisting(IHttpRequestResponse requestResponse) {
        int toolFlag = IBurpExtenderCallbacks.TOOL_PROXY;
        LogEntry logEntry = new LogEntry(true);
        processHttpMessage(logEntry, toolFlag, false, requestResponse);
    }
}
