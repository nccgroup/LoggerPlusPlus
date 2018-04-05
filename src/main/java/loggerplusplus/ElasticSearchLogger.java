package loggerplusplus;

import org.elasticsearch.action.admin.indices.create.CreateIndexRequestBuilder;
import org.elasticsearch.action.bulk.BulkItemResponse;
import org.elasticsearch.action.bulk.BulkRequestBuilder;
import org.elasticsearch.action.bulk.BulkResponse;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.index.IndexRequestBuilder;
import org.elasticsearch.client.Client;
import org.elasticsearch.client.IndicesAdminClient;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.transport.client.PreBuiltTransportClient;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import static org.elasticsearch.common.xcontent.XContentFactory.jsonBuilder;

public class ElasticSearchLogger implements LogEntryListener{
    IndicesAdminClient adminClient;
    Client client;
    ArrayList<LogEntry> pendingEntries;
    private InetAddress address;
    private short port;
    private String clusterName;
    private boolean isEnabled;
    private String indexName;
    private LoggerPreferences prefs;

    private final ScheduledExecutorService executorService;
    private ScheduledFuture indexTask;


    public ElasticSearchLogger(LogManager logManager, LoggerPreferences prefs){
        this.prefs = prefs;
        this.isEnabled = false;
        this.indexName = "logger";

        logManager.addLogListener(this);
        executorService = Executors.newScheduledThreadPool(1);
    }

    public void setEnabled(boolean isEnabled) throws UnknownHostException {
        if(isEnabled){
            this.address = InetAddress.getByName(prefs.getEsAddress());
            this.port = prefs.getEsPort();
            this.clusterName = prefs.getEsClusterName();
            this.indexName = prefs.getEsIndex();
            Settings settings = Settings.builder().put("cluster.name", this.clusterName).build();
            client = new PreBuiltTransportClient(settings)
                .addTransportAddress(new TransportAddress(this.address, this.port));
            adminClient = client.admin().indices();
            createIndices();
            pendingEntries = new ArrayList<>();
            indexTask = executorService.scheduleAtFixedRate(this::indexPendingEntries,prefs.getEsDelay(), prefs.getEsDelay(), TimeUnit.SECONDS);
        }else{
            if(this.indexTask != null){
                indexTask.cancel(true);
            }
            this.pendingEntries = null;
            this.client = null;
            this.adminClient = null;
        }
        this.isEnabled = isEnabled;
    }

    private void createIndices(){
//            XContentBuilder builder = jsonBuilder().startObject()
//                    .startObject("requestresponse")
//                        .startObject("properties")
//                            .startObject("protocol")
//                            .field("type", "text")
//                            .field("store", "true")
//                            .endObject()
//                            .startObject("method")
//                            .field("type", "text")
//                            .field("store", "true")
//                            .endObject()
//                            .startObject("host")
//                            .field("type", "text")
//                            .field("store", "true")
//                            .endObject()
//                            .startObject("path")
//                            .field("type", "text")
//                            .field("store", "true")
//                            .endObject()
//                            .startObject("requesttime")
//                            .field("type", "date")
//                            .field("store", "true")
//                            .field("format", "yyyy/MM/dd HH:mm:ss")
//                            .endObject()
//                            .startObject("responsetime")
//                            .field("type", "date")
//                            .field("store", "true")
//                            .field("format", "yyyy/MM/dd HH:mm:ss")
//                            .endObject()
//                            .startObject("status")
//                            .field("type", "text")
//                            .field("store", "true")
//                            .endObject()
//                            .startObject("title")
//                            .field("type", "text")
//                            .field("store", "true")
//                            .endObject()
//                            .startObject("newcookies")
//                            .field("type", "text")
//                            .field("store", "true")
//                            .endObject()
//                            .startObject("sentcookies")
//                            .field("type", "text")
//                            .field("store", "true")
//                            .endObject()
//                            .startObject("referrer")
//                            .field("type", "text")
//                            .field("store", "true")
//                            .endObject()
//                            .startObject("requestcontenttype")
//                            .field("type", "text")
//                            .field("store", "true")
//                            .endObject()
//                        .endObject()
//                    .endObject().endObject();
        boolean exists = adminClient.prepareExists(this.indexName).get().isExists();
        if(!exists) {
            CreateIndexRequestBuilder response = adminClient.prepareCreate(this.indexName);
            response.get();
        }
//            .addMapping("requestresponse", builder).get();
    }

    public IndexRequest buildIndexRequest(LogEntry logEntry){
        try{
            IndexRequestBuilder requestBuilder = client.prepareIndex(this.indexName, "requestresponse")
                    .setSource(
                            jsonBuilder().startObject()
                                .field("protocol", logEntry.protocol)
                                .field("method", logEntry.method)
                                .field("host", logEntry.host)
                                .field("path", logEntry.relativeURL)
                                .field("requesttime", logEntry.requestTime.equals("NA") ? null : logEntry.requestTime)
                                .field("responsetime", logEntry.responseTime.equals("NA") ? null : logEntry.responseTime)
                                .field("status", logEntry.status)
                                .field("title", logEntry.title)
                                .field("newcookies", logEntry.newCookies)
                                .field("sentcookies", logEntry.sentCookies)
                                .field("referrer", logEntry.referrerURL)
                                .field("requestcontenttype", logEntry.requestContentType)
//                                .field("requestbody", new String(logEntry.requestResponse.getRequest()))
//                                .field("responsebody", new String(logEntry.requestResponse.getResponse()))
                            .endObject()
                    );
            return requestBuilder.request();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    private void addToPending(LogEntry logEntry){
        if(!this.isEnabled) return;
        synchronized (pendingEntries) {
            pendingEntries.add(logEntry);
        }
    }

    private void indexPendingEntries(){
        if(!this.isEnabled || this.pendingEntries.size() == 0) return;

        BulkRequestBuilder bulkBuilder = client.prepareBulk();
        ArrayList<LogEntry> entriesInBulk;
        synchronized (pendingEntries){
            entriesInBulk = (ArrayList<LogEntry>) pendingEntries.clone();
            pendingEntries.clear();
        }

        for (LogEntry logEntry : entriesInBulk) {
            IndexRequest request = buildIndexRequest(logEntry);
            if(request != null) {
                bulkBuilder.add(request);
            }else{
                //Could not build index request. Ignore it?
            }
        }

        BulkResponse resp = bulkBuilder.get();
        if(resp.hasFailures()){
            for (BulkItemResponse bulkItemResponse : resp.getItems()) {
                System.err.println(bulkItemResponse.getFailureMessage());
            }
        }
    }

    @Override
    public void onRequestAdded(LogEntry logEntry, boolean hasResponse) {
        if(!this.isEnabled) return;
        if(hasResponse){
            addToPending(logEntry);
        }
    }

    @Override
    public void onResponseUpdated(LogEntry existingEntry) {
        if(!this.isEnabled) return;
        addToPending(existingEntry);
    }

    @Override
    public void onRequestRemoved(int index, LogEntry logEntry) {

    }
}
