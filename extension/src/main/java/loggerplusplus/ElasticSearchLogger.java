package loggerplusplus;

import org.apache.http.HttpHost;
import org.elasticsearch.action.admin.indices.create.CreateIndexRequest;
import org.elasticsearch.action.admin.indices.create.CreateIndexResponse;
import org.elasticsearch.action.admin.indices.get.GetIndexRequest;
import org.elasticsearch.action.bulk.BulkItemResponse;
import org.elasticsearch.action.bulk.BulkRequest;
import org.elasticsearch.action.bulk.BulkResponse;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.index.IndexRequestBuilder;
import org.elasticsearch.client.*;
import org.elasticsearch.common.settings.Settings;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

import static org.elasticsearch.common.xcontent.XContentFactory.jsonBuilder;

public class ElasticSearchLogger implements LogEntryListener{
    IndicesAdminClient adminClient;
    Client client;
    RestHighLevelClient httpClient;
    ArrayList<LogEntry> pendingEntries;
    private InetAddress address;
    private int port;
    private String clusterName;
    private boolean isEnabled;
    private String indexName;

    private final ScheduledExecutorService executorService;
    private ScheduledFuture indexTask;


    public ElasticSearchLogger(LogManager logManager){
        this.isEnabled = false;
        this.indexName = "logger";

        logManager.addLogListener(this);
        executorService = Executors.newScheduledThreadPool(1);
    }

    public void setEnabled(boolean isEnabled) throws UnknownHostException {
        if(isEnabled){
            this.address = InetAddress.getByName((String) LoggerPlusPlus.preferences.getSetting(Globals.PREF_ELASTIC_ADDRESS));
            this.port = (int) LoggerPlusPlus.preferences.getSetting(Globals.PREF_ELASTIC_PORT);
            this.clusterName = (String) LoggerPlusPlus.preferences.getSetting(Globals.PREF_ELASTIC_CLUSTER_NAME);
            this.indexName = (String) LoggerPlusPlus.preferences.getSetting(Globals.PREF_ELASTIC_INDEX);
            Settings settings = Settings.builder().put("cluster.name", this.clusterName).build();

            httpClient = new RestHighLevelClient(RestClient.builder(
                    new HttpHost(this.address, this.port, "http")));

            createIndices();
            pendingEntries = new ArrayList<>();
            int delay = (int) LoggerPlusPlus.preferences.getSetting(Globals.PREF_ELASTIC_DELAY);
            indexTask = executorService.scheduleAtFixedRate(new Runnable() {
                @Override
                public void run() {
                    indexPendingEntries();
                }
            }, delay, delay, TimeUnit.SECONDS);
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
        GetIndexRequest request = new GetIndexRequest();
        request.indices(this.indexName);

        boolean exists = false;
        try {
            exists = httpClient.indices().exists(request, RequestOptions.DEFAULT);
        } catch (IOException e) {
            e.printStackTrace();
        }

        if(!exists) {
            CreateIndexRequest _request = new CreateIndexRequest(this.indexName);

            try {
                CreateIndexResponse createIndexResponse = httpClient.indices().create(_request, RequestOptions.DEFAULT);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
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

        BulkRequest httpBulkBuilder = new BulkRequest();

        ArrayList<LogEntry> entriesInBulk;
        synchronized (pendingEntries){
            entriesInBulk = (ArrayList<LogEntry>) pendingEntries.clone();
            pendingEntries.clear();
        }

        for (LogEntry logEntry : entriesInBulk) {
            IndexRequest request = buildIndexRequest(logEntry);
            if(request != null) {
                httpBulkBuilder.add(request);
            }else{
                //Could not build index request. Ignore it?
            }
        }

        try {
            BulkResponse bulkResponse = httpClient.bulk(httpBulkBuilder, RequestOptions.DEFAULT);
            if(bulkResponse.hasFailures()){
                for (BulkItemResponse bulkItemResponse : bulkResponse.getItems()) {
                    System.err.println(bulkItemResponse.getFailureMessage());
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

//        if(resp.hasFailures()){
//            for (BulkItemResponse bulkItemResponse : resp.getItems()) {
//                System.err.println(bulkItemResponse.getFailureMessage());
//            }
//        }
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
