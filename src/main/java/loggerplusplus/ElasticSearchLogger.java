package loggerplusplus;

import org.apache.http.HttpHost;
import org.elasticsearch.action.ActionListener;
import org.elasticsearch.action.bulk.BulkItemResponse;
import org.elasticsearch.action.bulk.BulkRequest;
import org.elasticsearch.action.bulk.BulkResponse;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.RestClient;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.client.indices.CreateIndexRequest;
import org.elasticsearch.client.indices.CreateIndexResponse;
import org.elasticsearch.client.indices.GetIndexRequest;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentFactory;


import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Objects;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

public class ElasticSearchLogger implements LogEntryListener {

    RestHighLevelClient connector;
    ArrayList<LogEntry> pendingEntries;
    private InetAddress address;
    private short port;
    private String clusterName;
    private boolean isEnabled;
    private String indexName;
    private LoggerPreferences prefs;

    private final ScheduledExecutorService executorService;
    private ScheduledFuture indexTask;

    private void StartClient(){

        /*
                The TransportClient is deprecated in favour of the Java High Level REST Client
                and will be removed in Elasticsearch 8.0. The migration guide describes all
                the steps needed to migrate.
             */

        //  https://www.elastic.co/guide/en/elasticsearch/client/java-api/7.3/transport-client.html

        try {
            this.connector = new RestHighLevelClient(
                    RestClient.builder(
                            new HttpHost(
                                    Objects.requireNonNull("vmhost.fake"),
                                    Objects.requireNonNull(9200),
                                    "http")
                    )
            );
        } catch (Exception e) {
            e.printStackTrace();
        }
        return;
    }

    private void StopClient(){
        try {
            this.connector.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return;
    }


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

            createIndices();

            pendingEntries = new ArrayList<>();

            indexTask = executorService.scheduleAtFixedRate(new Runnable() {
                @Override
                public void run() {
                    indexPendingEntries();
                }
            }, prefs.getEsDelay(), prefs.getEsDelay(), TimeUnit.SECONDS);

        }else{
            if(this.indexTask != null){
                indexTask.cancel(true);
            }
            this.pendingEntries = null;
        }
        this.isEnabled = isEnabled;
    }

    private void createIndices(){

        StartClient();

        GetIndexRequest request = new GetIndexRequest(this.indexName);
        boolean exists = false;

        try {
            exists = this.connector.indices().exists(request, RequestOptions.DEFAULT);
        } catch (IOException e) {
            e.printStackTrace();
        }

        if(!exists) {
            try {
                CreateIndexRequest createRequest = new CreateIndexRequest(this.indexName);
                CreateIndexResponse createIndexResponse = this.connector.indices().create(createRequest, RequestOptions.DEFAULT);

                if(createIndexResponse.isAcknowledged()){
                    System.out.println("Index: " + this.indexName + " was created.");
                } else {
                    System.out.println("ERROR: Index " + this.indexName + " could not be created!");
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        StopClient();
    }

    public IndexRequest buildIndexRequest(LogEntry logEntry){
        try{
            try {

                if(logEntry.responseMimeType == "HTML" || prefs.elasticAllMimetypes()) {
                    XContentBuilder builder = XContentFactory.jsonBuilder();
                    builder.startObject();
                    {
                        builder.field("protocol", logEntry.protocol);
                        builder.field("method", logEntry.method);
                        builder.field("host", logEntry.host);
                        builder.field("path", logEntry.relativeURL);
                        builder.field("requesttime", logEntry.requestTime.equals("NA") ? null : logEntry.requestTime);
                        builder.field("responsetime", logEntry.responseTime.equals("NA") ? null : logEntry.responseTime);
                        builder.field("status", logEntry.status);
                        builder.field("title", logEntry.title);
                        builder.field("newcookies", logEntry.newCookies);
                        builder.field("sentcookies", logEntry.sentCookies);
                        builder.field("referrer", logEntry.referrerURL);
                        builder.field("requestcontenttype", logEntry.requestContentType);
                        if (prefs.elasticSendRequest()){
                            builder.field("requestbody", new String(logEntry.requestResponse.getRequest()));
                        }
                        if (prefs.elasticSendResponse()){
                            builder.field("responsebody", new String(logEntry.requestResponse.getResponse()));
                        }
                    }
                    builder.endObject();
                    IndexRequest indexRequest = new IndexRequest(this.indexName)
                            .source(builder);

                    return indexRequest;
                }

            } catch (Exception e) {
                e.printStackTrace();
            }

            return null;

        } catch (Exception e) {
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
        if(!this.isEnabled || this.pendingEntries.size() == 0){
            return;
        }

        StartClient();

        ActionListener<BulkResponse> listener = new ActionListener<BulkResponse>() {
            @Override
            public void onResponse(BulkResponse bulkResponse) {
                System.out.println("Bulk data was sent.");
                if (bulkResponse.hasFailures()) {
                    for (BulkItemResponse bulkItemResponse : bulkResponse.getItems()) {
                        System.out.println("Error in bulk response: " + bulkItemResponse.getFailureMessage());
                    }
                }
                StopClient();
            }

            @Override
            public void onFailure(Exception e) {
                e.printStackTrace();
                StopClient();
            }
        };

        BulkRequest bulkRequest = new BulkRequest();

        System.out.println("Bulk Request Created");

        ArrayList<LogEntry> entriesInBulk;
        synchronized (pendingEntries){
            entriesInBulk = (ArrayList<LogEntry>) pendingEntries.clone();
            pendingEntries.clear();
        }

        for (LogEntry logEntry : entriesInBulk) {
            IndexRequest request = buildIndexRequest(logEntry);
            if(request != null) {
                bulkRequest.add(request);
            } else {
                // ignore, buildIndexRequest() function has returned an error, stack trace in console...
            }
        }

        if (bulkRequest.numberOfActions() > 0){
            this.connector.bulkAsync(bulkRequest, RequestOptions.DEFAULT, listener);
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
