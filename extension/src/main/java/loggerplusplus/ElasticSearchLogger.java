package loggerplusplus;

import org.apache.http.HttpHost;
import org.elasticsearch.action.admin.indices.create.CreateIndexRequest;
import org.elasticsearch.action.admin.indices.create.CreateIndexRequestBuilder;
import org.elasticsearch.action.admin.indices.create.CreateIndexResponse;
import org.elasticsearch.action.admin.indices.get.GetIndexRequest;
import org.elasticsearch.action.bulk.BulkItemResponse;
import org.elasticsearch.action.bulk.BulkRequest;
import org.elasticsearch.action.bulk.BulkRequestBuilder;
import org.elasticsearch.action.bulk.BulkResponse;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.index.IndexRequestBuilder;
import org.elasticsearch.client.*;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.TransportAddress;
import org.elasticsearch.transport.client.PreBuiltTransportClient;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import static org.elasticsearch.common.xcontent.XContentFactory.jsonBuilder;

public class ElasticSearchLogger implements LogEntryListener{
    IndicesAdminClient adminClient;
    Client client;
    RestHighLevelClient httpClient;
    ArrayList<LogEntry> pendingEntries;
    private InetAddress address;
    private short port;
    private String clusterName;
    private boolean isEnabled;
    private boolean isEsHttpProtocol;
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
            this.isEsHttpProtocol = prefs.getEsHttpProtocol();
            this.clusterName = prefs.getEsClusterName();
            this.indexName = prefs.getEsIndex();
            Settings settings = Settings.builder().put("cluster.name", this.clusterName).build();

            if (this.isEsHttpProtocol) {
                httpClient = new RestHighLevelClient(RestClient.builder(
                        new HttpHost(this.address, this.port, "http")));
            } else {
                client = new PreBuiltTransportClient(settings)
                        .addTransportAddress(new TransportAddress(this.address, this.port));
                adminClient = client.admin().indices();
            }

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
            this.client = null;
            this.adminClient = null;
        }
        this.isEnabled = isEnabled;
    }

    private void createIndices(){
        GetIndexRequest request = new GetIndexRequest();
        request.indices(this.indexName);

        if (this.isEsHttpProtocol) {
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

        } else {
            boolean exists = adminClient.prepareExists(this.indexName).get().isExists();
            if(!exists) {
                CreateIndexRequestBuilder response = adminClient.prepareCreate(this.indexName);
                response.get();
            }
        }
    }

    public IndexRequest buildIndexRequest(LogEntry logEntry){
        try{
            if (isEsHttpProtocol) {
                Map<String, Object> jsonMap = new HashMap<>();
                jsonMap.put("protocol", logEntry.protocol);
                jsonMap.put("method", logEntry.method);
                jsonMap.put("host", logEntry.method);
                jsonMap.put("path", logEntry.method);
                jsonMap.put("requesttime", logEntry.method);
                jsonMap.put("responsetime", logEntry.method);
                jsonMap.put("status", logEntry.method);
                jsonMap.put("title", logEntry.method);
                jsonMap.put("newcookies", logEntry.method);
                jsonMap.put("sentcookies", logEntry.method);
                jsonMap.put("referrer", logEntry.method);
                jsonMap.put("requestcontenttype", logEntry.method);

                IndexRequest indexRequest = new IndexRequest(this.indexName, "doc").source(jsonMap);

                return indexRequest;
            } else {
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
            }
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

        BulkRequest httpBulkBuilder = null;
        BulkRequestBuilder bulkBuilder = null;

        if (isEsHttpProtocol) {
            httpBulkBuilder = new BulkRequest();
        } else {
            bulkBuilder = client.prepareBulk();
        }

        ArrayList<LogEntry> entriesInBulk;
        synchronized (pendingEntries){
            entriesInBulk = (ArrayList<LogEntry>) pendingEntries.clone();
            pendingEntries.clear();
        }

        for (LogEntry logEntry : entriesInBulk) {
            IndexRequest request = buildIndexRequest(logEntry);
            if(request != null) {
                if (isEsHttpProtocol) {
                    httpBulkBuilder.add(request);
                } else {
                    bulkBuilder.add(request);
                }
            }else{
                //Could not build index request. Ignore it?
            }
        }

        if (isEsHttpProtocol) {
            try {
                BulkResponse bulkResponse = httpClient.bulk(httpBulkBuilder, RequestOptions.DEFAULT);
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else {
            BulkResponse resp = bulkBuilder.get();
            if(resp.hasFailures()){
                for (BulkItemResponse bulkItemResponse : resp.getItems()) {
                    System.err.println(bulkItemResponse.getFailureMessage());
                }
            }
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
