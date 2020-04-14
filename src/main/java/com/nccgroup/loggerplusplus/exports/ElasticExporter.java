package com.nccgroup.loggerplusplus.exports;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.loggerplusplus.logentry.LogEntry;
import com.nccgroup.loggerplusplus.logentry.Status;
import com.nccgroup.loggerplusplus.util.Globals;
import org.apache.http.HttpHost;
import org.elasticsearch.action.bulk.BulkItemResponse;
import org.elasticsearch.action.bulk.BulkRequest;
import org.elasticsearch.action.bulk.BulkResponse;
import org.elasticsearch.action.index.IndexAction;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.action.index.IndexRequestBuilder;
import org.elasticsearch.client.*;
import org.elasticsearch.client.indices.CreateIndexRequest;
import org.elasticsearch.client.indices.GetIndexRequest;
import org.elasticsearch.common.settings.Settings;

import javax.swing.*;
import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import static org.elasticsearch.common.xcontent.XContentFactory.jsonBuilder;

public class ElasticExporter extends LogExporter {

    RestHighLevelClient httpClient;
    ArrayList<LogEntry> pendingEntries;
    private String indexName;
    private boolean includeReqResp;
    private ScheduledFuture indexTask;

    private final ScheduledExecutorService executorService;
    private final ElasticExporterControlPanel controlPanel;

    protected ElasticExporter(ExportController exportController, Preferences preferences) {
        super(exportController, preferences);

        executorService = Executors.newScheduledThreadPool(1);
        controlPanel = new ElasticExporterControlPanel(this);
    }

    @Override
    void setup() throws Exception {
        InetAddress address = InetAddress.getByName(preferences.getSetting(Globals.PREF_ELASTIC_ADDRESS));
        int port = preferences.getSetting(Globals.PREF_ELASTIC_PORT);
        indexName = preferences.getSetting(Globals.PREF_ELASTIC_INDEX);
        String protocol = preferences.getSetting(Globals.PREF_ELASTIC_PROTOCOL).toString();

        httpClient = new RestHighLevelClient(RestClient.builder(
                new HttpHost(address, port, protocol)));

        createIndices();
        pendingEntries = new ArrayList<>();
        includeReqResp = preferences.getSetting(Globals.PREF_ELASTIC_INCLUDE_REQ_RESP);
        int delay = preferences.getSetting(Globals.PREF_ELASTIC_DELAY);
        indexTask = executorService.scheduleAtFixedRate(this::indexPendingEntries, delay, delay, TimeUnit.SECONDS);
    }

    @Override
    public void exportNewEntry(final LogEntry logEntry) {
        if(logEntry.getStatus() == Status.PROCESSED) {
            pendingEntries.add(logEntry);
        }
    }

    @Override
    public void exportUpdatedEntry(final LogEntry updatedEntry) {
        if(updatedEntry.getStatus() == Status.PROCESSED) {
            pendingEntries.add(updatedEntry);
        }
    }

    @Override
    void shutdown() throws Exception {
        if(this.indexTask != null){
            indexTask.cancel(true);
        }
        this.pendingEntries = null;
    }

    @Override
    public JComponent getExportPanel() {
        return controlPanel;
    }

    private void createIndices() throws IOException {
        GetIndexRequest request = new GetIndexRequest(this.indexName);

        boolean exists = httpClient.indices().exists(request, RequestOptions.DEFAULT);

        if(!exists) {
            CreateIndexRequest _request = new CreateIndexRequest(this.indexName);
            httpClient.indices().create(_request, RequestOptions.DEFAULT);
        }
    }

    public IndexRequest buildIndexRequest(LogEntry logEntry) throws IOException {
        IndexRequest request = new IndexRequest(this.indexName).source(
                        jsonBuilder().startObject()
                            .field("protocol", logEntry.protocol)
                            .field("method", logEntry.method)
                            .field("host", logEntry.hostname)
                            .field("path", logEntry.url.getPath())
                            .field("requesttime", logEntry.formattedRequestTime.equals("") ? null : logEntry.formattedRequestTime)
                            .field("responsetime", logEntry.formattedResponseTime.equals("") ? null : logEntry.formattedResponseTime)
                            .field("responsedelay", logEntry.requestResponseDelay)
                            .field("status", logEntry.responseStatus)
                            .field("title", logEntry.title)
                            .field("newcookies", logEntry.newCookies)
                            .field("sentcookies", logEntry.sentCookies)
                            .field("referrer", logEntry.referrerURL)
                            .field("requestcontenttype", logEntry.requestContentType)
                            .field("requestlength", logEntry.requestLength)
                            .field("responselength", logEntry.responseLength)
                            .field("requestbody", this.includeReqResp ?  new String(logEntry.requestResponse.getRequest()) : "")
                            .field("responsebody", this.includeReqResp ?  new String(logEntry.requestResponse.getResponse()) : "")
                        .endObject()
                );
        return request;
    }

    private void indexPendingEntries(){
        try {
            if (this.pendingEntries.size() == 0) return;

            BulkRequest httpBulkBuilder = new BulkRequest();

            ArrayList<LogEntry> entriesInBulk;
            synchronized (pendingEntries) {
                entriesInBulk = new ArrayList<>(pendingEntries);
                pendingEntries.clear();
            }

            for (LogEntry logEntry : entriesInBulk) {
                try {
                    IndexRequest request = buildIndexRequest(logEntry);
                    httpBulkBuilder.add(request);
                }catch (IOException e){
                    //Could not build index request. Ignore it?
                }
            }

            try {
                BulkResponse bulkResponse = httpClient.bulk(httpBulkBuilder, RequestOptions.DEFAULT);
                if (bulkResponse.hasFailures()) {
                    for (BulkItemResponse bulkItemResponse : bulkResponse.getItems()) {
                        System.err.println(bulkItemResponse.getFailureMessage());
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    public ExportController getExportController() {
        return this.exportController;
    }
}
