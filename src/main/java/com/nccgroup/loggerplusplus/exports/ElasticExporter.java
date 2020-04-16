package com.nccgroup.loggerplusplus.exports;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.logentry.LogEntry;
import com.nccgroup.loggerplusplus.logentry.LogEntryField;
import com.nccgroup.loggerplusplus.logentry.Status;
import com.nccgroup.loggerplusplus.util.Globals;
import org.apache.http.HttpHost;
import org.elasticsearch.action.bulk.BulkItemResponse;
import org.elasticsearch.action.bulk.BulkRequest;
import org.elasticsearch.action.bulk.BulkResponse;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.RestClient;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.client.indices.CreateIndexRequest;
import org.elasticsearch.client.indices.GetIndexRequest;
import org.elasticsearch.common.xcontent.XContentBuilder;

import javax.swing.*;
import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import static com.nccgroup.loggerplusplus.logentry.LogEntryField.*;
import static org.elasticsearch.common.xcontent.XContentFactory.jsonBuilder;

public class ElasticExporter extends LogExporter {

    RestHighLevelClient httpClient;
    ArrayList<LogEntry> pendingEntries;
    private List<LogEntryField> fields;
    private String indexName;
    private ScheduledFuture indexTask;

    private final ScheduledExecutorService executorService;
    private final ElasticExporterControlPanel controlPanel;

    protected ElasticExporter(ExportController exportController, Preferences preferences) {
        super(exportController, preferences);
        this.fields = new ArrayList<>(preferences.getSetting(Globals.PREF_PREVIOUS_ELASTIC_FIELDS));
        executorService = Executors.newScheduledThreadPool(1);
        controlPanel = new ElasticExporterControlPanel(this);
    }

    @Override
    void setup() throws Exception {
        if(this.fields == null || this.fields.isEmpty())
            throw new Exception("No fields configured for export.");

        InetAddress address = InetAddress.getByName(preferences.getSetting(Globals.PREF_ELASTIC_ADDRESS));
        int port = preferences.getSetting(Globals.PREF_ELASTIC_PORT);
        indexName = preferences.getSetting(Globals.PREF_ELASTIC_INDEX);
        String protocol = preferences.getSetting(Globals.PREF_ELASTIC_PROTOCOL).toString();

        httpClient = new RestHighLevelClient(RestClient.builder(
                new HttpHost(address, port, protocol)));

        createIndices();
        pendingEntries = new ArrayList<>();
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
        XContentBuilder builder = jsonBuilder().startObject();
        for (LogEntryField field : this.fields) {
            builder = builder.field(field.getFullLabel(), formatValue(logEntry.getValueByKey(field)));
        }
        builder.endObject();

        return new IndexRequest(this.indexName).source(builder);
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
                    LoggerPlusPlus.callbacks.printError("Could not build elastic export request for entry: " + e.getMessage());
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

    private Object formatValue(Object value){
        if(value instanceof Date) return ((Date) value).getTime();
        else return value;
    }

    public ExportController getExportController() {
        return this.exportController;
    }

    public List<LogEntryField> getFields() {
        return fields;
    }

    public void setFields(List<LogEntryField> fields) {
        preferences.setSetting(Globals.PREF_PREVIOUS_ELASTIC_FIELDS, fields);
        this.fields = fields;
    }
}
