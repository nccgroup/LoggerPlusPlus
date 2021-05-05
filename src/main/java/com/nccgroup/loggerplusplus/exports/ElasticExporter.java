package com.nccgroup.loggerplusplus.exports;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.logentry.LogEntry;
import com.nccgroup.loggerplusplus.logentry.LogEntryField;
import com.nccgroup.loggerplusplus.logentry.Status;
import com.nccgroup.loggerplusplus.util.Globals;
import org.apache.http.Header;
import org.apache.http.HttpHost;
import org.apache.http.message.BasicHeader;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.action.bulk.BulkItemResponse;
import org.elasticsearch.action.bulk.BulkRequest;
import org.elasticsearch.action.bulk.BulkResponse;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.client.RequestOptions;
import org.elasticsearch.client.RestClient;
import org.elasticsearch.client.RestClientBuilder;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.client.indices.CreateIndexRequest;
import org.elasticsearch.client.indices.GetIndexRequest;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.XContentElasticsearchExtension;

import javax.swing.*;
import java.io.IOException;
import java.net.ConnectException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import static org.elasticsearch.common.xcontent.XContentFactory.jsonBuilder;

public class ElasticExporter extends AutomaticLogExporter implements ExportPanelProvider, ContextMenuExportProvider {

    RestHighLevelClient httpClient;
    ArrayList<LogEntry> pendingEntries;
    private List<LogEntryField> fields;
    private String indexName;
    private ScheduledFuture indexTask;
    private int connectFailedCounter;

    private final ScheduledExecutorService executorService;
    private final ElasticExporterControlPanel controlPanel;

    private Logger logger = LogManager.getLogger(this);

    protected ElasticExporter(ExportController exportController, Preferences preferences) {
        super(exportController, preferences);
        this.fields = new ArrayList<>(preferences.getSetting(Globals.PREF_PREVIOUS_ELASTIC_FIELDS));
        executorService = Executors.newScheduledThreadPool(1);

        if ((boolean) preferences.getSetting(Globals.PREF_ELASTIC_AUTOSTART_GLOBAL)
                || (boolean) preferences.getSetting(Globals.PREF_ELASTIC_AUTOSTART_PROJECT)) {
            try {
                this.exportController.enableExporter(this);
            } catch (Exception e) {
                JOptionPane.showMessageDialog(LoggerPlusPlus.instance.getLoggerFrame(), "Could not start elastic exporter: " +
                        e.getMessage() + "\nSee the logs for more information.", "Elastic Exporter", JOptionPane.ERROR_MESSAGE);
                logger.error("Could not automatically start elastic exporter:", e);
            }
        }
        controlPanel = new ElasticExporterControlPanel(this);
    }

    @Override
    void setup() throws Exception {
        if (this.fields == null || this.fields.isEmpty())
            throw new Exception("No fields configured for export.");

        InetAddress address = InetAddress.getByName(preferences.getSetting(Globals.PREF_ELASTIC_ADDRESS));
        int port = preferences.getSetting(Globals.PREF_ELASTIC_PORT);
        indexName = preferences.getSetting(Globals.PREF_ELASTIC_INDEX);
        String protocol = preferences.getSetting(Globals.PREF_ELASTIC_PROTOCOL).toString();
        String apiKeyId = preferences.getSetting(Globals.PREF_ELASTIC_API_KEY_ID);
        String apiKeySecret = preferences.getSetting(Globals.PREF_ELASTIC_API_KEY_SECRET);

        RestClientBuilder builder = RestClient.builder(new HttpHost(address, port, protocol));
        if (!"".equals(apiKeyId) && !"".equalsIgnoreCase(apiKeySecret)) {
            String apiKeyAuth = Base64.getEncoder().encodeToString((apiKeyId + ":" + apiKeySecret).getBytes(StandardCharsets.UTF_8));
            builder.setDefaultHeaders(new Header[]{new BasicHeader("Authorization", "ApiKey " + apiKeyAuth)});
        }

        httpClient = new RestHighLevelClient(builder);

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

    @Override
    public JMenuItem getExportEntriesMenuItem(List<LogEntry> entries) {
        return null;
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
            Object value = formatValue(logEntry.getValueByKey(field));
            try {
                //For some reason, the XContentElasticsearchExtension service cannot be loaded
                //when in burp, so we must format dates manually ourselves :(
                //TODO investigate further
                if (value instanceof Date) {
                    builder.field(field.getFullLabel(), XContentElasticsearchExtension.DEFAULT_DATE_PRINTER.print(((Date) value).getTime()));
                } else {
                    builder.field(field.getFullLabel(), value);
                }
            }catch (Exception e){
                LoggerPlusPlus.callbacks.printError("ElasticExporter: " + value);
                LoggerPlusPlus.callbacks.printError("ElasticExporter: " + e.getMessage());
                throw e;
            }
        }
        builder.endObject();

        return new IndexRequest(this.indexName, "doc").source(builder); //TODO Remove deprecated ES6 methods.
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
                } catch (Exception e) {
                    LoggerPlusPlus.callbacks.printError("Could not build elastic export request for entry: " + e.getMessage());
                    //Could not build index request. Ignore it?
                }
            }

            try {
                BulkResponse bulkResponse = httpClient.bulk(httpBulkBuilder, RequestOptions.DEFAULT);
                if (bulkResponse.hasFailures()) {
                    for (BulkItemResponse bulkItemResponse : bulkResponse.getItems()) {
                        LoggerPlusPlus.callbacks.printError(bulkItemResponse.getFailureMessage());
                    }
                }
                connectFailedCounter = 0;
            } catch (ConnectException e) {
                connectFailedCounter++;
                if(connectFailedCounter > 5) {
                    JOptionPane.showMessageDialog(JOptionPane.getFrameForComponent(LoggerPlusPlus.instance.getLoggerMenu()),
                            "Elastic exporter could not connect after 5 attempts. Elastic exporter shutting down...",
                            "Elastic Exporter - Connection Failed", JOptionPane.ERROR_MESSAGE);
                    shutdown();
                }
            }catch (IOException e) {
                e.printStackTrace();
            }
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    private Object formatValue(Object value){
        if (value instanceof java.net.URL) return String.valueOf((java.net.URL) value);
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
