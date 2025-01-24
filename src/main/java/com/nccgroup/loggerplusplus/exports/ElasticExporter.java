package com.nccgroup.loggerplusplus.exports;

import co.elastic.clients.elasticsearch.ElasticsearchClient;
import co.elastic.clients.elasticsearch.core.BulkRequest;
import co.elastic.clients.elasticsearch.core.BulkResponse;
import co.elastic.clients.elasticsearch.core.bulk.BulkResponseItem;
import co.elastic.clients.elasticsearch.indices.CreateIndexRequest;
import co.elastic.clients.elasticsearch.indices.ExistsRequest;
import co.elastic.clients.json.jackson.JacksonJsonpMapper;
import co.elastic.clients.transport.ElasticsearchTransport;
import co.elastic.clients.transport.endpoints.BooleanResponse;
import co.elastic.clients.transport.rest_client.RestClientTransport;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.core.Version;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.databind.ser.std.StdSerializer;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.filter.logfilter.LogTableFilter;
import com.nccgroup.loggerplusplus.filter.parser.ParseException;
import com.nccgroup.loggerplusplus.logentry.LogEntry;
import com.nccgroup.loggerplusplus.logentry.LogEntryField;
import com.nccgroup.loggerplusplus.logentry.Status;
import com.nccgroup.loggerplusplus.util.Globals;
import lombok.extern.log4j.Log4j2;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.Header;
import org.apache.http.HttpHost;
import org.apache.http.message.BasicHeader;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.elasticsearch.client.RestClient;
import org.elasticsearch.client.RestClientBuilder;


import javax.swing.*;
import java.io.IOException;
import java.net.ConnectException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import java.text.SimpleDateFormat;

@Log4j2
public class ElasticExporter extends AutomaticLogExporter implements ExportPanelProvider, ContextMenuExportProvider {

    ElasticsearchClient elasticClient;
    ArrayList<LogEntry> pendingEntries;
    LogTableFilter logFilter;
    private List<LogEntryField> fields;
    private String indexName;
    private ScheduledFuture indexTask;
    private int connectFailedCounter;

    private final ScheduledExecutorService executorService;
    private final ElasticExporterControlPanel controlPanel;
    private final ObjectMapper mapper;

    private Logger logger = LogManager.getLogger(this);

    protected ElasticExporter(ExportController exportController, Preferences preferences) {
        super(exportController, preferences);
        this.fields = new ArrayList<>(preferences.getSetting(Globals.PREF_PREVIOUS_ELASTIC_FIELDS));
        executorService = Executors.newScheduledThreadPool(1);

        this.mapper = new ObjectMapper();
        SimpleModule module = new SimpleModule("LogEntry Serializer", new Version(0,1,0,"",null, null));
        module.addSerializer(LogEntry.class, new ElasticExporter.EntrySerializer(LogEntry.class));
        mapper.registerModule(module);

        if ((boolean) preferences.getSetting(Globals.PREF_ELASTIC_AUTOSTART_GLOBAL)
                || (boolean) preferences.getSetting(Globals.PREF_ELASTIC_AUTOSTART_PROJECT)) {
            //Autostart exporter.
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

        String projectPreviousFilterString = preferences.getSetting(Globals.PREF_ELASTIC_FILTER_PROJECT_PREVIOUS);
        String filterString = preferences.getSetting(Globals.PREF_ELASTIC_FILTER);

//        if (!Objects.equals(projectPreviousFilterString, filterString)) {
//            //The current filter isn't what we used to export last time.
//            int res = JOptionPane.showConfirmDialog(LoggerPlusPlus.instance.getLoggerFrame(),
//                    "Heads up! Looks like the filter being used to select which logs to export to " +
//                            "ElasticSearch has changed since you last ran the exporter for this project.\n" +
//                            "Do you want to continue?", "ElasticSearch Export Log Filter", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
//            if (res == JOptionPane.NO_OPTION) {
//                throw new Exception("Export cancelled.");
//            }
//        }

        if (!StringUtils.isBlank(filterString)) {
            try {
                logFilter = new LogTableFilter(filterString);
            } catch (ParseException ex) {
                logger.error("The log filter configured for the Elastic exporter is invalid!", ex);
                throw new Exception("The log filter configured for the Elastic exporter is invalid!", ex);
            }
        }

        InetAddress address = InetAddress.getByName(preferences.getSetting(Globals.PREF_ELASTIC_ADDRESS));
        int port = preferences.getSetting(Globals.PREF_ELASTIC_PORT);
        indexName = preferences.getSetting(Globals.PREF_ELASTIC_INDEX);
        String protocol = preferences.getSetting(Globals.PREF_ELASTIC_PROTOCOL).toString();
        RestClientBuilder restClientBuilder = RestClient.builder(new HttpHost(address, port, protocol));
        logger.info(String.format("Starting ElasticSearch exporter. %s://%s:%s/%s", protocol, address, port, indexName));

        Globals.ElasticAuthType authType = preferences.getSetting(Globals.PREF_ELASTIC_AUTH);
        String user = "", pass = "";
        switch (authType) {
            case ApiKey:
                user = preferences.getSetting(Globals.PREF_ELASTIC_API_KEY_ID);
                pass = preferences.getSetting(Globals.PREF_ELASTIC_API_KEY_SECRET);
                break;
            case Basic:
                user = preferences.getSetting(Globals.PREF_ELASTIC_USERNAME);
                pass = preferences.getSetting(Globals.PREF_ELASTIC_PASSWORD);
                break;

            default:
                break;
        }

        if (!"".equals(user) && !"".equalsIgnoreCase(pass)) {
            logger.info(String.format("ElasticSearch using %s, Username: %s", authType, user));
            String authValue = Base64.getEncoder().encodeToString((user + ":" + pass).getBytes(StandardCharsets.UTF_8));
            restClientBuilder.setDefaultHeaders(new Header[]{new BasicHeader("Authorization", String.format("%s %s", authType, authValue))});
        }


        ElasticsearchTransport transport = new RestClientTransport(restClientBuilder.build(), new JacksonJsonpMapper(this.mapper));

        elasticClient = new ElasticsearchClient(transport);

        createIndices();
        pendingEntries = new ArrayList<>();
        int delay = preferences.getSetting(Globals.PREF_ELASTIC_DELAY);
        indexTask = executorService.scheduleAtFixedRate(this::indexPendingEntries, delay, delay, TimeUnit.SECONDS);
    }

    @Override
    public void exportNewEntry(final LogEntry logEntry) {
        if(logEntry.getStatus() == Status.PROCESSED) {
            if (logFilter != null && !logFilter.getFilterExpression().matches(logEntry)) return;
            pendingEntries.add(logEntry);
        }
    }

    @Override
    public void exportUpdatedEntry(final LogEntry updatedEntry) {
        if(updatedEntry.getStatus() == Status.PROCESSED) {
            if (logFilter != null && !logFilter.getFilterExpression().matches(updatedEntry)) return;
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
        ExistsRequest existsRequest = new ExistsRequest.Builder().index(this.indexName).build();

        BooleanResponse exists = elasticClient.indices().exists(existsRequest);

        if(!exists.value()) {
            CreateIndexRequest createIndexRequest = new CreateIndexRequest.Builder().index(this.indexName).build();
            elasticClient.indices().create(createIndexRequest);
        }
    }

//    public JsonObject serializeLogEntry(LogEntry logEntry) {
//        //Todo Better serialization of entries
//        JsonObject jsonObject = new JsonObject();
//        for (LogEntryField field : this.fields) {
//            Object value = formatValue(logEntry.getValueByKey(field));
//            try {
//                jsonObject.addProperty(field.getFullLabel(), gson.toJson(value));
//            }catch (Exception e){
//                log.error("ElasticExporter: " + value);
//                log.error("ElasticExporter: " + e.getMessage());
//                throw e;
//            }
//        }
//        return jsonObject;
//    }

    private void indexPendingEntries(){
        try {
            if (this.pendingEntries.size() == 0) return;

            BulkRequest.Builder bulkBuilder = new BulkRequest.Builder();

            ArrayList<LogEntry> entriesInBulk;
            synchronized (pendingEntries) {
                entriesInBulk = new ArrayList<>(pendingEntries);
                pendingEntries.clear();
            }

            for (LogEntry logEntry : entriesInBulk) {
                try {
                    bulkBuilder.operations(op -> op
                            .index(idx -> idx
                                    .index(this.indexName)
                                    .document(logEntry)
                            )
                    );

                } catch (Exception e) {
                    log.error("Could not build elastic export request for entry: " + e.getMessage());
                    //Could not build index request. Ignore it?
                }
            }

            try {
                BulkResponse bulkResponse = elasticClient.bulk(bulkBuilder.build());
                if (bulkResponse.errors()) {
                    for (BulkResponseItem bulkResponseItem : bulkResponse.items()) {
                        log.error(bulkResponseItem.error().reason());
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
                log.error(e);
            }
        }catch (Exception e){
            log.error(e);
        }
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

    private class EntrySerializer extends StdSerializer<LogEntry> {

        public EntrySerializer(Class<LogEntry> t) {
            super(t);
        }

        @Override
        public void serialize(LogEntry logEntry, JsonGenerator gen, SerializerProvider provider) throws IOException {
            gen.writeStartObject();
            String stamp = null;
            for (LogEntryField field : ElasticExporter.this.fields) {
                Object value = logEntry.getValueByKey(field);
                if(value == null) continue;
                try {
                    switch (field.getType().getSimpleName()){
                        case "Integer": gen.writeNumberField(field.getFullLabel(), (Integer) value); break;
                        case "Short": gen.writeNumberField(field.getFullLabel(), (Short) value); break;
                        case "Double": gen.writeNumberField(field.getFullLabel(), (Double) value); break;
                        case "String": gen.writeStringField(field.getFullLabel(), value.toString()); break;
                        case "Boolean": gen.writeBooleanField(field.getFullLabel(), (Boolean) value); break;
                        case "Date":
                            String label = field.getFullLabel();
                            if(label.equals("Request.Time")){
                                SimpleDateFormat simpleDate = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX");
                                simpleDate.setTimeZone(TimeZone.getTimeZone("UTC"));
                                stamp = simpleDate.format(((Date) value));
                            }
                            gen.writeStringField(field.getFullLabel(), ((Date) value).toLocaleString());
                            break;
                        default: log.error("Unhandled field type: " + field.getType().getSimpleName());
                    }
                }catch (Exception e){
                    log.error("ElasticExporter: Couldn't serialize field. The field was ommitted from the export.");
                }
            }
            if(stamp != null){
                gen.writeStringField("@timestamp", stamp);
            }
            gen.writeEndObject();
        }
    }
}
