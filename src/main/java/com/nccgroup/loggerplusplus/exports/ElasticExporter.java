package com.nccgroup.loggerplusplus.exports;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.filter.logfilter.LogTableFilter;
import com.nccgroup.loggerplusplus.filter.parser.ParseException;
import com.nccgroup.loggerplusplus.logentry.LogEntry;
import com.nccgroup.loggerplusplus.logentry.LogEntryField;
import com.nccgroup.loggerplusplus.logentry.Status;
import com.nccgroup.loggerplusplus.logging.Log;
import com.nccgroup.loggerplusplus.util.Globals;
import java.io.IOException;
import java.net.ConnectException;
import java.net.URI;
import java.net.http.HttpConnectTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;
import javax.swing.JComponent;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;

/**
 * Sends complete entries to an Elasticsearch index as they are logged: entries collect in a list,
 * and every few seconds a background task sends the list as one bulk request.
 *
 * <p>A document has one property per chosen field, named as the field is in filters (for example
 * {@code Response.Status}). Its value has the field's type: a number, a boolean, a text, or for a
 * time the milliseconds since 1970. A field without a value is left out of the document.
 */
public class ElasticExporter extends AutomaticLogExporter
        implements ExportPanelProvider, ContextMenuExportProvider {

    /** How many bulk requests in a row may fail to connect before the exporter stops itself. */
    private static final int CONNECT_FAILURES_ALLOWED = 5;

    private final Object pendingLock = new Object();
    private List<LogEntry> pendingEntries;
    private ElasticClient elasticClient;
    private LogTableFilter logFilter;
    private List<LogEntryField> fields;
    private String indexName;
    private ScheduledFuture<?> indexTask;
    private int connectFailedCounter;

    private final ScheduledExecutorService executorService;
    private final ElasticExporterControlPanel controlPanel;
    private final Gson gson;

    protected ElasticExporter(ExportController exportController, Preferences preferences) {
        super(exportController, preferences);
        this.fields = new ArrayList<>(preferences.getSetting(Globals.PREF_PREVIOUS_ELASTIC_FIELDS));
        this.gson = LoggerPlusPlus.gsonProvider.getGson();
        executorService = Executors.newScheduledThreadPool(1);

        if ((boolean) preferences.getSetting(Globals.PREF_ELASTIC_AUTOSTART_GLOBAL)
                || (boolean) preferences.getSetting(Globals.PREF_ELASTIC_AUTOSTART_PROJECT)) {
            // Autostart exporter.
            try {
                this.exportController.enableExporter(this);
            } catch (Exception e) {
                JOptionPane.showMessageDialog(
                        LoggerPlusPlus.instance.getLoggerFrame(),
                        "Could not start elastic exporter: "
                                + e.getMessage()
                                + "\nSee the logs for more information.",
                        "Elastic Exporter",
                        JOptionPane.ERROR_MESSAGE);
                Log.error("Could not automatically start elastic exporter:", e);
            }
        }
        controlPanel = new ElasticExporterControlPanel(this);
    }

    @Override
    void setup() throws Exception {
        if (this.fields == null || this.fields.isEmpty())
            throw new Exception("No fields configured for export.");

        String filterString = preferences.getSetting(Globals.PREF_ELASTIC_FILTER);
        if (filterString != null && !filterString.isBlank()) {
            try {
                logFilter = new LogTableFilter(filterString);
            } catch (ParseException ex) {
                Log.error("The log filter configured for the Elastic exporter is invalid!", ex);
                throw new Exception(
                        "The log filter configured for the Elastic exporter is invalid!", ex);
            }
        }

        String address = preferences.getSetting(Globals.PREF_ELASTIC_ADDRESS);
        int port = preferences.getSetting(Globals.PREF_ELASTIC_PORT);
        indexName = preferences.getSetting(Globals.PREF_ELASTIC_INDEX);
        String protocol =
                preferences
                        .getSetting(Globals.PREF_ELASTIC_PROTOCOL)
                        .toString()
                        .toLowerCase(Locale.ROOT);
        Log.info(
                String.format(
                        "Starting ElasticSearch exporter. %s://%s:%s/%s",
                        protocol, address, port, indexName));

        elasticClient =
                new ElasticClient(
                        new URI(protocol, null, address, port, null, null, null), authorization());
        elasticClient.ensureIndex(indexName);
        synchronized (pendingLock) {
            pendingEntries = new ArrayList<>();
        }
        int delay = preferences.getSetting(Globals.PREF_ELASTIC_DELAY);
        indexTask =
                executorService.scheduleAtFixedRate(
                        this::indexPendingEntries, delay, delay, TimeUnit.SECONDS);
    }

    /** The Authorization header for the configured credentials, or null when there are none. */
    private String authorization() {
        Globals.ElasticAuthType authType = preferences.getSetting(Globals.PREF_ELASTIC_AUTH);
        String user = "";
        String pass = "";
        switch (authType) {
            case ApiKey -> {
                user = preferences.getSetting(Globals.PREF_ELASTIC_API_KEY_ID);
                pass = preferences.getSetting(Globals.PREF_ELASTIC_API_KEY_SECRET);
            }
            case Basic -> {
                user = preferences.getSetting(Globals.PREF_ELASTIC_USERNAME);
                pass = preferences.getSetting(Globals.PREF_ELASTIC_PASSWORD);
            }
            default -> {}
        }
        if ("".equals(user) || "".equals(pass)) {
            return null;
        }
        Log.info(String.format("ElasticSearch using %s, Username: %s", authType, user));
        String credentials =
                Base64.getEncoder()
                        .encodeToString((user + ":" + pass).getBytes(StandardCharsets.UTF_8));
        return authType + " " + credentials;
    }

    @Override
    public void exportNewEntry(final LogEntry logEntry) {
        queue(logEntry);
    }

    @Override
    public void exportUpdatedEntry(final LogEntry updatedEntry) {
        queue(updatedEntry);
    }

    /** Called by the worker threads: keeps a complete entry that passes the filter for sending. */
    private void queue(LogEntry logEntry) {
        if (logEntry.getStatus() != Status.PROCESSED) {
            return;
        }
        if (logFilter != null && !logFilter.getFilterExpression().matches(logEntry)) {
            return;
        }
        synchronized (pendingLock) {
            if (pendingEntries != null) {
                pendingEntries.add(logEntry);
            }
        }
    }

    @Override
    void shutdown() throws Exception {
        if (this.indexTask != null) {
            indexTask.cancel(true);
        }
        synchronized (pendingLock) {
            this.pendingEntries = null;
        }
    }

    @Override
    public JComponent getExportPanel() {
        return controlPanel;
    }

    @Override
    public JMenuItem getExportEntriesMenuItem(List<LogEntry> entries) {
        return null;
    }

    /**
     * The document sent for an entry. A field whose value is not of the field's type (a response
     * field of an entry that has no response, say) is left out, and so is a field of a type that
     * Elasticsearch is given no mapping for here, such as a URL; both are reported in the log.
     */
    static JsonObject documentOf(LogEntry logEntry, List<LogEntryField> fields) {
        JsonObject document = new JsonObject();
        for (LogEntryField field : fields) {
            Object value = logEntry.getValueByKey(field);
            if (value == null) {
                continue;
            }
            String name = field.getFullLabel();
            Class<?> type = field.getType();
            if (type == String.class) {
                document.addProperty(name, value.toString());
            } else if (type == Integer.class || type == Short.class || type == Double.class) {
                if (value instanceof Number number) {
                    document.addProperty(name, number);
                } else {
                    reportOmitted();
                }
            } else if (type == Boolean.class) {
                if (value instanceof Boolean bool) {
                    document.addProperty(name, bool);
                } else {
                    reportOmitted();
                }
            } else if (type == Date.class) {
                if (value instanceof Date date) {
                    document.addProperty(name, date.getTime());
                } else {
                    reportOmitted();
                }
            } else {
                Log.error("Unhandled field type: " + type.getSimpleName());
            }
        }
        return document;
    }

    private static void reportOmitted() {
        Log.error(
                "ElasticExporter: Couldn't serialize field. The field was ommitted from the export.");
    }

    /** On the exporter's own thread: sends everything queued since the last run. */
    private void indexPendingEntries() {
        List<LogEntry> entriesInBulk;
        synchronized (pendingLock) {
            if (pendingEntries == null || pendingEntries.isEmpty()) {
                return;
            }
            entriesInBulk = pendingEntries;
            pendingEntries = new ArrayList<>();
        }

        List<String> documents = new ArrayList<>(entriesInBulk.size());
        for (LogEntry logEntry : entriesInBulk) {
            try {
                documents.add(gson.toJson(documentOf(logEntry, fields)));
            } catch (RuntimeException e) {
                Log.error("Could not build elastic export request for entry: " + e.getMessage());
            }
        }

        try {
            for (String reason : elasticClient.bulkIndex(indexName, documents)) {
                Log.error(reason);
            }
            connectFailedCounter = 0;
        } catch (ConnectException | HttpConnectTimeoutException e) {
            connectFailedCounter++;
            if (connectFailedCounter > CONNECT_FAILURES_ALLOWED) {
                stopAfterFailingToConnect();
            }
        } catch (IOException e) {
            Log.error("Elastic export failed: " + e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    private void stopAfterFailingToConnect() {
        JOptionPane.showMessageDialog(
                JOptionPane.getFrameForComponent(LoggerPlusPlus.instance.getLoggerMenu()),
                "Elastic exporter could not connect after 5 attempts. Elastic exporter shutting down...",
                "Elastic Exporter - Connection Failed",
                JOptionPane.ERROR_MESSAGE);
        try {
            shutdown();
        } catch (Exception e) {
            Log.error("Could not shut the elastic exporter down: " + e.getMessage());
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
}
