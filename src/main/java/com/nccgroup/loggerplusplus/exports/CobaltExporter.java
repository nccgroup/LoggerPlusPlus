package com.nccgroup.loggerplusplus.exports;

import java.net.ConnectException;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledFuture;
import java.util.concurrent.TimeUnit;

import javax.swing.JComponent;
import javax.swing.JMenuItem;
import javax.swing.JOptionPane;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.google.gson.Gson;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.logentry.LogEntry;
import com.nccgroup.loggerplusplus.logentry.LogEntryField;
import com.nccgroup.loggerplusplus.logentry.Status;
import com.nccgroup.loggerplusplus.util.Globals;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class CobaltExporter extends AutomaticLogExporter implements ExportPanelProvider, ContextMenuExportProvider {

    CloseableHttpClient httpClient;
    ArrayList<LogEntry> pendingEntries;
    private List<LogEntryField> fields;
    private ScheduledFuture syncTask;
    private int connectFailedCounter;

    private final ScheduledExecutorService executorService;
    private final CobaltExporterControlPanel controlPanel;

    private Logger logger = LogManager.getLogger(this);

    protected CobaltExporter(ExportController exportController, Preferences preferences) {
        super(exportController, preferences);
        this.fields = new ArrayList<>(preferences.getSetting(Globals.PREF_PREVIOUS_COBALT_FIELDS));
        executorService = Executors.newScheduledThreadPool(1);

        if ((boolean) preferences.getSetting(Globals.PREF_COBALT_AUTOSTART_GLOBAL)
                || (boolean) preferences.getSetting(Globals.PREF_COBALT_AUTOSTART_PROJECT)) {
            try {
                this.exportController.enableExporter(this);
            } catch (Exception e) {
                JOptionPane.showMessageDialog(LoggerPlusPlus.instance.getLoggerFrame(), "Could not start elastic exporter: " +
                        e.getMessage() + "\nSee the logs for more information.", "Elastic Exporter", JOptionPane.ERROR_MESSAGE);
                logger.error("Could not automatically start elastic exporter:", e);
            }
        }
        controlPanel = new CobaltExporterControlPanel(this);
    }

    @Override
    void setup() throws Exception {
        if (this.fields == null || this.fields.isEmpty())
            throw new Exception("No fields configured for export.");

        httpClient = HttpClients.createDefault();
        pendingEntries = new ArrayList<>();
        LoggerPlusPlus.callbacks.printOutput("Cobalt Logger++ initialized successfully");
        int delay = preferences.getSetting(Globals.PREF_COBALT_DELAY);
        syncTask = executorService.scheduleAtFixedRate(this::exportPendingEntries, delay, delay, TimeUnit.SECONDS);
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
        if(this.syncTask != null){
            syncTask.cancel(true);
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

    private void exportPendingEntries(){
        LoggerPlusPlus.callbacks.printOutput("Uploading pending log entries ("+this.pendingEntries.size()+")...");

        try {
            if (this.pendingEntries.size() == 0) return;

            ArrayList<LogEntry> entriesInBulk;
            synchronized (pendingEntries) {
                entriesInBulk = new ArrayList<>(pendingEntries);
                pendingEntries.clear();
            }

            Gson gson = exportController.getLoggerPlusPlus().getGsonProvider().getGson();
            StringEntity body = new StringEntity(gson.toJson(entriesInBulk));

            String address = preferences.getSetting(Globals.PREF_COBALT_ADDRESS);
            HttpPost post = new HttpPost(address);
            post.setEntity(body);

            try {
                CloseableHttpResponse response = httpClient.execute(post);
                int statusCode = response.getStatusLine().getStatusCode();

                LoggerPlusPlus.callbacks.printOutput("Upload finished with status code " + statusCode);
                if (statusCode >=400) {
                    LoggerPlusPlus.callbacks.printOutput(EntityUtils.toString(response.getEntity()));
                }
                connectFailedCounter = 0;
            } catch (ConnectException e) {
                LoggerPlusPlus.callbacks.printError("Connection error, upload failed");
                connectFailedCounter++;
                if(connectFailedCounter > 5) {
                    JOptionPane.showMessageDialog(JOptionPane.getFrameForComponent(LoggerPlusPlus.instance.getLoggerMenu()),
                            "Cobalt exporter could not connect after 5 attempts. Elastic exporter shutting down...",
                            "Cobalt Exporter - Connection Failed", JOptionPane.ERROR_MESSAGE);
                    shutdown();
                }
            }
        }catch (Exception e){
                LoggerPlusPlus.callbacks.printError("Upload failed: " + ExceptionUtils.getStackTrace(e));
        }
    }

    public ExportController getExportController() {
        return this.exportController;
    }

    public List<LogEntryField> getFields() {
        return fields;
    }

    public void setFields(List<LogEntryField> fields) {
        preferences.setSetting(Globals.PREF_PREVIOUS_COBALT_FIELDS, fields);
        this.fields = fields;
    }
}
