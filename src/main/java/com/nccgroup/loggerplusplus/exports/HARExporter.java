package com.nccgroup.loggerplusplus.exports;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.reflect.TypeToken;
import com.nccgroup.loggerplusplus.logentry.LogEntry;
import com.nccgroup.loggerplusplus.util.Globals;
import com.nccgroup.loggerplusplus.util.MoreHelp;
import com.nccgroup.loggerplusplus.util.SwingWorkerWithProgressDialog;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.io.File;
import java.io.FileWriter;
import java.lang.reflect.Type;
import java.util.List;

public class HARExporter extends LogExporter implements ExportPanelProvider, ContextMenuExportProvider {

    private final HARExporterControlPanel controlPanel;

    public HARExporter(ExportController exportController, Preferences preferences) {
        super(exportController, preferences);
        this.controlPanel = new HARExporterControlPanel(this);
    }

    @Override
    public JComponent getExportPanel() {
        return this.controlPanel;
    }

    public void exportEntries(List<LogEntry> entries) {
        try {
            File file = MoreHelp.getSaveFile("LoggerPlusPlus.har", "HAR Format", "har");
            if (file.exists() && !MoreHelp.shouldOverwriteExistingFilePrompt())
                return;

            SwingWorkerWithProgressDialog<Void> importWorker = new SwingWorkerWithProgressDialog<Void>(
                    JOptionPane.getFrameForComponent(this.controlPanel), "HAR Export", "Exporting as HAR...",
                    entries.size()) {
                @Override
                protected Void doInBackground() throws Exception {
                    super.doInBackground();
                    try (FileWriter fileWriter = new FileWriter(file, false)) {
                        Type logEntryListType = new TypeToken<List<LogEntry>>(){}.getType();
                        Gson gson = new GsonBuilder().registerTypeAdapter(logEntryListType, new HarSerializer(String.valueOf(Globals.VERSION), "LoggerPlusPlus")).create();
                        gson.toJson(entries, logEntryListType, fileWriter);
                    }

                    return null;
                }

                @Override
                protected void done() {
                    super.done();
                    JOptionPane.showMessageDialog(controlPanel, "Export as HAR completed.", "HAR Export",
                            JOptionPane.INFORMATION_MESSAGE);
                }
            };

            importWorker.execute();

        } catch (Exception e) {
            // Cancelled.
        }
    }

    @Override
    public JMenuItem getExportEntriesMenuItem(List<LogEntry> entries) {
        return new JMenuItem(new AbstractAction(
                String.format("Export %d %s as HAR", entries.size(), entries.size() != 1 ? "entries" : "entry")) {
            @Override
            public void actionPerformed(ActionEvent e) {
                exportEntries(entries);
            }
        });
    }

    public ExportController getExportController() {
        return this.exportController;
    }
}