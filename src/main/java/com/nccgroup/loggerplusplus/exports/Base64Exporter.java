package com.nccgroup.loggerplusplus.exports;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.logentry.LogEntry;
import com.nccgroup.loggerplusplus.util.MoreHelp;
import com.nccgroup.loggerplusplus.util.SwingWorkerWithProgressDialog;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Created by corey on 21/08/17.
 */
public class Base64Exporter extends LogExporter implements ContextMenuExportProvider {

    public Base64Exporter(ExportController exportController, Preferences preferences) {
        super(exportController, preferences);
    }

    public void exportEntries(List<LogEntry> entries, boolean includeRequest, boolean includeResponse) {
        if (!includeRequest && !includeResponse)
            throw new IllegalArgumentException("Must include either request, response or both.");
        try {
            File file = MoreHelp.getSaveFile("LoggerPlusPlus_Base64.json", "JSON Format", "json");
            if (file.exists() && !MoreHelp.shouldOverwriteExistingFilePrompt()) return;

            SwingWorkerWithProgressDialog<Void> importWorker = new SwingWorkerWithProgressDialog<Void>(
                    LoggerPlusPlus.instance.getLoggerFrame(),
                    "Base64 Encoded JSON Export", "Exporting as Base64 encoded JSON...", entries.size()) {
                @Override
                protected Void doInBackground() throws Exception {
                    super.doInBackground();
                    try (FileWriter fileWriter = new FileWriter(file, false)) {
                        Gson gson = LoggerPlusPlus.gsonProvider.getGson();
                        ArrayList<JsonObject> jsonEntries = new ArrayList<>();
                        Base64.Encoder encoder = Base64.getEncoder();
                        for (LogEntry entry : entries) {
                            JsonObject jsonEntry = new JsonObject();
                            if (includeRequest) {
                                jsonEntry.addProperty("request",
                                        encoder.encodeToString(entry.getRequestBytes()));
                            }

                            if (includeResponse) {
                                jsonEntry.addProperty("response",
                                        encoder.encodeToString(entry.getResponseBytes()));
                            }
                            jsonEntries.add(jsonEntry);
                        }

                        gson.toJson(jsonEntries, fileWriter);
                    }

                    return null;
                }

                @Override
                protected void done() {
                    super.done();
                    JOptionPane.showMessageDialog(LoggerPlusPlus.instance.getLoggerFrame(),
                            "Export as Base64 completed.",
                            "Base64 Export", JOptionPane.INFORMATION_MESSAGE);
                }
            };

            importWorker.execute();

        } catch (Exception e) {
            //Cancelled.
        }
    }

    @Override
    public JMenuItem getExportEntriesMenuItem(List<LogEntry> entries) {
        JMenu parent = new JMenu(String.format("Export %d %s as Base64 (JSON Formatted)",
                entries.size(), entries.size() != 1 ? "entries" : "entry"));

        parent.add(new JMenuItem(new AbstractAction(entries.size() == 1 ? "Request Only" : "Requests Only") {
            @Override
            public void actionPerformed(ActionEvent e) {
                exportEntries(entries, true, false);
            }
        }));

        parent.add(new JMenuItem(new AbstractAction(entries.size() == 1 ? "Response Only" : "Responses Only") {
            @Override
            public void actionPerformed(ActionEvent e) {
                exportEntries(entries, false, true);
            }
        }));

        parent.add(new JMenuItem(new AbstractAction(entries.size() == 1 ? "Request and Response" : "Requests and Responses") {
            @Override
            public void actionPerformed(ActionEvent e) {
                exportEntries(entries, true, true);
            }
        }));

        return parent;
    }

    public ExportController getExportController() {
        return this.exportController;
    }
}
