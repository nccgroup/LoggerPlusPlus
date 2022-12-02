package com.nccgroup.loggerplusplus.exports;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.google.gson.Gson;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.logentry.LogEntry;
import com.nccgroup.loggerplusplus.util.MoreHelp;
import com.nccgroup.loggerplusplus.util.SwingWorkerWithProgressDialog;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.io.File;
import java.io.FileWriter;
import java.util.List;

/**
 * Created by corey on 21/08/17.
 */
public class JSONExporter extends LogExporter implements ExportPanelProvider, ContextMenuExportProvider {

    private final JSONExporterControlPanel controlPanel;

    public JSONExporter(ExportController exportController, Preferences preferences) {
        super(exportController, preferences);
        this.controlPanel = new JSONExporterControlPanel(this);
    }

    @Override
    public JComponent getExportPanel() {
        return this.controlPanel;
    }

    public void exportEntries(List<LogEntry> entries) {
        try {
            File file = MoreHelp.getSaveFile("LoggerPlusPlus.json", "JSON Format", "json");
            if (file.exists() && !MoreHelp.shouldOverwriteExistingFilePrompt()) return;

            SwingWorkerWithProgressDialog<Void> importWorker = new SwingWorkerWithProgressDialog<Void>(
                    JOptionPane.getFrameForComponent(this.controlPanel),
                    "JSON Export", "Exporting as JSON...", entries.size()){
                @Override
                protected Void doInBackground() throws Exception {
                    super.doInBackground();
                    try(FileWriter fileWriter = new FileWriter(file, false)) {
                        Gson gson = LoggerPlusPlus.gsonProvider.getGson();
                        gson.toJson(entries, fileWriter);
                    }

                    return null;
                }

                @Override
                protected void done() {
                    super.done();
                    JOptionPane.showMessageDialog(controlPanel, "Export as JSON completed.",
                            "JSON Export", JOptionPane.INFORMATION_MESSAGE);
                }
            };

            importWorker.execute();

        }catch (Exception e){
            //Cancelled.
        }
    }

    @Override
    public JMenuItem getExportEntriesMenuItem(List<LogEntry> entries) {
        return new JMenuItem(new AbstractAction(String.format("Export %d %s as JSON",
                entries.size(), entries.size() != 1 ? "entries" : "entry")) {
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
