package com.nccgroup.loggerplusplus.exports;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.google.gson.Gson;
import com.nccgroup.loggerplusplus.logentry.LogEntry;
import com.nccgroup.loggerplusplus.logentry.LogEntryField;
import com.nccgroup.loggerplusplus.logentry.Status;
import com.nccgroup.loggerplusplus.util.FieldSelectorDialog;
import com.nccgroup.loggerplusplus.util.Globals;
import com.nccgroup.loggerplusplus.util.MoreHelp;
import com.nccgroup.loggerplusplus.util.SwingWorkerWithProgressDialog;
import org.apache.commons.text.StringEscapeUtils;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.event.ActionEvent;
import java.io.*;
import java.util.List;

/**
 * Created by corey on 21/08/17.
 */
public class JSONExporter extends LogExporter {

    private final JSONExporterControlPanel controlPanel;

    public JSONExporter(ExportController exportController, Preferences preferences){
        super(exportController, preferences);
        this.controlPanel = new JSONExporterControlPanel(this);
    }

    @Override
    public JComponent getExportPanel() {
        return this.controlPanel;
    }

    @Override
    public void exportEntries(List<LogEntry> entries) {
        try {
            File file = MoreHelp.getSaveFile("LoggerPlusPlus.json", "JSON Format", "json");
            if(file.exists() && !shouldOverwriteExistingFilePrompt()) return;

            SwingWorkerWithProgressDialog<Void> importWorker = new SwingWorkerWithProgressDialog<Void>(
                    JOptionPane.getFrameForComponent(this.controlPanel),
                    "JSON Export", "Exporting as JSON...", entries.size()){
                @Override
                protected Void doInBackground() throws Exception {
                    super.doInBackground();
                    try(FileWriter fileWriter = new FileWriter(file, false)) {
                        Gson gson = exportController.getLoggerPlusPlus().getGsonProvider().getGson();
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
        return new JMenuItem(new AbstractAction(String.format("Export %s as JSON", entries.size() != 1 ? "entries" : "entry")) {
            @Override
            public void actionPerformed(ActionEvent e) {
                exportEntries(entries);
            }
        });
    }

    private static boolean shouldOverwriteExistingFilePrompt() throws Exception {
        int val = JOptionPane.showConfirmDialog(null, "Replace Existing File?", "File Exists",
                JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);

        if (val == JOptionPane.YES_OPTION) {
            return true;
        } else {
            return false;
        }
    }

    public ExportController getExportController() {
        return this.exportController;
    }
}
