package com.nccgroup.loggerplusplus.exports;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.loggerplusplus.logentry.LogEntry;
import com.nccgroup.loggerplusplus.logentry.LogEntryField;
import com.nccgroup.loggerplusplus.logentry.Status;
import com.nccgroup.loggerplusplus.util.Globals;
import com.nccgroup.loggerplusplus.util.MoreHelp;
import com.nccgroup.loggerplusplus.util.SwingWorkerWithProgressDialog;
import org.apache.commons.text.StringEscapeUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.io.*;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * Created by corey on 21/08/17.
 */
public class CSVExporter extends AutomaticLogExporter implements ContextMenuExportProvider, ExportPanelProvider {

    private final CSVExporterControlPanel controlPanel;

    private FileWriter autoSaveWriter;
    private File autoSaveFile;
    private List<LogEntryField> fields;
    private Thread exporterThread;
    private LinkedBlockingQueue<LogEntry> awaitingExport;

    Logger logger = LogManager.getLogger(this);

    public CSVExporter(ExportController exportController, Preferences preferences){
        super(exportController, preferences);
        this.fields = preferences.getSetting(Globals.PREF_PREVIOUS_EXPORT_FIELDS);
        this.controlPanel = new CSVExporterControlPanel(this);
    }

    @Override
    public void setup() throws Exception {
        fields = MoreHelp.showFieldChooserDialog(controlPanel, preferences, "CSV Export", this.fields);
        if(fields == null || fields.isEmpty()) throw new Exception("Operation cancelled.");
        autoSaveFile = MoreHelp.getSaveFile("LoggerPlusPlus_Autosave.csv", "CSV File", "csv");
        boolean append;
        if(autoSaveFile.exists()){
            append = shouldAppendToExistingFile(autoSaveFile, fields);
        }else{
            append = true;
        }

        autoSaveWriter = new FileWriter(autoSaveFile, append);
        awaitingExport = new LinkedBlockingQueue<>();

        exporterThread = new Thread(() -> {
            if(!append){
                try {
                    autoSaveWriter.append(buildHeader(fields));
                    autoSaveWriter.flush();
                }catch (IOException e){}
            }

            while(!Thread.currentThread().isInterrupted()){
                try {
                    LogEntry logEntry = awaitingExport.take();

                    autoSaveWriter.append("\n");
                    autoSaveWriter.append(entryToCSVString(logEntry, fields));
                    autoSaveWriter.flush();

                }catch (InterruptedException e){
                    //Thread stopped
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        });

        exporterThread.start();
    }

    @Override
    public void shutdown() throws Exception {
        exporterThread.interrupt();
        exporterThread = null;
        try {
            autoSaveWriter.close();
        }catch (IOException ignored){}

        awaitingExport.clear();
        awaitingExport = null;
        autoSaveWriter = null;
    }

    @Override
    public JComponent getExportPanel() {
        return this.controlPanel;
    }

    @Override
    public JMenuItem getExportEntriesMenuItem(List<LogEntry> entries) {
        return new JMenuItem(new AbstractAction(String.format("Export %d %s as CSV",
                entries.size(), entries.size() != 1 ? "entries" : "entry")) {
            @Override
            public void actionPerformed(ActionEvent e) {
                exportEntries(entries);
            }
        });
    }

    static boolean shouldAppendToExistingFile(File file, List<LogEntryField> fields) throws Exception{
        if (validHeader(file, fields)) {
            //The existing file uses the same field set.
            // We can ask the user if they want to append the entries or overwrite
            //True = append, false = overwrite.
            return promptAppendToExistingFileDialog();
        } else {
            //Prompt the user if they wish to overwrite
            if (MoreHelp.shouldOverwriteExistingFilePrompt()) {
                return false; //i.e. Do not append
            } else {
                throw new Exception("Operation cancelled.");
            }
        }
    }

    //Check if header in file matches that of the columns we will be exporting.
    private static boolean validHeader(File csvFile, List<LogEntryField> fields) {
        BufferedReader reader;
        try {
            reader = new BufferedReader(new FileReader(csvFile));
        } catch (FileNotFoundException e) {
            return true;
        }
        try {
            String thisHeader = buildHeader(fields);
            String oldHeader = reader.readLine();
            return oldHeader == null || oldHeader.equalsIgnoreCase(thisHeader);
        } catch (IOException e) {
            return true;
        }
    }

    private static boolean promptAppendToExistingFileDialog() throws Exception {
        Object[] options = {"Append",
                "Overwrite", "Cancel"};
        int val = JOptionPane.showOptionDialog(null,
                "Append to, or overwrite the existing file?", "File Exists",
                JOptionPane.YES_NO_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE, null, options, options[0]);
        if (val == JOptionPane.YES_OPTION) {
            return true;
        } else if (val == JOptionPane.NO_OPTION) {
            return false;
        } else {
            throw new Exception("Operation cancelled.");
        }
    }

    @Override
    public void exportNewEntry(final LogEntry logEntry) {
        if(logEntry.getStatus() == Status.PROCESSED) {
            awaitingExport.add(logEntry);
        }
    }

    @Override
    public void exportUpdatedEntry(final LogEntry updatedEntry) {
        if(updatedEntry.getStatus() == Status.PROCESSED) {
            awaitingExport.add(updatedEntry);
        }
    }

    public void exportEntries(List<LogEntry> entries) {
        try {
            List<LogEntryField> fields = MoreHelp.showFieldChooserDialog(controlPanel, preferences, "CSV Export", this.fields);
            if (fields == null || fields.isEmpty()) return; //Operation cancelled.
            this.fields = fields;
            File file = MoreHelp.getSaveFile("LoggerPlusPlus.csv", "CSV File", "csv");
            final boolean append;
            if (file.exists()) {
                append = CSVExporter.shouldAppendToExistingFile(file, fields);
            }else{
                append = true;
            }

            SwingWorkerWithProgressDialog<Void> importWorker = new SwingWorkerWithProgressDialog<Void>(
                    JOptionPane.getFrameForComponent(this.controlPanel),
                    "CSV Export", "Exporting as CSV...", entries.size()){
                @Override
                protected Void doInBackground() throws Exception {
                    super.doInBackground();
                    try(FileWriter fileWriter = new FileWriter(file, append)) {
                        if(!append) { //If we're not appending to existing file, add the header
                            fileWriter.append(buildHeader(fields));
                            fileWriter.flush();
                        }

                        for (int i = 0; i < entries.size(); i++) {
                            if(this.isCancelled()) break;
                            fileWriter.append("\n");
                            LogEntry entry = entries.get(i);
                            fileWriter.append(CSVExporter.entryToCSVString(entry, fields));
                            fileWriter.flush();
                            publish(i);
                        }
                    }

                    return null;
                }

                @Override
                protected void done() {
                    super.done();
                    JOptionPane.showMessageDialog(controlPanel, "Export as CSV completed.",
                            "CSV Export", JOptionPane.INFORMATION_MESSAGE);
                }
            };

            importWorker.execute();

        }catch (Exception e){
            logger.error(e);
        }
    }

    private static String buildHeader(List<LogEntryField> fields) {
        StringBuilder result = new StringBuilder();

        for (int i = 0; i < fields.size(); i++) {
            if(i != 0) result.append(",");

            result.append(fields.get(i).getFullLabel());
        }

        return result.toString();
    }


    private static String sanitize(String string){
        if(string == null) return null;
        if(string.length() == 0) return "";
        char first = string.toCharArray()[0];
        switch (first){
            case '=':
            case '-':
            case '+':
            case '@': {
                return "'" + string;
            }
        }
        return string;
    }

    private static String entryToCSVString(LogEntry logEntry, List<LogEntryField> fields) {
        StringBuilder result = new StringBuilder();

        for (int i = 0; i < fields.size(); i++) {
            if(i != 0) result.append(",");
            String columnValue = String.valueOf(logEntry.getValueByKey(fields.get(i)));
            result.append(StringEscapeUtils.escapeCsv(sanitize(columnValue)));
        }

        return result.toString();
    }

    public ExportController getExportController() {
        return this.exportController;
    }
}
