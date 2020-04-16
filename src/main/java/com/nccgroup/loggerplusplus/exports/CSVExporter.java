package com.nccgroup.loggerplusplus.exports;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.loggerplusplus.logentry.LogEntry;
import com.nccgroup.loggerplusplus.logentry.LogEntryField;
import com.nccgroup.loggerplusplus.logentry.Status;
import com.nccgroup.loggerplusplus.util.FieldSelectorDialog;
import com.nccgroup.loggerplusplus.util.Globals;
import org.apache.commons.text.StringEscapeUtils;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.io.*;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * Created by corey on 21/08/17.
 */
public class CSVExporter extends LogExporter {

    private final CSVExporterControlPanel controlPanel;

    private FileWriter autoSaveWriter;
    private File autoSaveFile;
    private List<LogEntryField> fields;
    private Thread exporterThread;
    private LinkedBlockingQueue<LogEntry> awaitingExport;


    public CSVExporter(ExportController exportController, Preferences preferences){
        super(exportController, preferences);
        this.fields = preferences.getSetting(Globals.PREF_PREVIOUS_CSV_FIELDS);
        this.controlPanel = new CSVExporterControlPanel(this);
    }

    @Override
    public void setup() throws Exception {
        fields = showFieldChooserDialog();
        autoSaveFile = getSaveFile("LoggerPlusPlus_Autosave.csv");
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


    public List<LogEntryField> showFieldChooserDialog() throws Exception {
        //TODO Display dialog using previously used fields as default
        FieldSelectorDialog fieldSelectorDialog = new FieldSelectorDialog(JOptionPane.getFrameForComponent(this.controlPanel), "CSV Export", fields);
        fieldSelectorDialog.setVisible(true);

        List<LogEntryField> selectedFields = fieldSelectorDialog.getSelectedFields();
        if(selectedFields == null || selectedFields.isEmpty()) throw new Exception("Operation cancelled.");

        preferences.setSetting(Globals.PREF_PREVIOUS_CSV_FIELDS, fields);

        return selectedFields;
    }

    static File getSaveFile(String filename) throws Exception {
        JFileChooser chooser = null;
        FileNameExtensionFilter filter = new FileNameExtensionFilter("Excel Format (CSV)", "csv");

        chooser = new JFileChooser();
        chooser.setDialogTitle("Saving Logger++ Entries");
        chooser.setFileFilter(filter);
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        chooser.setSelectedFile(new File(filename));
        chooser.setAcceptAllFileFilterUsed(false);

        int val = chooser.showSaveDialog(null);

        if (val == JFileChooser.APPROVE_OPTION) {
            return chooser.getSelectedFile();
        }

        throw new Exception("Operation cancelled.");
    }

    static boolean shouldAppendToExistingFile(File file, List<LogEntryField> fields) throws Exception{
        if (validHeader(file, fields)) {
            //The existing file uses the same field set.
            // We can ask the user if they want to append the entries or overwrite
            //True = append, false = overwrite.
            return promptAppendToExistingFileDialog();
        } else {
            //Prompt the user if they wish to overwrite
            if(shouldOverwriteExistingFilePrompt()){
                return false; //i.e. Do not append
            }else{
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

    private static boolean shouldOverwriteExistingFilePrompt() throws Exception {
        int val = JOptionPane.showConfirmDialog(null, "Replace Existing File?", "File Exists",
                JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);

        if (val == JOptionPane.YES_OPTION) {
            return true;
        } else {
            return false;
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

    public static String buildHeader(List<LogEntryField> fields) {
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

    public static String entryToCSVString(LogEntry logEntry, List<LogEntryField> fields) {
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
