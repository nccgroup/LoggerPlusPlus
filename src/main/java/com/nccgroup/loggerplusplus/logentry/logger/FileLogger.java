package com.nccgroup.loggerplusplus.logentry.logger;

import burp.BurpExtender;
import burp.IHttpRequestResponse;
import com.nccgroup.loggerplusplus.*;
import com.nccgroup.loggerplusplus.logentry.LogEntry;
import com.nccgroup.loggerplusplus.logentry.LogEntryField;
import com.nccgroup.loggerplusplus.logview.logtable.LogTable;
import com.nccgroup.loggerplusplus.logview.logtable.LogTableColumn;
import com.nccgroup.loggerplusplus.logview.logtable.LogTableColumnModel;
import com.nccgroup.loggerplusplus.util.Globals;
import com.nccgroup.loggerplusplus.util.MoreHelp;
import org.apache.commons.text.StringEscapeUtils;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.TableColumn;
import java.io.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;

/**
 * Created by corey on 21/08/17.
 */
public class FileLogger {
    //TODO REIMPLEMENT
//    private FileWriter autoSaveWriter;
//    private File autoSaveFile;
//    private final ExcelExporter exp;
//    private boolean autoLogIncludeRequests = false;
//    private boolean autoLogIncludeResponses = false;
//
//    public FileLogger(){
//        exp = new ExcelExporter();
//    }
//
//    public void saveLogs(boolean fullLogs){
//        try {
//            File csvFile = getSaveFile("logger++_table", false);
//            if (csvFile != null) {
//                exp.exportTable(csvFile, fullLogs, false, true);
//            }
//
//        } catch (IOException ex) {
//            LoggerPlusPlus.callbacks.printError(ex.getMessage());
//        }
//    }
//
//    public void autoLogItem(LogEntry entry, boolean includeRequests, boolean includeResponses) {
//        exp.exportItem(entry, includeRequests, includeResponses);
//    }
//
//    // source: https://community.oracle.com/thread/1357495?start=0&tstart=0
//    private File getSaveFile(String filename, boolean allowAppend) {
//        File csvFile = null;
//        JFileChooser chooser = null;
//        FileNameExtensionFilter filter = new FileNameExtensionFilter("Excel Format (CSV)", "csv");
//        chooser = new JFileChooser();
//        chooser.setDialogTitle("Saving Database");
//        chooser.setFileFilter(filter);
//        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
//        chooser.setSelectedFile(new File(filename + ".csv"));
//        chooser.setAcceptAllFileFilterUsed(false);
//
//        int val = chooser.showSaveDialog(null);
//
//        if (val == JFileChooser.APPROVE_OPTION) {
//            csvFile = fixExtension(chooser.getSelectedFile(), "csv");
//            if (csvFile == null) {
//                JOptionPane.showMessageDialog(JOptionPane.getFrameForComponent(BurpExtender.instance.getUiComponent()), "File Name Specified Not Supported",
//                        "File Name Error", JOptionPane.ERROR_MESSAGE);
//                return getSaveFile(filename, allowAppend);
//            }
//
//            try {
//                if (csvFile.exists()) {
//                    if (allowAppend && validHeader(csvFile, false)) {
//                        csvFile = appendOrOverwrite(csvFile);
//                    } else {
//                        csvFile = checkOverwrite(csvFile);
//                    }
//                } else {
//                    csvFile.createNewFile();
//                }
//            } catch (IOException e) {
//                MoreHelp.showMessage("Could not create file. Do you have permissions for the folder?");
//                return null;
//            }
//            return csvFile;
//        }
//
//        return null;
//    }
//
//    //Check if header in file matches that of the columns we will be exporting.
//    private boolean validHeader(File csvFile, boolean isFullLog) {
//        BufferedReader reader;
//        try {
//            reader = new BufferedReader(new FileReader(csvFile));
//        } catch (FileNotFoundException e) {
//            return true;
//        }
//        try {
//            String thisHeader = getCSVHeader(LoggerPlusPlus.instance.getLogTable(), isFullLog);
//            String oldHeader = reader.readLine();
//            return oldHeader == null || oldHeader.equalsIgnoreCase(thisHeader);
//        } catch (IOException e) {
//            return true;
//        }
//    }
//
//    private File fixExtension(File file, String prefExt) {
//        String fileName = file.getName();
//        String dir = file.getParentFile().getAbsolutePath();
//
//        String ext = null;
//
//        try {
//            ext = fileName.substring(fileName.lastIndexOf("."));
//        } catch (StringIndexOutOfBoundsException e) {
//            ext = null;
//        }
//        if (ext != null && !ext.equalsIgnoreCase("." + prefExt)) {
//            return file;
//        }
//
//        String csvName;
//        if (ext == null || ext.length() == 0) {
//            csvName = fileName + "." + prefExt;
//        } else {
//            csvName = fileName.substring(0, fileName.lastIndexOf(".") + 1) + prefExt;
//        }
//
//        File csvCert = new File(dir, csvName);
//
//        return csvCert;
//    }
//
//    private File checkOverwrite(File file) throws IOException {
//        int val = JOptionPane.showConfirmDialog(null, "Replace Existing File?", "File Exists",
//                JOptionPane.YES_NO_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);
//
//        if (val == JOptionPane.NO_OPTION) {
//            return getSaveFile(file.getName(), false);
//        } else if (val == JOptionPane.CANCEL_OPTION) {
//            return null;
//        }
//        file.delete();
//        file.createNewFile();
//        return file;
//    }
//
//    private File appendOrOverwrite(File file) throws IOException {
//        Object[] options = {"Append",
//                "Overwrite", "Cancel"};
//        int val = JOptionPane.showOptionDialog(null,
//                "Append to, or overwrite the existing file?", "File Exists",
//                JOptionPane.YES_NO_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE, null, options, options[0]);
//        if (val == JOptionPane.YES_OPTION) {
//            return file;
//        } else if (val == JOptionPane.NO_OPTION) {
//            file.delete();
//            file.createNewFile();
//            return file;
//        } else {
//            return null;
//        }
//    }
//
//
//    public void setAutoSave(boolean enabled) {
//        if (enabled) {
//            autoSaveFile = getSaveFile("logger++_auto", true);
//            if (autoSaveFile != null) {
//                LoggerPlusPlus.preferences.setSetting(Globals.PREF_AUTO_SAVE, true);
//                try {
//                    autoSaveWriter = new FileWriter(autoSaveFile, true);
//                    int result = JOptionPane.showConfirmDialog(null, "Include REQUEST bodies in the logs?","Automatic Logging", JOptionPane.YES_OPTION);
//                    autoLogIncludeRequests = result == JOptionPane.YES_OPTION;
//
//                    result = JOptionPane.showConfirmDialog(null, "Include RESPONSE bodies in the logs?","Automatic Logging", JOptionPane.YES_OPTION);
//                    autoLogIncludeResponses = result == JOptionPane.YES_OPTION;
//                    if (autoSaveFile.length() == 0)
//                        exp.addHeader(autoSaveWriter, autoLogIncludeRequests, autoLogIncludeResponses);
//
//                    LoggerPlusPlus.instance.getLogProcessor().addLogListener(this);
//
//                } catch (IOException e) {
//                    autoSaveFile = null;
//                    enabled = false;
//                }
//            } else {
//                enabled = false;
//            }
//        } else {
//            autoSaveFile = null;
//            try{
//                autoSaveWriter.close();
//            } catch (Exception e) {}
//            autoSaveWriter = null;
//            LoggerPlusPlus.instance.getLogProcessor().removeLogListener(this);
//        }
//        LoggerPlusPlus.preferences.setSetting(Globals.PREF_AUTO_SAVE, enabled);
//        LoggerPlusPlus.instance.getLoggerOptionsPanel().setAutoSaveBtn(enabled);
//    }
//
//    @Override
//    public void onRequestAdded(int modelIndex, final LogEntry logEntry, boolean hasResponse) {
//        if(!hasResponse) return;
//        Thread saveThread = new Thread(){
//            @Override
//            public void run() {
//                synchronized (autoSaveWriter){
//                    autoLogItem(logEntry, autoLogIncludeRequests, autoLogIncludeResponses);
//                }
//            }
//        };
//        saveThread.start();
//    }
//
//    @Override
//    public void onResponseUpdated(int modelRow, final LogEntry existingEntry) {
//        Thread saveThread = new Thread(){
//            @Override
//            public void run() {
//                synchronized (autoSaveWriter){
//                    autoLogItem(existingEntry, autoLogIncludeRequests, autoLogIncludeResponses);
//                }
//            }
//        };
//        saveThread.start();
//    }
//
//    @Override
//    public void onRequestRemoved(int modelIndex, LogEntry logEntry) {
//
//    }
//
//    @Override
//    public void onLogsCleared() {
//
//    }
//
//    // source: http://book.javanb.com/swing-hacks/swinghacks-chp-3-sect-6.html
//    public class ExcelExporter {
//
//        public void addHeader(FileWriter writer, boolean isFullLog) throws IOException {
//            writer.write(getCSVHeader(LoggerPlusPlus.instance.getLogTable(), isFullLog) + "\n");
//        }
//
//        public void addHeader(FileWriter writer, boolean includeRequest, boolean includeResponse) throws IOException {
//            writer.write(getCSVHeader(LoggerPlusPlus.instance.getLogTable(), includeRequest, includeResponse) + "\n");
//        }
//
//        public void exportTable(File file, boolean isFullLog, boolean append, boolean header) throws IOException {
//            FileWriter out = new FileWriter(file, append);
//
//            if (header) {
//                out.write(getCSVHeader(LoggerPlusPlus.instance.getLogTable(), isFullLog));
//                out.write("\n");
//            }
//
//            for (LogEntry item : LoggerPlusPlus.instance.getLogProcessor().getLogEntries()) {
//                out.write(entryToCSVString(item, isFullLog) + "\n");
//            }
//
//            out.close();
//            MoreHelp.showMessage("Log saved to " + file.getAbsolutePath());
//        }
//
//        public void exportItem(LogEntry logEntry, boolean includeRequests, boolean includeResponses) {
//            if(autoSaveWriter != null) {
//                try {
//                    autoSaveWriter.write(entryToCSVString(logEntry, includeRequests, includeResponses));
//                    autoSaveWriter.write("\n");
//                    autoSaveWriter.flush();
//                } catch (Exception e) {
//                    MoreHelp.showMessage("Could not save log. Automatic logging will be disabled.");
//                    setAutoSave(false);
//                }
//            }else{
//                MoreHelp.showMessage("Could not save log. Automatic logging will be disabled.");
//                setAutoSave(false);
//            }
//        }
//
//    }
//
//    public static String getCSVHeader(LogTable table, boolean isFullLog) {
//        return getCSVHeader(table, isFullLog, isFullLog);
//    }
//
//    public static String getCSVHeader(LogTable table, boolean includeRequest, boolean includeResponse) {
//        StringBuilder result = new StringBuilder();
//
//        boolean firstDone = false;
//        ArrayList<LogTableColumn> columns = new ArrayList<>();
//        Enumeration<TableColumn> columnEnumeration = table.getColumnModel().getColumns();
//        while(columnEnumeration.hasMoreElements()){
//            columns.add((LogTableColumn) columnEnumeration.nextElement());
//        }
//
//        columns.remove(table.getColumnModel().getColumnByIdentifier(LogEntryField.NUMBER));
//
//        Collections.sort(columns);
//        for (LogTableColumn logTableColumn : columns) {
//            if(logTableColumn.isVisible()) {
//                if(firstDone) {
//                    result.append(",");
//                }else{
//                    firstDone = true;
//                }
//                result.append(logTableColumn.getName());
//            }
//        }
//
//        if(includeRequest) {
//            result.append(",");
//            result.append("Request");
//        }
//        if(includeResponse) {
//            result.append(",");
//            result.append("Response");
//        }
//        return result.toString();
//    }
//
//
//    public String entryToCSVString(LogEntry logEntry, boolean isFullLog) {
//        return entryToCSVString(logEntry, isFullLog, isFullLog);
//    }
//
//    private String sanitize(String string){
//        if(string == null) return null;
//        if(string.length() == 0) return "";
//        char first = string.toCharArray()[0];
//        switch (first){
//            case '=':
//            case '-':
//            case '+':
//            case '@': {
//                return "'" + string;
//            }
//        }
//        return string;
//    }
//
//    public String entryToCSVString(LogEntry logEntry, boolean includeRequests, boolean includeResponses) {
//        StringBuilder result = new StringBuilder();
//
//        LogTableColumnModel columnModel = LoggerPlusPlus.instance.getLogTable().getColumnModel();
//        ArrayList<LogTableColumn> columns = new ArrayList<>();
//        Enumeration<TableColumn> columnEnumeration = columnModel.getColumns();
//        while(columnEnumeration.hasMoreElements()){
//            columns.add((LogTableColumn) columnEnumeration.nextElement());
//        }
//
//        columns.remove(columnModel.getColumnByIdentifier(LogEntryField.NUMBER));
//
//        Collections.sort(columns);
//        boolean firstDone = false;
//        for (LogTableColumn logTableColumn : columns) {
//            if(logTableColumn.isVisible() && logTableColumn.getIdentifier() != LogEntryField.NUMBER){
//                if(firstDone){
//                    result.append(",");
//                }else{
//                    firstDone = true;
//                }
//                String columnValue = String.valueOf(logEntry.getValueByKey(logTableColumn.getIdentifier()));
//
//                result.append(StringEscapeUtils.escapeCsv(sanitize(columnValue)));
//            }
//        }
//
//        IHttpRequestResponse requestResponse = logEntry.getRequestResponse();
//        if(includeRequests) {
//
//            result.append(",");
//            if (requestResponse != null && requestResponse.getRequest() != null)
//                result.append(StringEscapeUtils.escapeCsv(sanitize(new String(requestResponse.getRequest()))));
//        }
//        if(includeResponses) {
//            result.append(",");
//            if(requestResponse != null && requestResponse.getResponse() != null)
//                result.append(StringEscapeUtils.escapeCsv(sanitize(new String(requestResponse.getResponse()))));
//        }
//        return result.toString();
//    }

}
