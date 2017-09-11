package loggerplusplus;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.io.*;

/**
 * Created by corey on 21/08/17.
 */
public class FileLogger implements LogEntryListener{
    private FileWriter autoSaveWriter;
    private File autoSaveFile;
    private final LoggerPreferences loggerPreferences;
    private final ExcelExporter exp;

    public FileLogger(){
        loggerPreferences = LoggerPlusPlus.getInstance().getLoggerPreferences();
        exp = new ExcelExporter();
    }

    public void saveLogs(boolean fullLogs){
        try {
            File csvFile = getSaveFile("logger++_table", false);
            if (csvFile != null) {
                exp.exportTable(csvFile, fullLogs, false, true);
            }

        } catch (IOException ex) {
            LoggerPlusPlus.getCallbacks().printError(ex.getMessage());
        }
    }

    public void autoLogItem(LogEntry entry) {
        try {
            exp.exportItem(entry, false);
        } catch (IOException e) {
            LoggerPlusPlus.getCallbacks().printError("Could not write log item. Autologging has been disabled.");
            MoreHelp.showMessage("Could not write to automatic log file. Automatic logging will be disabled.");
            this.setAutoSave(false);
        }
    }

    // source: https://community.oracle.com/thread/1357495?start=0&tstart=0
    private File getSaveFile(String filename, boolean allowAppend) {
        File csvFile = null;
        JFileChooser chooser = null;
        FileNameExtensionFilter filter = new FileNameExtensionFilter("Excel Format (CSV)", "csv");
        chooser = new JFileChooser();
        chooser.setDialogTitle("Saving Database");
        chooser.setFileFilter(filter);
        chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
        chooser.setSelectedFile(new File(filename + ".csv"));
        chooser.setAcceptAllFileFilterUsed(false);

        int val = chooser.showSaveDialog(null);

        if (val == JFileChooser.APPROVE_OPTION) {
            csvFile = fixExtension(chooser.getSelectedFile(), "csv");
            if (csvFile == null) {
                JOptionPane.showMessageDialog(null, "File Name Specified Not Supported",
                        "File Name Error", JOptionPane.ERROR_MESSAGE);
                return getSaveFile(filename, allowAppend);
            }

            try {
                if (csvFile.exists()) {
                    if (allowAppend && validHeader(csvFile, false)) {
                        csvFile = appendOrOverwrite(csvFile);
                    } else {
                        csvFile = checkOverwrite(csvFile);
                    }
                } else {
                    csvFile.createNewFile();
                }
            } catch (IOException e) {
                MoreHelp.showMessage("Could not create file. Do you have permissions for the folder?");
                return null;
            }
            return csvFile;
        }

        return null;
    }

    //Check if header in file matches that of the columns we will be exporting.
    private boolean validHeader(File csvFile, boolean isFullLog) {
        BufferedReader reader;
        try {
            reader = new BufferedReader(new FileReader(csvFile));
        } catch (FileNotFoundException e) {
            return true;
        }
        try {
            String thisHeader = LogEntry.getCSVHeader(LoggerPlusPlus.getInstance().getLogTable(), isFullLog);
            String oldHeader = reader.readLine();
            return oldHeader == null || oldHeader.equalsIgnoreCase(thisHeader);
        } catch (IOException e) {
            return true;
        }
    }

    private File fixExtension(File file, String prefExt) {
        String fileName = file.getName();
        String dir = file.getParentFile().getAbsolutePath();

        String ext = null;

        try {
            ext = fileName.substring(fileName.lastIndexOf("."), fileName.length());
        } catch (StringIndexOutOfBoundsException e) {
            ext = null;
        }
        if (ext != null && !ext.equalsIgnoreCase("." + prefExt)) {
            return file;
        }

        String csvName;
        if (ext == null || ext.length() == 0) {
            csvName = fileName + "." + prefExt;
        } else {
            csvName = fileName.substring(0, fileName.lastIndexOf(".") + 1) + prefExt;
        }

        File csvCert = new File(dir, csvName);

        return csvCert;
    }

    private File checkOverwrite(File file) throws IOException {
        int val = JOptionPane.showConfirmDialog(null, "Replace Existing File?", "File Exists",
                JOptionPane.YES_NO_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE);

        if (val == JOptionPane.NO_OPTION) {
            return getSaveFile(file.getName(), false);
        } else if (val == JOptionPane.CANCEL_OPTION) {
            return null;
        }
        file.delete();
        file.createNewFile();
        return file;
    }

    private File appendOrOverwrite(File file) throws IOException {
        Object[] options = {"Append",
                "Overwrite", "Cancel"};
        int val = JOptionPane.showOptionDialog(null,
                "Append to, or overwrite the existing file?", "File Exists",
                JOptionPane.YES_NO_CANCEL_OPTION, JOptionPane.WARNING_MESSAGE, null, options, options[0]);
        if (val == JOptionPane.YES_OPTION) {
            return file;
        } else if (val == JOptionPane.NO_OPTION) {
            file.delete();
            file.createNewFile();
            return file;
        } else {
            return null;
        }
    }


    public void setAutoSave(boolean enabled) {
        if (enabled) {
            autoSaveFile = getSaveFile("logger++_auto", true);
            if (autoSaveFile != null) {
                loggerPreferences.setAutoSave(true);
                try {
                    autoSaveWriter = new FileWriter(autoSaveFile, true);
                    if (autoSaveFile.length() == 0)
                        exp.addHeader(autoSaveWriter, false);

                    LoggerPlusPlus.getInstance().getLogManager().addLogListener(this);

                } catch (IOException e) {
                    autoSaveFile = null;
                    enabled = false;
                }
            } else {
                enabled = false;
            }
        } else {
            autoSaveFile = null;
            try{
                autoSaveWriter.close();
            } catch (Exception e) {}
            autoSaveWriter = null;
            LoggerPlusPlus.getInstance().getLogManager().removeLogListener(this);
        }
        loggerPreferences.setAutoSave(enabled);
        LoggerPlusPlus.getInstance().getLoggerOptionsPanel().setAutoSaveBtn(enabled);
    }

    @Override
    public void onRequestAdded(final LogEntry logEntry) {

    }

    @Override
    public void onResponseUpdated(final LogEntry.PendingRequestEntry existingEntry) {
        Thread saveThread = new Thread(){
            @Override
            public void run() {
                synchronized (autoSaveWriter){
                    autoLogItem(existingEntry);
                }
            }
        };
        saveThread.start();
    }

    @Override
    public void onRequestRemoved(int index, LogEntry logEntry) {

    }


    // source: http://book.javanb.com/swing-hacks/swinghacks-chp-3-sect-6.html
    public class ExcelExporter {

        public void addHeader(FileWriter writer, boolean isFullLog) throws IOException {
            writer.write(LogEntry.getCSVHeader(LoggerPlusPlus.getInstance().getLogTable(), isFullLog) + "\n");
        }

        public void exportTable(File file, boolean isFullLog, boolean append, boolean header) throws IOException {
            FileWriter out = new FileWriter(file, append);

            if (header) {
                out.write(LogEntry.getCSVHeader(LoggerPlusPlus.getInstance().getLogTable(), isFullLog));
                out.write("\n");
            }

            for (LogEntry item : LoggerPlusPlus.getInstance().getLogManager().getLogEntries()) {
                out.write(item.toCSVString(isFullLog) + "\n");
            }

            out.close();
            MoreHelp.showMessage("Log saved to " + file.getAbsolutePath() + file.getName());
        }

        public void exportItem(LogEntry logEntry, boolean isFullLog) throws IOException {
            if(autoSaveWriter != null) {
                try {
                    autoSaveWriter.write(logEntry.toCSVString(isFullLog));
                    autoSaveWriter.write("\n");
                    autoSaveWriter.flush();
                } catch (Exception e) {
                    MoreHelp.showMessage("Could not save log. Automatic logging will be disabled.");
                    setAutoSave(false);
                }
            }else{
                MoreHelp.showMessage("Could not save log. Automatic logging will be disabled.");
                setAutoSave(false);
            }
        }

    }

}
