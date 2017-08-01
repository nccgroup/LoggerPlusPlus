//
// Burp Suite Logger++
// 
// Released as open source by NCC Group Plc - https://www.nccgroup.trust/
// 
// Developed by Soroush Dalili (@irsdl)
//
// Project link: http://www.github.com/nccgroup/BurpSuiteLoggerPlusPlus
//
// Released under AGPL see LICENSE for more information
//

package burp;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.filechooser.FileNameExtensionFilter;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ComponentEvent;
import java.awt.event.ComponentListener;
import java.io.*;
import java.net.URI;
import java.util.List;

public class LoggerOptionsPanel extends JPanel{


    private final burp.IBurpExtenderCallbacks callbacks;
    private final PrintWriter stdout;
    private final PrintWriter stderr;
    private File autoSaveCSVFile;
    private boolean canSaveCSV;
    private final LoggerPreferences loggerPreferences;
    private final ExcelExporter exp = new ExcelExporter();

    private JToggleButton tglbtnIsEnabled = new JToggleButton("Logger++ is running");
    private JCheckBox chckbxIsRestrictedToScope = new JCheckBox("In scope items only");
    private JCheckBox chckbxIsLoggingFiltered = new JCheckBox("Store logs only if matches filter");
    private JCheckBox chckbxUpdateOnStartup = new JCheckBox("Check for updates on startup.");
    private JCheckBox chckbxAllTools = new JCheckBox("All Tools");
    private JCheckBox chckbxSpider = new JCheckBox("Spider");
    private JCheckBox chckbxIntruder = new JCheckBox("Intruder");
    private JCheckBox chckbxScanner = new JCheckBox("Scanner");
    private JCheckBox chckbxRepeater = new JCheckBox("Repeater");
    private JCheckBox chckbxSequencer = new JCheckBox("Sequencer");
    private JCheckBox chckbxProxy = new JCheckBox("Proxy");
    private JButton btnSaveLogsButton = new JButton("Save log table as CSV");
    private JButton btnSaveFullLogs = new JButton("Save full logs as CSV (slow)");
    private JToggleButton btnAutoSaveLogs = new JToggleButton("Autosave as CSV");
    private final JCheckBox chckbxExtender = new JCheckBox("Extender");
    private final JCheckBox chckbxTarget = new JCheckBox("Target");
    private final JLabel lblNewLabel = new JLabel("Note 1: Extensive logging  may affect Burp Suite performance.");
    private final JLabel lblNoteLogging = new JLabel("Note 2: Automatic logging does not save requests and responses. Only table contents. ");
    private final JLabel lblNoteLoggingCont = new JLabel("Full request/response logging available in 'Project Options > Misc > Logging'");
    private final JLabel lblNoteUpdating = new JLabel("Note 3: Updating the extension will reset the table settings.");
    private final JLabel lblColumnSettings = new JLabel("Column Settings:");
    private final JLabel lblNewLabel_1 = new JLabel("Right click on the columns' headers");
    private final List<LogEntry> log;

    private final boolean isDebug;

    /**
     * Create the panel.
     */
    public LoggerOptionsPanel(final IBurpExtenderCallbacks callbacks, final PrintWriter stdout, final PrintWriter stderr, final List<LogEntry> log, boolean canSaveCSV, final LoggerPreferences loggerPreferences, boolean isDebug) {
        this.callbacks = callbacks;
        this.stdout = stdout;
        this.stderr = stderr;
        this.canSaveCSV = canSaveCSV;
        this.loggerPreferences = loggerPreferences;
        this.loggerPreferences.setAutoSave(false);
        this.isDebug = isDebug;
        this.log = log;

        GridBagLayout gridBagLayout = new GridBagLayout();
        gridBagLayout.columnWidths = new int[]{53, 94, 320, 250, 0, 0};
        gridBagLayout.rowHeights = new int[]{0, 43, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 42, 0, 0, 0, 0, 0, 0, 0};
        gridBagLayout.columnWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
        gridBagLayout.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
        setLayout(gridBagLayout);

        JLabel lblLoggerStatus = new JLabel("Status:");
        lblLoggerStatus.setFont(new Font("Tahoma", Font.BOLD, 14));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.SOUTHWEST;
        gbc.insets = new Insets(0, 0, 5, 5);
        gbc.gridx = 1;
        gbc.gridy = 1;
        add(lblLoggerStatus, gbc);


        tglbtnIsEnabled.setFont(new Font("Tahoma", Font.PLAIN, 13));
        gbc.anchor = GridBagConstraints.SOUTH;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.gridx = 2;
        add(tglbtnIsEnabled, gbc);


        btnSaveLogsButton.setToolTipText("This does not save requests and responses");
        btnSaveLogsButton.setFont(new Font("Tahoma", Font.PLAIN, 13));
        btnSaveLogsButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                try {
                    File csvFile = getSaveFile("logger++_table", false);
                    if (csvFile != null) {
                        exp.exportTable(log, csvFile, false, false, true);
                    }

                } catch (IOException ex) {
                    stderr.println(ex.getMessage());
                    ex.printStackTrace();
                }
            }
        });
        gbc.gridx = 3;
        add(btnSaveLogsButton, gbc);

        JLabel lblScopes = new JLabel("Scope:");
        lblScopes.setFont(new Font("Tahoma", Font.BOLD, 14));
        gbc.anchor = GridBagConstraints.WEST;
        gbc.gridx = 1;
        gbc.gridy = 2;
        add(lblScopes, gbc);

        gbc.gridx = 2;
        add(chckbxIsRestrictedToScope, gbc);

        //Disabled until implemented
//		add(chckbxIsLoggingFiltered, gbc);

        gbc.gridy = 2;
        gbc.gridx = 3;
        btnSaveFullLogs.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                try {
                    File csvFile = getSaveFile("logger++_full", false);
                    if (csvFile != null) {
                        exp.exportTable(log, csvFile, true, false, true);
                    }

                } catch (IOException ex) {
                    stderr.println(ex.getMessage());
                    ex.printStackTrace();

                }
            }


        });
        btnSaveFullLogs.setToolTipText("This can be slow and  messy when response is more than 32760 characters - not recommended!");
        btnSaveFullLogs.setFont(new Font("Tahoma", Font.PLAIN, 13));
        add(btnSaveFullLogs, gbc);

        JLabel updateLabel = new JLabel("Update:");
        updateLabel.setFont(new Font("Tahoma", Font.BOLD, 14));
        gbc.gridx = 1;
        gbc.gridy++;
        add(updateLabel, gbc);
        gbc.gridx = 2;
        add(chckbxUpdateOnStartup, gbc);

        gbc.gridx = 3;
        btnAutoSaveLogs.setToolTipText("Automatically save logs as CSV");
        btnAutoSaveLogs.setFont(new Font("Tahoma", Font.PLAIN, 13));
        add(btnAutoSaveLogs, gbc);


        JLabel lblLogFrom = new JLabel("Log From:");
        lblLogFrom.setFont(new Font("Tahoma", Font.BOLD, 14));
        gbc.gridx = 1;
        gbc.gridy++;
        add(lblLogFrom, gbc);
        gbc.gridx = 2;
        add(chckbxAllTools, gbc);
        gbc.gridy++;
        add(chckbxSpider, gbc);
        gbc.gridy++;
        add(chckbxIntruder, gbc);
        gbc.gridy++;
        add(chckbxScanner, gbc);
        gbc.gridy++;
        add(chckbxRepeater, gbc);
        gbc.gridy++;
        add(chckbxSequencer, gbc);
        gbc.gridy++;
        add(chckbxProxy, gbc);
        gbc.gridy++;
        add(chckbxTarget, gbc);
        gbc.gridy++;
        add(chckbxExtender, gbc);

        JButton btnResetSettings = new JButton("Reset all settings");
        btnResetSettings.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                boolean origState = loggerPreferences.isEnabled();
                loggerPreferences.setEnabled(false);
                loggerPreferences.resetLoggerPreferences();
                BurpExtender.getInstance().getLogTable().getColumnModel().resetToDefaultVariables();
                BurpExtender.getInstance().getLogTable().getModel().fireTableStructureChanged();
                loggerPreferences.setEnabled(origState);
                setPreferencesValues();
            }

        });
        btnResetSettings.setFont(new Font("Tahoma", Font.PLAIN, 13));
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.gridy++;
        add(btnResetSettings, gbc);

        JButton btnClearTheLog = new JButton("Clear the logs");
        btnClearTheLog.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                //BurpExtender.logTableReset();
                boolean origState = loggerPreferences.isEnabled();
                loggerPreferences.setEnabled(false);

                log.clear();

                BurpExtender.getInstance().getLogTable().getModel().fireTableDataChanged();
                loggerPreferences.setEnabled(origState);
                setPreferencesValues();
            }
        });
        btnClearTheLog.setFont(new Font("Tahoma", Font.PLAIN, 13));
        gbc.gridx = 3;
        add(btnClearTheLog, gbc);

        gbc.anchor = GridBagConstraints.WEST;
        gbc.gridx = 1;
        gbc.gridy++;
        lblColumnSettings.setFont(new Font("Tahoma", Font.BOLD, 14));
        add(lblColumnSettings, gbc);

        gbc.gridx = 2;
        add(lblNewLabel_1, gbc);

        gbc.gridwidth = 3;
        gbc.gridx = 1;
        gbc.gridy++;
        add(lblNewLabel, gbc);

        gbc.gridx = 1;
        gbc.gridy++;
        add(lblNoteLogging, gbc);
        gbc.gridy++;
        add(lblNoteLoggingCont, gbc);

        gbc.gridx = 1;
        gbc.gridy++;
        add(lblNoteUpdating, gbc);

        setPreferencesValues();
        setComponentsActions();
    }

    public void autoLogItem(LogEntry entry) {
        try {
            exp.exportItem(entry, false, true);
        } catch (IOException e) {
            stderr.write("Could not write log item. Autologging has been disabled.");
            MoreHelp.showMessage("Could not write to automatic log file. Automatic logging will be disabled.");
            this.autoSaveCSVFile = null;
            this.loggerPreferences.setAutoSave(false);
        }
    }


    // source: http://book.javanb.com/swing-hacks/swinghacks-chp-3-sect-6.html
    public class ExcelExporter {

        public void addHeader(File file, boolean isFullLog) throws IOException {
            FileWriter out = new FileWriter(file, true);
            out.write(LogEntry.getCSVHeader(BurpExtender.getInstance().getLogTable(), isFullLog));
            out.write("\n");
            out.close();
        }

        public void exportTable(List<LogEntry> log, File file, boolean isFullLog, boolean append, boolean header) throws IOException {

            FileWriter out = new FileWriter(file, append);

            boolean includeHeader = header;

            for (LogEntry item : log) {
                if (includeHeader) {
                    out.write(LogEntry.getCSVHeader(BurpExtender.getInstance().getLogTable(), isFullLog));
                    out.write("\n");
                    includeHeader = false;
                }
                out.write(item.toCSVString(isFullLog));

                out.write("\n");
            }

            out.close();
            MoreHelp.showMessage("Log saved to " + file.getAbsolutePath() + file.getName());
        }

        public void exportItem(LogEntry logEntry, boolean isFullLog, boolean append) throws IOException {
            FileWriter autoSaveWriter = null;
            try {
                autoSaveWriter = new FileWriter(autoSaveCSVFile, append);
                autoSaveWriter.write(logEntry.toCSVString(isFullLog));
                autoSaveWriter.write("\n");
            }catch (Exception e){
                MoreHelp.showMessage("Could not save log. Automatic logging will be disabled.");
                loggerPreferences.setAutoSave(false);
            }finally {
                if(autoSaveWriter != null) {
                    autoSaveWriter.close();
                }
            }
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

        int val = chooser.showSaveDialog((Component) null);

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
    //TODO
    private boolean validHeader(File csvFile, boolean isFullLog) {
        BufferedReader reader;
        try {
            reader = new BufferedReader(new FileReader(csvFile));
        } catch (FileNotFoundException e) {
            return true;
        }
        try {
            String thisHeader = LogEntry.getCSVHeader(BurpExtender.getInstance().getLogTable(), isFullLog);
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
            stdout.println("Original File Extension: " + ext);
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

        stdout.println("Corrected File Name: " + csvName);

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


    private void setComponentsActions() {
        chckbxIsRestrictedToScope.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                loggerPreferences.setRestrictedToScope(chckbxIsRestrictedToScope.isSelected());
            }
        });

        chckbxIsLoggingFiltered.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                loggerPreferences.setLoggingFiltered(chckbxIsLoggingFiltered.isSelected());
            }
        });

        chckbxUpdateOnStartup.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                loggerPreferences.setUpdateOnStartup(chckbxUpdateOnStartup.isSelected());
            }
        });

        chckbxAllTools.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                loggerPreferences.setEnabled4All(chckbxAllTools.isSelected());
            }
        });

        chckbxSpider.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                loggerPreferences.setEnabled4Spider(chckbxSpider.isSelected());
            }
        });

        chckbxIntruder.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                loggerPreferences.setEnabled4Intruder(chckbxIntruder.isSelected());
            }
        });

        chckbxScanner.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                loggerPreferences.setEnabled4Scanner(chckbxScanner.isSelected());
            }
        });

        chckbxRepeater.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                loggerPreferences.setEnabled4Repeater(chckbxRepeater.isSelected());
            }
        });

        chckbxSequencer.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                loggerPreferences.setEnabled4Sequencer(chckbxSequencer.isSelected());
            }
        });

        chckbxProxy.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                loggerPreferences.setEnabled4Proxy(chckbxProxy.isSelected());
            }
        });

        chckbxExtender.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                loggerPreferences.setEnabled4Extender(chckbxExtender.isSelected());
            }
        });

        chckbxTarget.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                loggerPreferences.setEnabled4TargetTab(chckbxTarget.isSelected());
            }
        });

        tglbtnIsEnabled.addChangeListener(new ChangeListener() {
            public void stateChanged(ChangeEvent arg0) {
                toggleButtonAction(tglbtnIsEnabled, tglbtnIsEnabled.isSelected());
            }
        });

        btnAutoSaveLogs.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                setAutoSave(!loggerPreferences.getAutoSave());
            }
        });
    }

    public void setAutoSaveBtn(boolean enabled){
        btnAutoSaveLogs.setSelected(enabled);
    }

    private void setAutoSave(boolean enabled) {
        if (enabled) {
            autoSaveCSVFile = getSaveFile("logger++_auto", true);
            if (autoSaveCSVFile != null) {
                loggerPreferences.setAutoSave(true);
                if (autoSaveCSVFile.length() == 0) {
                    try {
                        exp.addHeader(autoSaveCSVFile, false);
                    } catch (IOException ioException) {
                        enabled = false;
                        autoSaveCSVFile = null;
                    }
                }
            } else {
                enabled = false;
            }
        } else {
            autoSaveCSVFile = null;
        }
        loggerPreferences.setAutoSave(enabled);
        btnAutoSaveLogs.setSelected(enabled);
    }

    private void toggleButtonAction(JToggleButton targetToggleBtn, boolean isSelected) {
        if (targetToggleBtn.equals(tglbtnIsEnabled)) {
            targetToggleBtn.setText((isSelected ? "Logger++ is running" : "Logger++ has been stopped"));
            targetToggleBtn.setSelected(isSelected);
            loggerPreferences.setEnabled(isSelected);
        }
    }


    private void setPreferencesValues() {

        chckbxIsRestrictedToScope.setSelected(loggerPreferences.isRestrictedToScope());
        chckbxUpdateOnStartup.setSelected(loggerPreferences.checkUpdatesOnStartup());
        chckbxAllTools.setSelected(loggerPreferences.isEnabled4All());
        chckbxSpider.setSelected(loggerPreferences.isEnabled4Spider());
        chckbxIntruder.setSelected(loggerPreferences.isEnabled4Intruder());
        chckbxScanner.setSelected(loggerPreferences.isEnabled4Scanner());
        chckbxRepeater.setSelected(loggerPreferences.isEnabled4Repeater());
        chckbxSequencer.setSelected(loggerPreferences.isEnabled4Sequencer());
        chckbxProxy.setSelected(loggerPreferences.isEnabled4Proxy());
        chckbxExtender.setSelected(loggerPreferences.isEnabled4Extender());
        chckbxTarget.setSelected(loggerPreferences.isEnabled4TargetTab());

        toggleButtonAction(tglbtnIsEnabled, loggerPreferences.isEnabled());

        if (!canSaveCSV) {
            btnSaveLogsButton.setEnabled(false);
            btnSaveFullLogs.setEnabled(false);
            btnAutoSaveLogs.setEnabled(false);
            btnSaveLogsButton.setToolTipText("Please look at the extension's error tab.");
            btnSaveFullLogs.setToolTipText("Please look at the extension's error tab.");
            btnAutoSaveLogs.setToolTipText("Please look at the extension's error tab.");
        }
    }

    public static void openWebpage(URI uri) {
        Desktop desktop = Desktop.isDesktopSupported() ? Desktop.getDesktop() : null;
        if (desktop != null && desktop.isSupported(Desktop.Action.BROWSE)) {
            try {
                desktop.browse(uri);
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }
}
