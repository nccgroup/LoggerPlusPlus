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

package loggerplusplus.userinterface;

import loggerplusplus.FileLogger;
import loggerplusplus.LoggerPlusPlus;
import loggerplusplus.LoggerPreferences;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.net.URI;

public class LoggerOptionsPanel extends JScrollPane{
    private final LoggerPreferences loggerPreferences;

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
    private JButton btnImport = new JButton("Import from CSV");
    private final JCheckBox chckbxExtender = new JCheckBox("Extender");
    private final JCheckBox chckbxTarget = new JCheckBox("Target");
    private final JLabel lblNewLabel = new JLabel("Note 1: Extensive logging  may affect Burp Suite performance.");
    private final JLabel lblNoteLogging = new JLabel("Note 2: Automatic logging does not save requests and responses. Only table contents. ");
    private final JLabel lblNoteLoggingCont = new JLabel("Full request/response logging available in 'Project Options > Misc > Logging'");
    private final JLabel lblNoteUpdating = new JLabel("Note 3: Updating the extension will reset the log table settings.");
    private final JLabel lblColumnSettings = new JLabel("Column Settings:");
    private final JLabel lblNewLabel_1 = new JLabel("Right click on the columns' headers");
    private final FileLogger fileLogger;
    private final JPanel contentWrapper;


    /**
     * Create the panel.
     */
    public LoggerOptionsPanel() {
        contentWrapper = new JPanel();
        this.setViewportView(contentWrapper);
        this.loggerPreferences = LoggerPlusPlus.getInstance().getLoggerPreferences();
        this.loggerPreferences.setAutoSave(false);
        this.fileLogger = new FileLogger();

        GridBagLayout gridBagLayout = new GridBagLayout();
        gridBagLayout.columnWidths = new int[]{10, 94, 320, 250, 0, 0};
        gridBagLayout.rowHeights = new int[]{0, 43, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 42, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        gridBagLayout.columnWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
        gridBagLayout.rowWeights = new double[]{0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, Double.MIN_VALUE};
        contentWrapper.setLayout(gridBagLayout);

        JLabel lblLoggerStatus = new JLabel("Status:");
        lblLoggerStatus.setFont(new Font("Tahoma", Font.BOLD, 14));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.anchor = GridBagConstraints.SOUTHWEST;
        gbc.insets = new Insets(0, 0, 5, 5);
        gbc.gridx = 1;
        gbc.gridy = 1;
        contentWrapper.add(lblLoggerStatus, gbc);


        tglbtnIsEnabled.setFont(new Font("Tahoma", Font.PLAIN, 13));
        gbc.anchor = GridBagConstraints.SOUTH;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.gridx = 2;
        contentWrapper.add(tglbtnIsEnabled, gbc);


        btnSaveLogsButton.setToolTipText("This does not save requests and responses");
        btnSaveLogsButton.setFont(new Font("Tahoma", Font.PLAIN, 13));
        btnSaveLogsButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                fileLogger.saveLogs(false);
            }
        });
        gbc.gridx = 3;
        contentWrapper.add(btnSaveLogsButton, gbc);

        JLabel lblScopes = new JLabel("Scope:");
        lblScopes.setFont(new Font("Tahoma", Font.BOLD, 14));
        gbc.anchor = GridBagConstraints.WEST;
        gbc.gridx = 1;
        gbc.gridy = 2;
        contentWrapper.add(lblScopes, gbc);

        gbc.gridx = 2;
        contentWrapper.add(chckbxIsRestrictedToScope, gbc);

        //Disabled until implemented
//		contentWrapper.add(chckbxIsLoggingFiltered, gbc);

        gbc.gridy = 2;
        gbc.gridx = 3;
        btnSaveFullLogs.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                fileLogger.saveLogs(true);
            }


        });
        btnSaveFullLogs.setToolTipText("This can be slow and  messy when response is more than 32760 characters - not recommended!");
        btnSaveFullLogs.setFont(new Font("Tahoma", Font.PLAIN, 13));
        contentWrapper.add(btnSaveFullLogs, gbc);

        JLabel updateLabel = new JLabel("Update:");
        updateLabel.setFont(new Font("Tahoma", Font.BOLD, 14));
        gbc.gridx = 1;
        gbc.gridy++;
        contentWrapper.add(updateLabel, gbc);
        gbc.gridx = 2;
        contentWrapper.add(chckbxUpdateOnStartup, gbc);

        gbc.gridx = 3;
        btnAutoSaveLogs.setToolTipText("Automatically save logs as CSV");
        btnAutoSaveLogs.setFont(new Font("Tahoma", Font.PLAIN, 13));
        contentWrapper.add(btnAutoSaveLogs, gbc);


        JLabel lblLogFrom = new JLabel("Log From:");
        lblLogFrom.setFont(new Font("Tahoma", Font.BOLD, 14));
        gbc.gridx = 1;
        gbc.gridy++;
        contentWrapper.add(lblLogFrom, gbc);
        gbc.gridx = 3;
//        btnImport.addActionListener(new ActionListener() {
//            @Override
//            public void actionPerformed(ActionEvent actionEvent) {
//                importFromFile();
//            }
//        });
//        contentWrapper.add(btnImport, gbc);
        gbc.gridx = 2;
        contentWrapper.add(chckbxAllTools, gbc);
        gbc.gridy++;
        contentWrapper.add(chckbxSpider, gbc);
        gbc.gridy++;
        contentWrapper.add(chckbxIntruder, gbc);
        gbc.gridy++;
        contentWrapper.add(chckbxScanner, gbc);
        gbc.gridy++;
        contentWrapper.add(chckbxRepeater, gbc);
        gbc.gridy++;
        contentWrapper.add(chckbxSequencer, gbc);
        gbc.gridy++;
        contentWrapper.add(chckbxProxy, gbc);
        gbc.gridy++;
        contentWrapper.add(chckbxTarget, gbc);
        gbc.gridy++;
        contentWrapper.add(chckbxExtender, gbc);

        gbc.gridx = 1;
        gbc.gridy++;
        JLabel lblResponseSettings = new JLabel("Response Timeout (s):");
        lblResponseSettings.setFont(new Font("Tahoma", Font.BOLD, 14));
        contentWrapper.add(lblResponseSettings, gbc);
        gbc.gridx++;
        final JSpinner spnResponseTimeout = new JSpinner();
        spnResponseTimeout.setModel(new SpinnerNumberModel(LoggerPlusPlus.getInstance().getLoggerPreferences().getResponseTimeout()/1000, 10, 600, 1));
        spnResponseTimeout.addChangeListener(new ChangeListener() {
            @Override
            public void stateChanged(ChangeEvent changeEvent) {
                LoggerPlusPlus.getInstance().getLoggerPreferences().setResponseTimeout(((Integer) spnResponseTimeout.getValue()).longValue()*1000);
            }
        });
        contentWrapper.add(spnResponseTimeout, gbc);

        gbc.gridx++;
        contentWrapper.add(new JLabel("Min: 10 Max: 600"), gbc);

        gbc.gridx = 1;
        gbc.gridy++;
        JLabel lblMaxEntries = new JLabel("Maximum Log Entries:");
        lblMaxEntries.setFont(new Font("Tahoma", Font.BOLD, 14));
        contentWrapper.add(lblMaxEntries, gbc);
        gbc.gridx++;
        final JSpinner spnMaxEntries = new JSpinner();
        int maxEntriesMax = 1000000;
        spnMaxEntries.setModel(new SpinnerNumberModel(Math.min(LoggerPlusPlus.getInstance().getLoggerPreferences().getMaximumEntries(), maxEntriesMax), 10, maxEntriesMax, 10));
        spnMaxEntries.addChangeListener(new ChangeListener() {
            @Override
            public void stateChanged(ChangeEvent changeEvent) {
                LoggerPlusPlus.getInstance().getLoggerPreferences().setMaximumEntries((Integer) spnMaxEntries.getValue());
            }
        });
        spnMaxEntries.getEditor().getComponent(0).addFocusListener(new FocusAdapter() {
            @Override
            public void focusLost(FocusEvent e) {
                super.focusLost(e);
            }
        });

        contentWrapper.add(spnMaxEntries, gbc);

        gbc.gridx++;
        contentWrapper.add(new JLabel("Min: 10 Max: 1,000,000"), gbc);

        gbc.gridx = 1;
        gbc.gridy++;
        JLabel lblSearchThreads = new JLabel("Search Threads:");
        lblSearchThreads.setFont(new Font("Tahoma", Font.BOLD, 14));
        contentWrapper.add(lblSearchThreads, gbc);
        gbc.gridx++;
        int maxSearchThreads = 50;
        final SpinnerNumberModel spnSearchThreadModel = new SpinnerNumberModel(
                Math.min(LoggerPlusPlus.getInstance().getLoggerPreferences().getSearchThreads(), maxSearchThreads), 1, maxSearchThreads, 1);
        final JSpinner spnSearchThreads = new JSpinner(spnSearchThreadModel);
        spnSearchThreads.addChangeListener(new ChangeListener() {
            @Override
            public void stateChanged(ChangeEvent changeEvent) {
                LoggerPlusPlus.getInstance().getLoggerPreferences().setSearchThreads((Integer) spnSearchThreads.getValue());
            }
        });
        contentWrapper.add(spnSearchThreads, gbc);

        gbc.gridx++;
        contentWrapper.add(new JLabel("Min: 1 Max: 50"), gbc);

        JButton btnResetSettings = new JButton("Reset all settings");
        btnResetSettings.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                boolean origState = loggerPreferences.isEnabled();
                loggerPreferences.setEnabled(false);
                loggerPreferences.resetLoggerPreferences();
                LoggerPlusPlus.getInstance().getLogTable().getColumnModel().resetToDefaultVariables();
                LoggerPlusPlus.getInstance().getLogTable().getModel().fireTableStructureChanged();
                fileLogger.setAutoSave(false);
                loggerPreferences.setEnabled(origState);
                setPreferencesValues();
            }

        });
        btnResetSettings.setFont(new Font("Tahoma", Font.PLAIN, 13));
        gbc.anchor = GridBagConstraints.NORTH;
        gbc.gridx = 2;
        gbc.gridy++;
        contentWrapper.add(btnResetSettings, gbc);

        JButton btnClearTheLog = new JButton("Clear the logs");
        btnClearTheLog.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                boolean origState = loggerPreferences.isEnabled();
                loggerPreferences.setEnabled(false);
                LoggerPlusPlus.getInstance().reset();
                LoggerPlusPlus.getInstance().getLogTable().getModel().fireTableDataChanged();
                loggerPreferences.setEnabled(origState);
                setPreferencesValues();
            }
        });
        btnClearTheLog.setFont(new Font("Tahoma", Font.PLAIN, 13));
        gbc.gridx = 3;
        contentWrapper.add(btnClearTheLog, gbc);

        gbc.anchor = GridBagConstraints.WEST;
        gbc.gridx = 1;
        gbc.gridy++;
        lblColumnSettings.setFont(new Font("Tahoma", Font.BOLD, 14));
        contentWrapper.add(lblColumnSettings, gbc);

        gbc.gridx = 2;
        contentWrapper.add(lblNewLabel_1, gbc);

        gbc.gridwidth = 3;
        gbc.gridx = 1;
        gbc.gridy++;gbc.gridy++;
        contentWrapper.add(lblNewLabel, gbc);

        gbc.gridx = 1;
        gbc.gridy++;
        contentWrapper.add(lblNoteLogging, gbc);
        gbc.gridy++;
        contentWrapper.add(lblNoteLoggingCont, gbc);

        gbc.gridx = 1;
        gbc.gridy++;
        contentWrapper.add(lblNoteUpdating, gbc);

        setPreferencesValues();
        setComponentsActions();
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
                toggleEnabledButton(tglbtnIsEnabled.isSelected());
            }
        });

        btnAutoSaveLogs.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                fileLogger.setAutoSave(!loggerPreferences.getAutoSave());
            }
        });
    }

    public void setAutoSaveBtn(boolean enabled){
        btnAutoSaveLogs.setSelected(enabled);
    }

    private void toggleEnabledButton(boolean isSelected) {
        if (tglbtnIsEnabled.equals(this.tglbtnIsEnabled)) {
            tglbtnIsEnabled.setText((isSelected ? "Logger++ is running" : "Logger++ has been stopped"));
            tglbtnIsEnabled.setSelected(isSelected);
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
        toggleEnabledButton(loggerPreferences.isEnabled());

        if (!loggerPreferences.canSaveCSV()) {
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

    public FileLogger getFileLogger() {
        return fileLogger;
    }
}
