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

import burp.IHttpRequestResponse;
import loggerplusplus.FileLogger;
import loggerplusplus.LoggerPlusPlus;
import loggerplusplus.LoggerPreferences;
import loggerplusplus.MoreHelp;

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
    private JCheckBox chkIsRestrictedToScope = new JCheckBox("In scope items only");
    private JCheckBox chkUpdateOnStartup = new JCheckBox();
    private JCheckBox chkAutoImport = new JCheckBox("Auto import proxy history on startup.");
    private JCheckBox chkAllTools = new JCheckBox("All Tools");
    private JCheckBox chkSpider = new JCheckBox("Spider");
    private JCheckBox chkIntruder = new JCheckBox("Intruder");
    private JCheckBox chkScanner = new JCheckBox("Scanner");
    private JCheckBox chkRepeater = new JCheckBox("Repeater");
    private JCheckBox chkSequencer = new JCheckBox("Sequencer");
    private JCheckBox chkProxy = new JCheckBox("Proxy");
    private JButton btnManualImport = new JButton("Import Burp Proxy History.");
    private JButton btnSaveLogs = new JButton("Save log table as CSV");
    private JButton btnSaveFullLogs = new JButton("Save full logs as CSV (slow)");
    private JToggleButton btnAutoSaveLogs = new JToggleButton("Autosave as CSV");
    private final JCheckBox chkExtender = new JCheckBox("Extender");
    private final JCheckBox chkTarget = new JCheckBox("Target");
    private final JLabel lblColumnSettings = new JLabel("Note 0: Right click on columns' headers to change settings.");
    private final JLabel lblPerformanceNote = new JLabel("Note 1: Extensive logging  may affect Burp Suite performance.");
    private final JLabel lblAutoLoggingNote = new JLabel("Note 2: Automatic logging does not save requests and responses. Only table contents. ");
    private final JLabel lblBurpLoggingNote = new JLabel("Note 3: Full request/response logging available in 'Project Options > Misc > Logging'");
    private final JLabel lblUpdatingNote = new JLabel("Note 4: Updating the extension will reset the log table settings.");
    private final FileLogger fileLogger;
    private final JPanel contentWrapper;
    private final JSpinner spnResponseTimeout;
    private final JSpinner spnMaxEntries;
    private final JSpinner spnSearchThreads;
    private final JButton btnResetSettings;
    private final JButton btnClearLogs;


    /**
     * Create the panel.
     */
    public LoggerOptionsPanel() {
        contentWrapper = new JPanel(new GridBagLayout());
        this.setViewportView(contentWrapper);
        this.loggerPreferences = LoggerPlusPlus.getInstance().getLoggerPreferences();
        this.loggerPreferences.setAutoSave(false);
        this.fileLogger = new FileLogger();
        JPanel innerContainer = new JPanel(new GridBagLayout());

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.BOTH;
        JPanel statusPanel = new JPanel(new BorderLayout());
        gbc.gridx = 1;
        gbc.gridy = 1;
        gbc.weightx = 0.7;
        gbc.gridwidth = 2;
        statusPanel.setBorder(BorderFactory.createTitledBorder("Status"));
        statusPanel.add(tglbtnIsEnabled, BorderLayout.CENTER);
        innerContainer.add(statusPanel, gbc);
        
        JPanel logFromPanel = new JPanel(new GridLayout(0, 1));
        gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.BOTH;
        logFromPanel.setBorder(BorderFactory.createTitledBorder("Log From"));
        logFromPanel.add(chkIsRestrictedToScope);
        logFromPanel.add(Box.createVerticalStrut(10));
        logFromPanel.add(chkAllTools);
        logFromPanel.add(chkSpider);
        logFromPanel.add(chkIntruder);
        logFromPanel.add(chkScanner);
        logFromPanel.add(chkRepeater);
        logFromPanel.add(chkSequencer);
        logFromPanel.add(chkProxy);
        logFromPanel.add(chkTarget);
        logFromPanel.add(chkExtender);
        gbc.weightx = 0.7;
        gbc.gridx = 1;
        gbc.gridy = 2;
        gbc.gridheight = 9;
        gbc.weighty = 1.0;
        innerContainer.add(logFromPanel, gbc);

        JPanel importPanel = new JPanel(new GridLayout(0, 1));
        gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.BOTH;
        importPanel.setBorder(BorderFactory.createTitledBorder("Import"));
        importPanel.add(chkAutoImport);
        importPanel.add(btnManualImport);
        JButton importFromCSV = new JButton("Import From CSV (Not implemented)");
        importFromCSV.setEnabled(false);
        importPanel.add(importFromCSV);
        gbc.gridx = 2;
        gbc.gridy = 2;
        gbc.weightx = 0.3;
        gbc.gridheight = 3;
        gbc.weighty = 1.0;
        innerContainer.add(importPanel, gbc);

        JPanel exportPanel = new JPanel(new GridLayout(0, 1));
        exportPanel.setBorder(BorderFactory.createTitledBorder("Export"));
        exportPanel.add(btnSaveLogs);
        exportPanel.add(btnSaveFullLogs);
        exportPanel.add(btnAutoSaveLogs);
        gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.BOTH;
        gbc.gridx = 2;
        gbc.gridy = 5;
        gbc.gridheight = 4;
        gbc.weightx = 0.3;
        gbc.weighty = 1.0;
        innerContainer.add(exportPanel, gbc);



        JPanel otherPanel = new JPanel(new GridBagLayout());
        otherPanel.setBorder(BorderFactory.createTitledBorder("Other"));

        gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.BOTH;
        gbc.weightx = 1;
        if(!LoggerPlusPlus.getCallbacks().isExtensionBapp()) {
            gbc.gridx = gbc.gridy = 1;
            gbc.gridx = 1;
            otherPanel.add(new JLabel("Check For Updates:"), gbc);
            gbc.gridx = 3;
            otherPanel.add(chkUpdateOnStartup, gbc);
        }
        gbc.gridy++;
        gbc.gridx = 1;
        JLabel lblResponseSettings = new JLabel("Response Timeout (s):");
        otherPanel.add(lblResponseSettings, gbc);
        gbc.gridx++;
        otherPanel.add(Box.createHorizontalStrut(7), gbc);
        gbc.gridx++;
        spnResponseTimeout = new JSpinner();
        otherPanel.add(spnResponseTimeout, gbc);
        gbc.gridx++;
        otherPanel.add(Box.createHorizontalStrut(7), gbc);
        gbc.gridx++;
        otherPanel.add(new JLabel("Min: 10 Max: 600"), gbc);

        gbc.gridx = 1;
        gbc.gridy++;
        JLabel lblMaxEntries = new JLabel("Maximum Log Entries:");
        otherPanel.add(lblMaxEntries, gbc);
        gbc.gridx++;
        otherPanel.add(Box.createHorizontalStrut(7), gbc);
        gbc.gridx++;
        spnMaxEntries = new JSpinner();
        otherPanel.add(spnMaxEntries, gbc);
        gbc.gridx++;
        otherPanel.add(Box.createHorizontalStrut(7), gbc);
        gbc.gridx++;
        otherPanel.add(new JLabel("Min: 10 Max: 1,000,000"), gbc);

        gbc.gridx = 1;
        gbc.gridy++;
        JLabel lblSearchThreads = new JLabel("Search Threads:");
        otherPanel.add(lblSearchThreads, gbc);
        gbc.gridx++;
        otherPanel.add(Box.createHorizontalStrut(7), gbc);
        gbc.gridx++;
        spnSearchThreads = new JSpinner();
        otherPanel.add(spnSearchThreads, gbc);
        gbc.gridx++;
        otherPanel.add(Box.createHorizontalStrut(7), gbc);
        gbc.gridx++;
        otherPanel.add(new JLabel("Min: 1 Max: 50"), gbc);

        gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.BOTH;
        gbc.gridx = 1;
        gbc.gridy = 9;
        gbc.gridheight = 5;
        gbc.weightx = 1.0;
        gbc.gridwidth = 2;

        innerContainer.add(otherPanel, gbc);


        JPanel buttonPanel = new JPanel(new GridLayout(0,1));
        buttonPanel.setBorder(BorderFactory.createTitledBorder("Reset"));
        btnResetSettings = new JButton("Reset all settings");
        buttonPanel.add(btnResetSettings);
        btnClearLogs = new JButton("Clear the logs");
        buttonPanel.add(btnClearLogs);

        gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.BOTH;
        gbc.gridx = 1;
        gbc.gridy = 15;
        gbc.weightx = 1.0;
        gbc.gridwidth = 2;
        innerContainer.add(buttonPanel, gbc);


        JPanel notesPanel = new JPanel(new GridLayout(0,1));
        notesPanel.setBorder(BorderFactory.createTitledBorder("Note"));
        notesPanel.add(lblColumnSettings);
        notesPanel.add(lblPerformanceNote);
        notesPanel.add(lblAutoLoggingNote);
        notesPanel.add(lblBurpLoggingNote);
        notesPanel.add(lblUpdatingNote);
        gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.BOTH;
        gbc.gridx = 1;
        gbc.gridy = 16;
        gbc.gridheight = 1;
        gbc.weightx = 1.0;
        gbc.gridwidth = 2;
        innerContainer.add(notesPanel, gbc);

        //Add bottom filler

//        innerContainer.setMaximumSize(new Dimension(960, 9999));
        gbc = new GridBagConstraints();
        gbc.gridx = 1;
        gbc.gridy = 1;
        contentWrapper.add(Box.createHorizontalStrut(15), gbc);
        gbc.ipadx = gbc.ipady = 25;
        gbc.gridx = 2;
        contentWrapper.add(innerContainer, gbc);

        gbc = new GridBagConstraints();
        gbc.gridwidth = 1;
        gbc.gridx = 3;
        gbc.gridy = 2;
        gbc.weightx = gbc.weighty = 1;
        JPanel paddingPanel = new JPanel();
        contentWrapper.add(paddingPanel, gbc);

        setPreferencesValues();
        setComponentsActions();
    }


    private void setComponentsActions() {
        chkIsRestrictedToScope.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                loggerPreferences.setRestrictedToScope(chkIsRestrictedToScope.isSelected());
            }
        });

        chkUpdateOnStartup.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                loggerPreferences.setUpdateOnStartup(chkUpdateOnStartup.isSelected());
            }
        });

        chkAutoImport.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                loggerPreferences.setAutoImportProxyHistory(chkAutoImport.isSelected());
            }
        });

        chkAllTools.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                loggerPreferences.setEnabled4All(chkAllTools.isSelected());
                chkSpider.setEnabled(!chkAllTools.isSelected());
                chkIntruder.setEnabled(!chkAllTools.isSelected());
                chkScanner.setEnabled(!chkAllTools.isSelected());
                chkRepeater.setEnabled(!chkAllTools.isSelected());
                chkSequencer.setEnabled(!chkAllTools.isSelected());
                chkProxy.setEnabled(!chkAllTools.isSelected());
                chkTarget.setEnabled(!chkAllTools.isSelected());
                chkExtender.setEnabled(!chkAllTools.isSelected());
            }
        });

        chkSpider.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                loggerPreferences.setEnabled4Spider(chkSpider.isSelected());
            }
        });

        chkIntruder.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                loggerPreferences.setEnabled4Intruder(chkIntruder.isSelected());
            }
        });

        chkScanner.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                loggerPreferences.setEnabled4Scanner(chkScanner.isSelected());
            }
        });

        chkRepeater.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                loggerPreferences.setEnabled4Repeater(chkRepeater.isSelected());
            }
        });

        chkSequencer.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                loggerPreferences.setEnabled4Sequencer(chkSequencer.isSelected());
            }
        });

        chkProxy.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                loggerPreferences.setEnabled4Proxy(chkProxy.isSelected());
            }
        });

        chkExtender.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                loggerPreferences.setEnabled4Extender(chkExtender.isSelected());
            }
        });

        chkTarget.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                loggerPreferences.setEnabled4TargetTab(chkTarget.isSelected());
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

        btnSaveFullLogs.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                fileLogger.saveLogs(true);
            }
        });

        btnSaveLogs.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                fileLogger.saveLogs(false);
            }
        });


        btnManualImport.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                int result = MoreHelp.askConfirmMessage("Burp Proxy Import", "Import history from burp suite proxy? This will clear the current entries.", new String[]{"Import", "Cancel"});
                if(result == JOptionPane.OK_OPTION) {
                    LoggerPlusPlus.getInstance().getLogManager().reset();
                    for (IHttpRequestResponse requestResponse : LoggerPlusPlus.getCallbacks().getProxyHistory()) {
                        LoggerPlusPlus.getInstance().getLogManager().importExisting(requestResponse);
                    }
                }
            }
        });


        btnClearLogs.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                boolean origState = loggerPreferences.isEnabled();
                loggerPreferences.setEnabled(false);
                LoggerPlusPlus.getInstance().reset();
                LoggerPlusPlus.getInstance().getLogTable().getModel().fireTableDataChanged();
                loggerPreferences.setEnabled(origState);
                setPreferencesValues();
            }
        });

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

        spnResponseTimeout.setModel(new SpinnerNumberModel(LoggerPlusPlus.getInstance().getLoggerPreferences().getResponseTimeout()/1000, 10, 600, 1));
        spnResponseTimeout.addChangeListener(new ChangeListener() {
            @Override
            public void stateChanged(ChangeEvent changeEvent) {
                LoggerPlusPlus.getInstance().getLoggerPreferences().setResponseTimeout(((Integer) spnResponseTimeout.getValue()).longValue()*1000);
            }
        });

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

        int maxSearchThreads = 50;
        spnSearchThreads.setModel(new SpinnerNumberModel(
                Math.min(LoggerPlusPlus.getInstance().getLoggerPreferences().getSearchThreads(), maxSearchThreads), 1, maxSearchThreads, 1));
        spnSearchThreads.addChangeListener(new ChangeListener() {
            @Override
            public void stateChanged(ChangeEvent changeEvent) {
                LoggerPlusPlus.getInstance().getLoggerPreferences().setSearchThreads((Integer) spnSearchThreads.getValue());
            }
        });
    }

    public void setAutoSaveBtn(boolean enabled){
        btnAutoSaveLogs.setSelected(enabled);
    }

    private void toggleEnabledButton(boolean isSelected) {
        tglbtnIsEnabled.setText((isSelected ? "Logger++ is running" : "Logger++ has been stopped"));
        tglbtnIsEnabled.setSelected(isSelected);
        loggerPreferences.setEnabled(isSelected);
    }


    private void setPreferencesValues() {

        chkAutoImport.setSelected(loggerPreferences.autoImportProxyHistory());
        chkIsRestrictedToScope.setSelected(loggerPreferences.isRestrictedToScope());
        chkUpdateOnStartup.setSelected(loggerPreferences.checkUpdatesOnStartup());
        chkAllTools.setSelected(loggerPreferences.isEnabled4All());
        if(loggerPreferences.isEnabled4All()){
            chkSpider.setEnabled(false);
            chkIntruder.setEnabled(false);
            chkScanner.setEnabled(false);
            chkRepeater.setEnabled(false);
            chkSequencer.setEnabled(false);
            chkProxy.setEnabled(false);
            chkExtender.setEnabled(false);
            chkTarget.setEnabled(false);
        }
        chkSpider.setSelected(loggerPreferences.isEnabled4Spider());
        chkIntruder.setSelected(loggerPreferences.isEnabled4Intruder());
        chkScanner.setSelected(loggerPreferences.isEnabled4Scanner());
        chkRepeater.setSelected(loggerPreferences.isEnabled4Repeater());
        chkSequencer.setSelected(loggerPreferences.isEnabled4Sequencer());
        chkProxy.setSelected(loggerPreferences.isEnabled4Proxy());
        chkExtender.setSelected(loggerPreferences.isEnabled4Extender());
        chkTarget.setSelected(loggerPreferences.isEnabled4TargetTab());
        toggleEnabledButton(loggerPreferences.isEnabled());

        if (!loggerPreferences.canSaveCSV()) {
            btnSaveLogs.setEnabled(false);
            btnSaveFullLogs.setEnabled(false);
            btnAutoSaveLogs.setEnabled(false);
            btnSaveLogs.setToolTipText("Please look at the extension's error tab.");
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
