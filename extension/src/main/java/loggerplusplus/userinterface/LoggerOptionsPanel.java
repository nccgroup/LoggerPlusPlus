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
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.google.gson.reflect.TypeToken;
import loggerplusplus.*;
import loggerplusplus.filter.ColorFilter;
import loggerplusplus.filter.FilterListener;
import loggerplusplus.filter.SavedFilter;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.FocusAdapter;
import java.awt.event.FocusEvent;
import java.net.URI;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.logging.Logger;

import static loggerplusplus.Globals.*;

public class LoggerOptionsPanel extends JScrollPane{
    private final Preferences preferences;

    private JToggleButton tglbtnIsEnabled = new JToggleButton("Logger++ is running");
    private JCheckBox chkIsRestrictedToScope = new JCheckBox("In scope items only");
    private JCheckBox chkUpdateOnStartup = new JCheckBox();
    private JCheckBox chkOtherToolLiveLogging = new JCheckBox();
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

    private final JPanel elasticPanel;
    private final JToggleButton esEnabled = new JToggleButton("Disabled");
    private final JSpinner esPortSpinner = new JSpinner(new SpinnerNumberModel(9100, 0, 65535, 1));
    private final JTextField esAddressField = new JTextField();
    private final JTextField esClusterField = new JTextField();
    private final JTextField esIndexField = new JTextField();
    private final JSpinner esUploadDelay = new JSpinner(new SpinnerNumberModel(120, 10, 999999, 10));
    private final JLabel esValueChangeWarning = new JLabel("Warning: Changing preferences while running will disable the upload service and clear all pending values.");


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

    private final JButton btnImportFilters;
    private final JButton btnExportFilters;
    private final JButton btnImportColorFilters;
    private final JButton btnExportColorFilters;


    /**
     * Create the panel.
     */
    public LoggerOptionsPanel() {
        contentWrapper = new JPanel(new GridBagLayout());
        this.setViewportView(contentWrapper);
        this.preferences = LoggerPlusPlus.preferences;
        this.fileLogger = new FileLogger();
        this.esValueChangeWarning.setForeground(Color.RED);
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


        elasticPanel = new JPanel(new GridBagLayout());
        elasticPanel.setBorder(BorderFactory.createTitledBorder("Elastic Search"));
        gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.BOTH;
        gbc.weightx = 1;
        JLabel esAddress = new JLabel("Address:");
        JLabel esClusterName = new JLabel("Cluster Name:");
        JLabel esIndexName = new JLabel("Index:");
        JLabel esRefreshTime = new JLabel("Upload Delay:");
        JLabel esSecondsHint = new JLabel("(Seconds)");

        gbc.gridwidth = 3;
        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.weighty = 0;
        gbc.weightx = 0;
        elasticPanel.add(esEnabled, gbc);

        gbc.gridy = 1;
        JSeparator separator = new JSeparator(SwingConstants.HORIZONTAL);
        separator.setBorder(BorderFactory.createEmptyBorder(5,0,5,0));
        elasticPanel.add(separator, gbc);

        gbc.gridwidth = 1;
        gbc.weighty = 1;
        gbc.weightx = 0.25;
        gbc.gridy = 2;
        elasticPanel.add(esAddress, gbc);
        gbc.gridy = 3;
        elasticPanel.add(esClusterName, gbc);
        gbc.gridy = 4;
        elasticPanel.add(esIndexName, gbc);
        gbc.gridy = 5;
        elasticPanel.add(esRefreshTime, gbc);
        gbc.gridx = 1;
        gbc.gridy = 2;
        gbc.weightx = 1;
        elasticPanel.add(esAddressField, gbc);
        gbc.gridx = 2;
        gbc.weightx = 0.25;
        elasticPanel.add(esPortSpinner, gbc);
        gbc.gridx = 1;
        gbc.gridy = 3;
        gbc.gridwidth = 2;
        gbc.weightx = 1;
        elasticPanel.add(esClusterField, gbc);
        gbc.gridy = 4;
        elasticPanel.add(esIndexField, gbc);
        gbc.gridy = 5;
        gbc.gridwidth = 1;
        elasticPanel.add(esUploadDelay, gbc);
        gbc.gridwidth = 1;
        gbc.gridx = 2;
        elasticPanel.add(esSecondsHint, gbc);

        gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.BOTH;
        gbc.gridx = 1;
        gbc.gridy = 10;
        gbc.gridheight = 4;
        gbc.weightx = 1.0;
        gbc.gridwidth = 2;
        innerContainer.add(elasticPanel, gbc);


        JPanel otherPanel = new JPanel(new GridBagLayout());
        otherPanel.setBorder(BorderFactory.createTitledBorder("Other"));

        gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.BOTH;
        gbc.weightx = 1;
        if(!LoggerPlusPlus.callbacks.isExtensionBapp()) {
            gbc.gridx = gbc.gridy = 1;
            gbc.gridx = 1;
            otherPanel.add(new JLabel("Check For Updates:"), gbc);
            gbc.gridx = 3;
            otherPanel.add(chkUpdateOnStartup, gbc);
        }

        gbc.gridy++;
        gbc.gridx = 1;
        gbc.gridwidth = 2;
        otherPanel.add(new JLabel("Live Logging For Non-Proxy Tools:"), gbc);
        gbc.gridwidth = 1;
        gbc.gridx++;
        otherPanel.add(Box.createHorizontalStrut(7), gbc);
        gbc.gridx++;
        otherPanel.add(chkOtherToolLiveLogging, gbc);


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
        gbc.gridy = 14;
        gbc.gridheight = 5;
        gbc.weightx = 1.0;
        gbc.gridwidth = 2;

        innerContainer.add(otherPanel, gbc);


        JPanel filterSharingPanel = new JPanel(new GridBagLayout());
        filterSharingPanel.setBorder(BorderFactory.createTitledBorder("Saved Filter Sharing"));
        gbc = new GridBagConstraints();
        gbc.weightx = 1;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.gridx = gbc.gridy = 1;
        btnImportFilters = new JButton("Import Saved Filters");
        filterSharingPanel.add(btnImportFilters, gbc);
        gbc.gridy++;
        btnExportFilters = new JButton("Export Saved Filters");
        filterSharingPanel.add(btnExportFilters, gbc);

        JPanel colorFilterSharingPanel = new JPanel(new GridBagLayout());
        colorFilterSharingPanel.setBorder(BorderFactory.createTitledBorder("Color Filter Sharing"));
        gbc = new GridBagConstraints();
        gbc.weightx = 1;
        gbc.fill = GridBagConstraints.BOTH;
        gbc.gridx = gbc.gridy = 1;
        btnImportColorFilters = new JButton("Import Color Filters");
        colorFilterSharingPanel.add(btnImportColorFilters, gbc);
        gbc.gridy++;
        btnExportColorFilters = new JButton("Export Color Filters");
        colorFilterSharingPanel.add(btnExportColorFilters, gbc);


        gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.BOTH;
        gbc.gridx = 1;
        gbc.gridy = 20;
        gbc.weightx = 5.0;
        gbc.gridwidth = 1;
        innerContainer.add(colorFilterSharingPanel, gbc);
        gbc.weightx = 5.0;
        gbc.gridx++;
        innerContainer.add(filterSharingPanel, gbc);



        JPanel buttonPanel = new JPanel(new GridLayout(0,1));
        buttonPanel.setBorder(BorderFactory.createTitledBorder("Reset"));
        btnResetSettings = new JButton("Reset all settings");
        buttonPanel.add(btnResetSettings);
        btnClearLogs = new JButton("Clear the logs");
        buttonPanel.add(btnClearLogs);

        gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.BOTH;
        gbc.gridx = 1;
        gbc.gridy = 21;
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
        gbc.gridy = 22;
        gbc.gridheight = 1;
        gbc.weightx = 1.0;
        gbc.gridwidth = 2;
        innerContainer.add(notesPanel, gbc);

        //Add bottom filler

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
                LoggerPlusPlus.preferences.setSetting(Globals.PREF_RESTRICT_TO_SCOPE, chkIsRestrictedToScope.isSelected());
            }
        });

        chkUpdateOnStartup.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                preferences.setSetting(PREF_UPDATE_ON_STARTUP, chkUpdateOnStartup.isSelected());
            }
        });

        chkOtherToolLiveLogging.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                LoggerPlusPlus.preferences.setSetting(PREF_LOG_OTHER_LIVE, chkOtherToolLiveLogging.isSelected());
            }
        });

        chkAutoImport.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                LoggerPlusPlus.preferences.setSetting(PREF_AUTO_IMPORT_PROXY_HISTORY, chkAutoImport.isSelected());
            }
        });

        chkAllTools.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                LoggerPlusPlus.preferences.setSetting(PREF_LOG_GLOBAL, chkAllTools.isSelected());
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
                preferences.setSetting(PREF_LOG_SPIDER, chkSpider.isSelected());
            }
        });

        chkIntruder.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                preferences.setSetting(PREF_LOG_INTRUDER, chkIntruder.isSelected());
            }
        });

        chkScanner.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                preferences.setSetting(PREF_LOG_SCANNER, chkScanner.isSelected());
            }
        });

        chkRepeater.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                preferences.setSetting(PREF_LOG_REPEATER, chkRepeater.isSelected());
            }
        });

        chkSequencer.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                preferences.setSetting(PREF_LOG_SEQUENCER, chkSequencer.isSelected());
            }
        });

        chkProxy.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                preferences.setSetting(PREF_LOG_PROXY, chkProxy.isSelected());
            }
        });

        chkExtender.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                preferences.setSetting(PREF_LOG_EXTENDER, chkExtender.isSelected());
            }
        });

        chkTarget.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent arg0) {
                preferences.setSetting(PREF_LOG_TARGET_TAB, chkTarget.isSelected());
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
                fileLogger.setAutoSave(!(boolean) LoggerPlusPlus.preferences.getSetting(PREF_AUTO_SAVE));
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
                    LoggerPlusPlus.instance.getLogManager().reset();
                    for (IHttpRequestResponse requestResponse : LoggerPlusPlus.callbacks.getProxyHistory()) {
                        LoggerPlusPlus.instance.getLogManager().importExisting(requestResponse);
                    }
                }
            }
        });


        btnClearLogs.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                boolean origState = (Boolean) LoggerPlusPlus.preferences.getSetting(Globals.PREF_ENABLED);
                LoggerPlusPlus.preferences.setSetting(PREF_ENABLED, false);
                LoggerPlusPlus.instance.reset();
                LoggerPlusPlus.instance.getLogTable().getModel().fireTableDataChanged();
                LoggerPlusPlus.preferences.setSetting(PREF_ENABLED, origState);
                setPreferencesValues();
            }
        });


        //TODO Fix reset settings.
        btnResetSettings.setEnabled(false);
//        btnResetSettings.addActionListener(new ActionListener() {
//            public void actionPerformed(ActionEvent arg0) {
//                boolean origState = (Boolean) LoggerPlusPlus.preferences.getSetting(Globals.PREF_ENABLED);
//                LoggerPlusPlus.preferences.setSetting(PREF_ENABLED, false);
//
//                LoggerPlusPlus.instance.getLogTable().getColumnModel().resetToDefaultVariables();
//                LoggerPlusPlus.instance.getLogTable().getModel().fireTableStructureChanged();
//                fileLogger.setAutoSave(false);
//                LoggerPlusPlus.preferences.setSetting(PREF_ENABLED, origState);
//                setPreferencesValues();
//            }
//
//        });

        long responseTimeout = (long) LoggerPlusPlus.preferences.getSetting(PREF_RESPONSE_TIMEOUT);
        spnResponseTimeout.setModel(new SpinnerNumberModel(responseTimeout/1000, 10, 600, 1));
        spnResponseTimeout.addChangeListener(new ChangeListener() {
            @Override
            public void stateChanged(ChangeEvent changeEvent) {
                LoggerPlusPlus.preferences.setSetting(PREF_RESPONSE_TIMEOUT,
                        ((Integer) spnResponseTimeout.getValue()).longValue()*1000);
            }
        });


        int maxEntriesMax = 1000000;
        int maxEntries = (int) LoggerPlusPlus.preferences.getSetting(PREF_MAXIMUM_ENTRIES);
        spnMaxEntries.setModel(new SpinnerNumberModel(Math.min(maxEntries, maxEntriesMax), 10, maxEntriesMax, 10));
        spnMaxEntries.addChangeListener(new ChangeListener() {
            @Override
            public void stateChanged(ChangeEvent changeEvent) {
                LoggerPlusPlus.preferences.setSetting(PREF_MAXIMUM_ENTRIES, spnMaxEntries.getValue());
            }
        });
        spnMaxEntries.getEditor().getComponent(0).addFocusListener(new FocusAdapter() {
            @Override
            public void focusLost(FocusEvent e) {
                super.focusLost(e);
            }
        });

        int maxSearchThreads = 50;
        int currentSearchThreads = (int) LoggerPlusPlus.preferences.getSetting(PREF_SEARCH_THREADS);
        spnSearchThreads.setModel(new SpinnerNumberModel(
                Math.min(currentSearchThreads, maxSearchThreads), 1, maxSearchThreads, 1));
        spnSearchThreads.addChangeListener(new ChangeListener() {
            @Override
            public void stateChanged(ChangeEvent changeEvent) {
                LoggerPlusPlus.preferences.setSetting(PREF_SEARCH_THREADS, spnSearchThreads.getValue());
            }
        });


        this.esAddressField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent documentEvent) {}
            @Override
            public void removeUpdate(DocumentEvent documentEvent) {}
            @Override
            public void changedUpdate(DocumentEvent documentEvent) {
                toggleEsEnabledButton(false);
            }
        });
        this.esAddressField.addFocusListener(new FocusAdapter() {
            @Override
            public void focusLost(FocusEvent focusEvent) {
                super.focusLost(focusEvent);
                LoggerPlusPlus.preferences.setSetting(PREF_ELASTIC_ADDRESS, esAddressField.getText());
            }
        });
        this.esPortSpinner.getModel().addChangeListener(new ChangeListener() {
            @Override
            public void stateChanged(ChangeEvent changeEvent) {
                toggleEsEnabledButton(false);
                Integer spinnerval = (Integer) esPortSpinner.getValue();
                LoggerPlusPlus.preferences.setSetting(PREF_ELASTIC_PORT, spinnerval.shortValue());
            }
        });
        this.esClusterField.getDocument().addDocumentListener(new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent documentEvent) {}
            @Override
            public void removeUpdate(DocumentEvent documentEvent) {}
            @Override
            public void changedUpdate(DocumentEvent documentEvent) {
                toggleEsEnabledButton(false);
            }
        });
        this.esClusterField.addFocusListener(new FocusAdapter() {
            @Override
            public void focusLost(FocusEvent focusEvent) {
                super.focusLost(focusEvent);
                LoggerPlusPlus.preferences.setSetting(PREF_ELASTIC_CLUSTER_NAME, esClusterField.getText());
            }
        });

        this.esIndexField.addFocusListener(new FocusAdapter() {
            @Override
            public void focusLost(FocusEvent focusEvent) {
                super.focusLost(focusEvent);
                LoggerPlusPlus.preferences.setSetting(PREF_ELASTIC_INDEX, esIndexField.getText());
            }
        });

        this.esUploadDelay.addChangeListener(new ChangeListener() {
            @Override
            public void stateChanged(ChangeEvent changeEvent) {
                LoggerPlusPlus.preferences.setSetting(PREF_ELASTIC_DELAY, esUploadDelay.getValue());
                toggleEsEnabledButton(false);
            }
        });

        this.esEnabled.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                toggleEsEnabledButton(esEnabled.isSelected());
            }
        });

        this.btnImportFilters.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                String json = MoreHelp.showLargeInputDialog("Import Saved Filters", null);
                ArrayList<SavedFilter> importedFilters = LoggerPlusPlus.gsonProvider.getGson().fromJson(json,
                        new TypeToken<ArrayList<SavedFilter>>(){}.getType());
                ArrayList<SavedFilter> savedFilters = (ArrayList<SavedFilter>) LoggerPlusPlus.preferences.getSetting(PREF_SAVED_FILTERS);
                ArrayList<SavedFilter> savedFiltersClone = new ArrayList<>(savedFilters);
                for (SavedFilter importedFilter : importedFilters) {
                    if(!savedFiltersClone.contains(importedFilter)) savedFiltersClone.add(importedFilter);
                }
                LoggerPlusPlus.preferences.setSetting(PREF_SAVED_FILTERS, savedFiltersClone);
            }
        });

        this.btnExportFilters.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                ArrayList<SavedFilter> savedFilters = (ArrayList<SavedFilter>) LoggerPlusPlus.preferences.getSetting(PREF_SAVED_FILTERS);
                String jsonOutput = LoggerPlusPlus.gsonProvider.getGson().toJson(savedFilters);
                MoreHelp.showLargeOutputDialog("Export Saved Filters", jsonOutput);
            }
        });

        this.btnImportColorFilters.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                String json = MoreHelp.showLargeInputDialog("Import Color Filters", null);
                Map<UUID, ColorFilter> colorFilterMap = LoggerPlusPlus.gsonProvider.getGson().fromJson(json,
                                new TypeToken<Map<UUID, ColorFilter>>(){}.getType());
                HashMap<UUID,ColorFilter> colorFilters = (HashMap<UUID, ColorFilter>) LoggerPlusPlus.preferences.getSetting(PREF_COLOR_FILTERS);
                Map<UUID, ColorFilter> cloneMap = new HashMap<>(colorFilters);
                cloneMap.putAll(colorFilterMap);
                for (FilterListener filterListener : LoggerPlusPlus.instance.getFilterListeners()) {
                    for (ColorFilter colorFilter : colorFilterMap.values()) {
                        filterListener.onFilterAdd(colorFilter);
                    }
                }
                LoggerPlusPlus.preferences.setSetting(PREF_COLOR_FILTERS, cloneMap);
            }
        });

        this.btnExportColorFilters.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                HashMap<UUID,ColorFilter> colorFilters = (HashMap<UUID, ColorFilter>) LoggerPlusPlus.preferences.getSetting(PREF_COLOR_FILTERS);
                String jsonOutput = LoggerPlusPlus.gsonProvider.getGson().toJson(colorFilters);
                MoreHelp.showLargeOutputDialog("Export Color Filters", jsonOutput);
            }
        });
    }


    public void setAutoSaveBtn(boolean enabled){
        btnAutoSaveLogs.setSelected(enabled);
    }

    private void toggleEnabledButton(boolean isSelected) {
        tglbtnIsEnabled.setText((isSelected ? "Logger++ is running" : "Logger++ has been stopped"));
        tglbtnIsEnabled.setSelected(isSelected);
        LoggerPlusPlus.preferences.setSetting(PREF_ENABLED, isSelected);
    }

    private void toggleEsEnabledButton(final boolean isSelected) {
        new Thread(new Runnable() {
            @Override
            public void run() {
                if(isSelected) {
                    esEnabled.setText("Starting...");
                }
                try {
                    LoggerPlusPlus.instance.setEsEnabled(isSelected);
                    esEnabled.setText((isSelected ? "Enabled" : "Disabled"));
                    esEnabled.setSelected(isSelected);
                    if(isSelected) {
                        GridBagConstraints gbc = new GridBagConstraints();
                        gbc.gridx = 0;
                        gbc.gridwidth = 3;
                        elasticPanel.add(esValueChangeWarning, gbc);
                    }else{
                        elasticPanel.remove(esValueChangeWarning);
                    }
                } catch (Exception e) {
                    if(isSelected) {
                        MoreHelp.showWarningMessage("Elastic Search could not be enabled. Please check your settings.\n" + e.getMessage());
                    }
                    esEnabled.setText("Connection Failed");
                    esEnabled.setSelected(false);
                }
            }
        }).start();
    }

    private void setPreferencesValues() {

        chkAutoImport.setSelected((Boolean) LoggerPlusPlus.preferences.getSetting(PREF_AUTO_IMPORT_PROXY_HISTORY));
        chkIsRestrictedToScope.setSelected((Boolean) LoggerPlusPlus.preferences.getSetting(Globals.PREF_RESTRICT_TO_SCOPE));
        chkUpdateOnStartup.setSelected((Boolean) preferences.getSetting(PREF_UPDATE_ON_STARTUP));
        chkOtherToolLiveLogging.setSelected((Boolean) LoggerPlusPlus.preferences.getSetting(PREF_LOG_OTHER_LIVE));
        chkAllTools.setSelected((Boolean) LoggerPlusPlus.preferences.getSetting(PREF_LOG_GLOBAL));
        if((Boolean) LoggerPlusPlus.preferences.getSetting(PREF_LOG_GLOBAL)){
            chkSpider.setEnabled(false);
            chkIntruder.setEnabled(false);
            chkScanner.setEnabled(false);
            chkRepeater.setEnabled(false);
            chkSequencer.setEnabled(false);
            chkProxy.setEnabled(false);
            chkExtender.setEnabled(false);
            chkTarget.setEnabled(false);
        }
        chkSpider.setSelected((Boolean) preferences.getSetting(PREF_LOG_SPIDER));
        chkIntruder.setSelected((Boolean) preferences.getSetting(PREF_LOG_INTRUDER));
        chkScanner.setSelected((Boolean) preferences.getSetting(PREF_LOG_SCANNER));
        chkRepeater.setSelected((Boolean) preferences.getSetting(PREF_LOG_REPEATER));
        chkSequencer.setSelected((Boolean) preferences.getSetting(PREF_LOG_SEQUENCER));
        chkProxy.setSelected((Boolean) preferences.getSetting(PREF_LOG_PROXY));
        chkExtender.setSelected((Boolean) preferences.getSetting(PREF_LOG_EXTENDER));
        chkTarget.setSelected((Boolean) preferences.getSetting(PREF_LOG_TARGET_TAB));
        toggleEnabledButton((Boolean) LoggerPlusPlus.preferences.getSetting(PREF_ENABLED));

        this.esAddressField.setText((String) LoggerPlusPlus.preferences.getSetting(Globals.PREF_ELASTIC_ADDRESS));
        this.esPortSpinner.setValue(LoggerPlusPlus.preferences.getSetting(Globals.PREF_ELASTIC_PORT));
        this.esClusterField.setText((String) LoggerPlusPlus.preferences.getSetting(Globals.PREF_ELASTIC_CLUSTER_NAME));
        this.esIndexField.setText((String) LoggerPlusPlus.preferences.getSetting(Globals.PREF_ELASTIC_INDEX));
        this.esUploadDelay.setValue(LoggerPlusPlus.preferences.getSetting(Globals.PREF_ELASTIC_DELAY));
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
