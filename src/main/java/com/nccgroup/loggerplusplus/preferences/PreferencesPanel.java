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

package com.nccgroup.loggerplusplus.preferences;

import burp.IHttpRequestResponse;
import com.coreyd97.BurpExtenderUtilities.Alignment;
import com.coreyd97.BurpExtenderUtilities.ComponentGroup;
import com.coreyd97.BurpExtenderUtilities.PanelBuilder;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.google.gson.reflect.TypeToken;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.filter.colorfilter.ColorFilter;
import com.nccgroup.loggerplusplus.filter.savedfilter.SavedFilter;
import com.nccgroup.loggerplusplus.imports.LoggerImport;
import com.nccgroup.loggerplusplus.util.MoreHelp;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static com.nccgroup.loggerplusplus.util.Globals.*;

public class PreferencesPanel extends JScrollPane{

    private final PreferencesController preferencesController;
    private final Preferences preferences;

    private final JToggleButton tglbtnIsEnabled;
    private JToggleButton btnAutoSaveLogs;
    private final JToggleButton esEnabled;
    private final JLabel esValueChangeWarning = new JLabel("Warning: Changing preferences while running will disable the upload service and clear all pending groups.");


    /**
     * Create the panel.
     */
    public PreferencesPanel(PreferencesController preferencesController) {
        this.preferencesController = preferencesController;
        this.preferences = preferencesController.getPreferences();

        PanelBuilder panelBuilder = new PanelBuilder(this.preferences);
        this.esValueChangeWarning.setForeground(Color.RED);

        ComponentGroup statusPanel = panelBuilder.createComponentGroup("Status");
        tglbtnIsEnabled = statusPanel.addToggleButton(APP_NAME + " is running", actionEvent -> {
            JToggleButton thisButton = (JToggleButton) actionEvent.getSource();
            toggleEnabledButton(thisButton.isSelected());
        });
        tglbtnIsEnabled.setSelected(preferences.getSetting(PREF_ENABLED));

        ComponentGroup logFromPanel = panelBuilder.createComponentGroup("Log From");
        logFromPanel.addPreferenceComponent(PREF_RESTRICT_TO_SCOPE, "In scope items only");
        GridBagConstraints strutConstraints = logFromPanel.generateNextConstraints();
        strutConstraints.weighty = strutConstraints.weightx = 0;
        logFromPanel.addComponent((JComponent) Box.createVerticalStrut(10), strutConstraints);
        JCheckBox logAllTools = logFromPanel.addPreferenceComponent(PREF_LOG_GLOBAL, "All Tools");
        JCheckBox logSpider = logFromPanel.addPreferenceComponent(PREF_LOG_SPIDER, "Spider");
        JCheckBox logIntruder = logFromPanel.addPreferenceComponent(PREF_LOG_INTRUDER, "Intruder");
        JCheckBox logScanner = logFromPanel.addPreferenceComponent(PREF_LOG_SCANNER, "Scanner");
        JCheckBox logRepeater = logFromPanel.addPreferenceComponent(PREF_LOG_REPEATER, "Repeater");
        JCheckBox logSequencer = logFromPanel.addPreferenceComponent(PREF_LOG_SEQUENCER, "Sequencer");
        JCheckBox logProxy = logFromPanel.addPreferenceComponent(PREF_LOG_PROXY, "Proxy");
        JCheckBox logTarget = logFromPanel.addPreferenceComponent(PREF_LOG_TARGET_TAB, "Target");
        JCheckBox logExtender = logFromPanel.addPreferenceComponent(PREF_LOG_EXTENDER, "Extender");

        strutConstraints = logFromPanel.generateNextConstraints();
        strutConstraints.weighty = strutConstraints.weightx = 0;
        logFromPanel.addComponent((JComponent) Box.createVerticalStrut(10), strutConstraints);
        logFromPanel.addPreferenceComponent(PREF_LOG_OTHER_LIVE, "Log Non-Proxy Tools Live");

        {   //Disable check boxes if global logging is enabled.
            boolean globalDisabled = !logAllTools.isSelected();
            logSpider.setEnabled(globalDisabled);
            logIntruder.setEnabled(globalDisabled);
            logScanner.setEnabled(globalDisabled);
            logRepeater.setEnabled(globalDisabled);
            logSequencer.setEnabled(globalDisabled);
            logProxy.setEnabled(globalDisabled);
            logTarget.setEnabled(globalDisabled);
            logExtender.setEnabled(globalDisabled);
        }

        logAllTools.addChangeListener(changeEvent -> {
            boolean globalDisabled = !logAllTools.isSelected();
            logSpider.setEnabled(globalDisabled);
            logIntruder.setEnabled(globalDisabled);
            logScanner.setEnabled(globalDisabled);
            logRepeater.setEnabled(globalDisabled);
            logSequencer.setEnabled(globalDisabled);
            logProxy.setEnabled(globalDisabled);
            logTarget.setEnabled(globalDisabled);
            logExtender.setEnabled(globalDisabled);
        });

        ComponentGroup importGroup = panelBuilder.createComponentGroup("Import");
        importGroup.addPreferenceComponent(PREF_AUTO_IMPORT_PROXY_HISTORY, "Import proxy history on startup");
        importGroup.addButton("Import Burp Proxy History", actionEvent -> {

            int historySize = LoggerPlusPlus.callbacks.getProxyHistory().length;
            int maxEntries = preferences.getSetting(PREF_MAXIMUM_ENTRIES);
            String message = "Import " + historySize + " items from burp suite proxy history? This will clear the current entries." +
                    "\nLarge imports may take a few minutes to process.";
            if(historySize > maxEntries) {
                message += "\nNote: History will be truncated to " + maxEntries + " entries.";
            }

            int result = MoreHelp.askConfirmMessage("Burp Proxy Import",
                    message, new String[]{"Import", "Cancel"});

            if(result == JOptionPane.OK_OPTION) {
                preferencesController.getLoggerPlusPlus().getLogProcessor().importProxyHistory();
            }
        });

        importGroup.addButton("Import From WStalker CSV", actionEvent -> {
            ArrayList<IHttpRequestResponse> requests = LoggerImport.importWStalker();
            LoggerImport.loadImported(requests);
        }).setEnabled(true);

        importGroup.addButton("Import From OWASP ZAP", actionEvent -> {
            ArrayList<IHttpRequestResponse> requests = LoggerImport.importZAP();
            LoggerImport.loadImported(requests);
        }).setEnabled(true);

        ComponentGroup exportGroup = panelBuilder.createComponentGroup("Export");
        preferencesController.getLoggerPlusPlus().getExportController().getExporters().forEach(logExporter -> {
            exportGroup.addComponent(logExporter.getExportPanel());
        });

//        exportGroup.addButton("Save log table as CSV", actionEvent -> {
////            fileLogger.saveLogs(false);
//        });
//        exportGroup.addButton("Save full logs as CSV (slow)", actionEvent -> {
////            fileLogger.saveLogs(true);
//        });
//        btnAutoSaveLogs = exportGroup.addToggleButton("Autosave as CSV", actionEvent -> {
////            fileLogger.setAutoSave(!(boolean) preferences.getSetting(PREF_AUTO_SAVE));
//        });

        ComponentGroup elasticPanel = panelBuilder.createComponentGroup("Elastic Search");
        esEnabled = elasticPanel.addToggleButton("Disabled", actionEvent -> {
            JToggleButton thisButton = (JToggleButton) actionEvent.getSource();
            toggleEsEnabledButton(thisButton.isSelected());
        });

        JSeparator separator = new JSeparator(SwingConstants.HORIZONTAL);
        separator.setBorder(BorderFactory.createEmptyBorder(5,0,5,0));
        elasticPanel.addComponent(separator);

        elasticPanel.addPreferenceComponent(PREF_ELASTIC_ADDRESS, "Address: ");
        JSpinner elasticPort = elasticPanel.addPreferenceComponent(PREF_ELASTIC_PORT, "Port: ");
        ((SpinnerNumberModel) elasticPort.getModel()).setMaximum(65535);
        ((SpinnerNumberModel) elasticPort.getModel()).setMinimum(0);
        elasticPort.setEditor(new JSpinner.NumberEditor(elasticPort,"#"));

        elasticPanel.addPreferenceComponent(PREF_ELASTIC_CLUSTER_NAME, "Cluster Name: ");
        elasticPanel.addPreferenceComponent(PREF_ELASTIC_INDEX, "Index: ");
        JSpinner elasticDelay = elasticPanel.addPreferenceComponent(PREF_ELASTIC_DELAY, "Upload Delay (Seconds): ");
        ((SpinnerNumberModel) elasticDelay.getModel()).setMaximum(99999);
        ((SpinnerNumberModel) elasticDelay.getModel()).setMinimum(10);
        ((SpinnerNumberModel) elasticDelay.getModel()).setStepSize(10);
        elasticPanel.addPreferenceComponent(PREF_ELASTIC_INCLUDE_REQ_RESP, "Include Request and Response: ");

        ComponentGroup otherPanel = panelBuilder.createComponentGroup("Other");
        JSpinner spnRespTimeout = otherPanel.addPreferenceComponent(PREF_RESPONSE_TIMEOUT, "Response Timeout (Seconds): ");
        ((SpinnerNumberModel) spnRespTimeout.getModel()).setMinimum(10);
        ((SpinnerNumberModel) spnRespTimeout.getModel()).setMaximum(600);
        ((SpinnerNumberModel) spnRespTimeout.getModel()).setStepSize(10);

        JSpinner spnMaxEntries = otherPanel.addPreferenceComponent(PREF_MAXIMUM_ENTRIES, "Maximum Log Entries: ");
        ((SpinnerNumberModel) spnMaxEntries.getModel()).setMinimum(10);
        ((SpinnerNumberModel) spnMaxEntries.getModel()).setMaximum(Integer.MAX_VALUE);
        ((SpinnerNumberModel) spnMaxEntries.getModel()).setStepSize(10);

        JSpinner spnSearchThreads = otherPanel.addPreferenceComponent(PREF_SEARCH_THREADS, "Search Threads: ");
        ((SpinnerNumberModel) spnSearchThreads.getModel()).setMinimum(1);
        ((SpinnerNumberModel) spnSearchThreads.getModel()).setMaximum(50);
        ((SpinnerNumberModel) spnSearchThreads.getModel()).setStepSize(1);

        if(!LoggerPlusPlus.callbacks.isExtensionBapp()) {
            otherPanel.addPreferenceComponent(PREF_UPDATE_ON_STARTUP, "Check For Updates");
        }
        
        ComponentGroup savedFilterSharing = panelBuilder.createComponentGroup("Saved LogFilter Sharing");
        savedFilterSharing.addButton("Import Saved Filters", actionEvent -> {
            String json = MoreHelp.showLargeInputDialog("Import Saved Filters", null);
            ArrayList<SavedFilter> importedFilters = preferencesController.getGsonProvider().getGson().fromJson(json,
                    new TypeToken<ArrayList<SavedFilter>>(){}.getType());
            ArrayList<SavedFilter> savedFilters = preferences.getSetting(PREF_SAVED_FILTERS);
            ArrayList<SavedFilter> savedFiltersClone = new ArrayList<>(savedFilters);
            for (SavedFilter importedFilter : importedFilters) {
                if(!savedFiltersClone.contains(importedFilter)) savedFiltersClone.add(importedFilter);
            }
            preferences.setSetting(PREF_SAVED_FILTERS, savedFiltersClone);
        });
        savedFilterSharing.addButton("Export Saved Filters", actionEvent -> {
            ArrayList<SavedFilter> savedFilters = preferences.getSetting(PREF_SAVED_FILTERS);
            String jsonOutput = preferencesController.getGsonProvider().getGson().toJson(savedFilters);
            MoreHelp.showLargeOutputDialog("Export Saved Filters", jsonOutput);
        });

        ComponentGroup colorFilterSharing = panelBuilder.createComponentGroup("Color LogFilter Sharing");
        colorFilterSharing.addButton("Import Color Filters", actionEvent -> {
            String json = MoreHelp.showLargeInputDialog("Import Color Filters", null);
            Map<UUID, ColorFilter> colorFilterMap = preferencesController.getGsonProvider().getGson().fromJson(json,
                    new TypeToken<Map<UUID, ColorFilter>>(){}.getType());
            for (ColorFilter colorFilter : colorFilterMap.values()) {
                LoggerPlusPlus.instance.getLibraryController().addColorFilter(colorFilter);
            }
        });
        colorFilterSharing.addButton("Export Color Filters", actionEvent -> {
            HashMap<UUID,ColorFilter> colorFilters = preferences.getSetting(PREF_COLOR_FILTERS);
            String jsonOutput = preferencesController.getGsonProvider().getGson().toJson(colorFilters);
            MoreHelp.showLargeOutputDialog("Export Color Filters", jsonOutput);
        });

        ComponentGroup resetPanel = panelBuilder.createComponentGroup("Reset");
        resetPanel.addButton("Reset All Settings", actionEvent -> {
            int result = JOptionPane.showConfirmDialog(null, "Are you sure you wish to reset all settings? This includes the table layout!", "Warning", JOptionPane.YES_NO_OPTION);
            if(result == JOptionPane.YES_OPTION){
                preferences.resetSettings(preferences.getRegisteredSettings().keySet());
                preferencesController.getLoggerPlusPlus().getLogViewController().getLogTableController().reinitialize();
            }
        });
        resetPanel.addButton("Clear The Logs", actionEvent -> {
            preferencesController.getLoggerPlusPlus().getLogViewController().getLogTableController().reset();
        });


        ComponentGroup notesPanel = panelBuilder.createComponentGroup("Notes");
        notesPanel.addComponent(new JLabel("Note 0: Right click on columns' headers to change settings."));
        notesPanel.addComponent(new JLabel("Note 1: Extensive logging  may affect Burp Suite performance."));
        notesPanel.addComponent(new JLabel("Note 2: Automatic logging does not saveFilters requests and responses. Only table contents. "));
        notesPanel.addComponent(new JLabel("Note 3: Full request/response logging available in 'Project Options > Misc > Logging'"));
        notesPanel.addComponent(new JLabel("Note 4: Updating the extension will reset the log table settings."));

        JComponent mainComponent = panelBuilder.build(new JPanel[][]{
                new JPanel[]{statusPanel, statusPanel},
                new JPanel[]{logFromPanel, importGroup},
                new JPanel[]{logFromPanel, exportGroup},
                new JPanel[]{elasticPanel, elasticPanel},
                new JPanel[]{otherPanel, otherPanel},
                new JPanel[]{colorFilterSharing, savedFilterSharing},
                new JPanel[]{resetPanel, resetPanel},
                new JPanel[]{notesPanel, notesPanel},
        }, Alignment.TOPMIDDLE, 1, 1);

        this.setViewportView(mainComponent);
    }


    public void setAutoSaveBtn(boolean enabled){
        btnAutoSaveLogs.setSelected(enabled);
    }

    private void toggleEnabledButton(boolean isSelected) {
        tglbtnIsEnabled.setText(APP_NAME + (isSelected ? " is running" : " has been stopped"));
        tglbtnIsEnabled.setSelected(isSelected);
        preferences.setSetting(PREF_ENABLED, isSelected);
    }

    private void toggleEsEnabledButton(final boolean isSelected) {
        new Thread(new Runnable() {
            @Override
            public void run() {
                if(isSelected) {
                    esEnabled.setText("Starting...");
                }
                try {
//                    LoggerPlusPlus.instance.setEsEnabled(isSelected);//TODO FIXME
                    esEnabled.setText((isSelected ? "Enabled" : "Disabled"));
                    esEnabled.setSelected(isSelected);
                    if(isSelected) {
                        //TODO Re-Add these.
//                        GridBagConstraints gbc = new GridBagConstraints();
//                        gbc.gridx = 0;
//                        gbc.gridwidth = 3;
//                        elasticPanel.add(esValueChangeWarning, gbc);
                    }else{
//                        elasticPanel.remove(esValueChangeWarning);
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
}
