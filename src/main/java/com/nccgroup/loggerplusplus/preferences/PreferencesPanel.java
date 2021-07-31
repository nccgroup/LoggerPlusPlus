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
import com.coreyd97.BurpExtenderUtilities.ComponentGroup.Orientation;
import com.coreyd97.BurpExtenderUtilities.PanelBuilder;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.google.gson.reflect.TypeToken;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.exports.*;
import com.nccgroup.loggerplusplus.filter.colorfilter.ColorFilter;
import com.nccgroup.loggerplusplus.filter.savedfilter.SavedFilter;
import com.nccgroup.loggerplusplus.imports.LoggerImport;
import com.nccgroup.loggerplusplus.util.MoreHelp;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static com.nccgroup.loggerplusplus.util.Globals.*;

public class PreferencesPanel extends JScrollPane {

    private final PreferencesController preferencesController;
    private final Preferences preferences;

    private final JToggleButton tglbtnIsEnabled;
    private final JLabel esValueChangeWarning = new JLabel(
            "Warning: Changing preferences while running will disable the upload service and clear all pending groups.");

    /**
     * Create the panel.
     */
    public PreferencesPanel(PreferencesController preferencesController) {
        this.preferencesController = preferencesController;
        this.preferences = preferencesController.getPreferences();
        this.esValueChangeWarning.setForeground(Color.RED);

        ComponentGroup statusPanel = new ComponentGroup(Orientation.HORIZONTAL, "Status");
        tglbtnIsEnabled = new JToggleButton(new AbstractAction(APP_NAME + " is running") {
            @Override
            public void actionPerformed(ActionEvent e) {
                JToggleButton thisButton = (JToggleButton) e.getSource();
                toggleEnabledButton(thisButton.isSelected());
            }
        });
        statusPanel.add(tglbtnIsEnabled);
        tglbtnIsEnabled.setSelected(preferences.getSetting(PREF_ENABLED));

        ComponentGroup logFromPanel = new ComponentGroup(Orientation.VERTICAL, "Log From");
        logFromPanel.addPreferenceComponent(preferences, PREF_RESTRICT_TO_SCOPE, "In scope items only");
        GridBagConstraints strutConstraints = logFromPanel.generateNextConstraints(true);
        strutConstraints.weighty = strutConstraints.weightx = 0;
        logFromPanel.add(Box.createVerticalStrut(10), strutConstraints);
        JCheckBox logAllTools = logFromPanel.addPreferenceComponent(preferences, PREF_LOG_GLOBAL, "All Tools");
        JCheckBox logSpider = logFromPanel.addPreferenceComponent(preferences, PREF_LOG_SPIDER, "Spider");
        JCheckBox logIntruder = logFromPanel.addPreferenceComponent(preferences, PREF_LOG_INTRUDER, "Intruder");
        JCheckBox logScanner = logFromPanel.addPreferenceComponent(preferences, PREF_LOG_SCANNER, "Scanner");
        JCheckBox logRepeater = logFromPanel.addPreferenceComponent(preferences, PREF_LOG_REPEATER, "Repeater");
        JCheckBox logSequencer = logFromPanel.addPreferenceComponent(preferences, PREF_LOG_SEQUENCER, "Sequencer");
        JCheckBox logProxy = logFromPanel.addPreferenceComponent(preferences, PREF_LOG_PROXY, "Proxy");
        JCheckBox logTarget = logFromPanel.addPreferenceComponent(preferences, PREF_LOG_TARGET_TAB, "Target");
        JCheckBox logExtender = logFromPanel.addPreferenceComponent(preferences, PREF_LOG_EXTENDER, "Extender");

        strutConstraints = logFromPanel.generateNextConstraints(true);
        strutConstraints.weighty = strutConstraints.weightx = 0;
        logFromPanel.add(Box.createVerticalStrut(10), strutConstraints);
        // logFromPanel.addPreferenceComponent(preferences, PREF_LOG_OTHER_LIVE, "Log
        // Non-Proxy Tools Live");

        { // Disable check boxes if global logging is enabled.
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

        ComponentGroup importGroup = new ComponentGroup(Orientation.VERTICAL, "Import");
        importGroup.addPreferenceComponent(preferences, PREF_AUTO_IMPORT_PROXY_HISTORY,
                "Import proxy history on startup");
        importGroup.add(new JButton(new AbstractAction("Import Burp Proxy History") {
            @Override
            public void actionPerformed(ActionEvent e) {
                int historySize = LoggerPlusPlus.callbacks.getProxyHistory().length;
                int maxEntries = preferences.getSetting(PREF_MAXIMUM_ENTRIES);
                String message = "Import " + historySize
                        + " items from burp suite proxy history? This will clear the current entries."
                        + "\nLarge imports may take a few minutes to process.";
                if (historySize > maxEntries) {
                    message += "\nNote: History will be truncated to " + maxEntries + " entries.";
                }

                int result = MoreHelp.askConfirmMessage("Burp Proxy Import", message,
                        new String[] { "Import", "Cancel" });

                if (result == JOptionPane.OK_OPTION) {
                    boolean sendToAutoExporters = false;
                    if (LoggerPlusPlus.instance.getExportController().getEnabledExporters().size() > 0) {
                        int res = JOptionPane.showConfirmDialog(LoggerPlusPlus.instance.getLoggerFrame(),
                                "One or more auto-exporters are currently enabled. " +
                                        "Do you want the imported entries to also be sent to the auto-exporters?",
                                "Auto-exporters Enabled", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
                        sendToAutoExporters = res == JOptionPane.YES_OPTION;
                    }

                    preferencesController.getLoggerPlusPlus().getLogProcessor().importProxyHistory(sendToAutoExporters);
                }
            }
        }));

        importGroup.add(new JButton(new AbstractAction("Import From WStalker CSV") {
            @Override
            public void actionPerformed(ActionEvent e) {
                ArrayList<IHttpRequestResponse> requests = LoggerImport.importWStalker();
                if (LoggerPlusPlus.instance.getExportController().getEnabledExporters().size() > 0) {
                    int res = JOptionPane.showConfirmDialog(LoggerPlusPlus.instance.getLoggerFrame(),
                            "One or more auto-exporters are currently enabled. " +
                                    "Do you want the imported entries to also be sent to the auto-exporters?",
                            "Auto-exporters Enabled", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
                    LoggerImport.loadImported(requests, res == JOptionPane.YES_OPTION);
                } else {
                    LoggerImport.loadImported(requests, false);
                }
            }
        }));

        importGroup.add(new JButton(new AbstractAction("Import From OWASP ZAP") {
            @Override
            public void actionPerformed(ActionEvent e) {
                ArrayList<IHttpRequestResponse> requests = LoggerImport.importZAP();

                if (LoggerPlusPlus.instance.getExportController().getEnabledExporters().size() > 0) {
                    int res = JOptionPane.showConfirmDialog(LoggerPlusPlus.instance.getLoggerFrame(),
                            "One or more auto-exporters are currently enabled. " +
                                    "Do you want the imported entries to also be sent to the auto-exporters?",
                            "Auto-exporters Enabled", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
                    LoggerImport.loadImported(requests, res == JOptionPane.YES_OPTION);
                } else {
                    LoggerImport.loadImported(requests, false);
                }
            }
        }));

        ComponentGroup exportGroup = new ComponentGroup(Orientation.HORIZONTAL);
        HashMap<Class<? extends LogExporter>, LogExporter> exporters = preferencesController.getLoggerPlusPlus()
                .getExportController().getExporters();
        exportGroup.add(((ExportPanelProvider) exporters.get(CSVExporter.class)).getExportPanel());
        exportGroup.add(((ExportPanelProvider) exporters.get(JSONExporter.class)).getExportPanel());
        exportGroup.add(((ExportPanelProvider) exporters.get(HARExporter.class)).getExportPanel());
        exportGroup.add(((ExportPanelProvider) exporters.get(ElasticExporter.class)).getExportPanel());

        ComponentGroup otherPanel = new ComponentGroup(Orientation.VERTICAL, "Other");
        JSpinner spnRespTimeout = otherPanel.addPreferenceComponent(preferences, PREF_RESPONSE_TIMEOUT,
                "Response Timeout (Seconds): ");
        ((SpinnerNumberModel) spnRespTimeout.getModel()).setMinimum(10);
        ((SpinnerNumberModel) spnRespTimeout.getModel()).setMaximum(600);
        ((SpinnerNumberModel) spnRespTimeout.getModel()).setStepSize(10);

        JSpinner spnMaxEntries = otherPanel.addPreferenceComponent(preferences, PREF_MAXIMUM_ENTRIES,
                "Maximum Log Entries: ");
        ((SpinnerNumberModel) spnMaxEntries.getModel()).setMinimum(10);
        ((SpinnerNumberModel) spnMaxEntries.getModel()).setMaximum(Integer.MAX_VALUE);
        ((SpinnerNumberModel) spnMaxEntries.getModel()).setStepSize(10);

        JSpinner spnSearchThreads = otherPanel.addPreferenceComponent(preferences, PREF_SEARCH_THREADS,
                "Search Threads: ");
        ((SpinnerNumberModel) spnSearchThreads.getModel()).setMinimum(1);
        ((SpinnerNumberModel) spnSearchThreads.getModel()).setMaximum(50);
        ((SpinnerNumberModel) spnSearchThreads.getModel()).setStepSize(1);

        JSpinner maxResponseSize = otherPanel.addPreferenceComponent(preferences, PREF_MAX_RESP_SIZE,
                "Maximum Response Size (MB): ");
        ((SpinnerNumberModel) maxResponseSize.getModel()).setMinimum(0);
        ((SpinnerNumberModel) maxResponseSize.getModel()).setMaximum(1000000);
        ((SpinnerNumberModel) maxResponseSize.getModel()).setStepSize(1);

        ComponentGroup savedFilterSharing = new ComponentGroup(Orientation.VERTICAL, "Saved Filter Sharing");
        savedFilterSharing.add(new JButton(new AbstractAction("Import Saved Filters") {
            @Override
            public void actionPerformed(ActionEvent e) {
                String json = MoreHelp.showLargeInputDialog("Import Saved Filters", null);
                ArrayList<SavedFilter> importedFilters = preferencesController.getGsonProvider().getGson()
                        .fromJson(json, new TypeToken<ArrayList<SavedFilter>>() {
                        }.getType());
                ArrayList<SavedFilter> savedFilters = preferences.getSetting(PREF_SAVED_FILTERS);
                for (SavedFilter importedFilter : importedFilters) {
                    if (!savedFilters.contains(importedFilter))
                        savedFilters.add(importedFilter);
                }
                preferences.setSetting(PREF_SAVED_FILTERS, savedFilters);
            }
        }));

        savedFilterSharing.add(new JButton(new AbstractAction("Export Saved Filters") {
            @Override
            public void actionPerformed(ActionEvent e) {
                ArrayList<SavedFilter> savedFilters = preferences.getSetting(PREF_SAVED_FILTERS);
                String jsonOutput = preferencesController.getGsonProvider().getGson().toJson(savedFilters);
                MoreHelp.showLargeOutputDialog("Export Saved Filters", jsonOutput);
            }
        }));

        ComponentGroup colorFilterSharing = new ComponentGroup(Orientation.VERTICAL, "Color Filter Sharing");
        colorFilterSharing.add(new JButton(new AbstractAction("Import Color Filters") {
            @Override
            public void actionPerformed(ActionEvent e) {
                String json = MoreHelp.showLargeInputDialog("Import Color Filters", null);
                Map<UUID, ColorFilter> colorFilterMap = preferencesController.getGsonProvider().getGson().fromJson(json,
                        new TypeToken<Map<UUID, ColorFilter>>() {
                        }.getType());
                for (ColorFilter colorFilter : colorFilterMap.values()) {
                    LoggerPlusPlus.instance.getLibraryController().addColorFilter(colorFilter);
                }
            }
        }));

        colorFilterSharing.add(new JButton(new AbstractAction("Export Color Filters") {
            @Override
            public void actionPerformed(ActionEvent e) {
                HashMap<UUID, ColorFilter> colorFilters = preferences.getSetting(PREF_COLOR_FILTERS);
                String jsonOutput = preferencesController.getGsonProvider().getGson().toJson(colorFilters);
                MoreHelp.showLargeOutputDialog("Export Color Filters", jsonOutput);
            }
        }));

        ComponentGroup reflectionsPanel = new ComponentGroup(Orientation.HORIZONTAL, "Reflections");
        reflectionsPanel.add(new JButton(new AbstractAction("Configure Filters") {
            @Override
            public void actionPerformed(ActionEvent e) {
                LoggerPlusPlus.instance.getReflectionController().showFilterConfigDialog();
            }
        }));
        reflectionsPanel.add(new JButton(new AbstractAction("Configure Transformation Detectors") {
            @Override
            public void actionPerformed(ActionEvent e) {
                LoggerPlusPlus.instance.getReflectionController().showValueTransformerDialog();
            }
        }));

        ComponentGroup resetPanel = new ComponentGroup(Orientation.VERTICAL, "Reset");
        resetPanel.add(new JButton(new AbstractAction("Reset All Settings") {
            @Override
            public void actionPerformed(ActionEvent e) {
                int result = JOptionPane.showConfirmDialog(null,
                        "Are you sure you wish to reset all settings? This includes the table layout!", "Warning",
                        JOptionPane.YES_NO_OPTION);
                if (result == JOptionPane.YES_OPTION) {
                    preferences.resetSettings(preferences.getRegisteredSettings().keySet());
                    preferencesController.getLoggerPlusPlus().getLogViewController().getLogTableController()
                            .reinitialize();
                }
            }
        }));

        resetPanel.add(new JButton(new AbstractAction("Clear The Logs") {
            @Override
            public void actionPerformed(ActionEvent e) {
                preferencesController.getLoggerPlusPlus().getLogViewController().getLogTableController().reset();
            }
        }));

        ComponentGroup notesPanel = new ComponentGroup(Orientation.VERTICAL, "Notes");
        notesPanel.add(new JLabel("Note 0: Right click on columns' headers to change settings."));
        notesPanel.add(new JLabel("Note 1: Extensive logging  may affect Burp Suite performance."));
        notesPanel.add(new JLabel(
                "Note 2: Automatic logging does not saveFilters requests and responses. Only table contents. "));
        notesPanel.add(
                new JLabel("Note 3: Full request/response logging available in 'Project Options > Misc > Logging'"));
        notesPanel.add(new JLabel("Note 4: Updating the extension will reset the log table settings."));

        JComponent mainComponent = PanelBuilder
                .build(new JPanel[][] { new JPanel[] { statusPanel, statusPanel, statusPanel, statusPanel },
                        new JPanel[] { logFromPanel, importGroup, importGroup, importGroup },
                        new JPanel[] { logFromPanel, exportGroup, exportGroup, exportGroup },
                        new JPanel[] { savedFilterSharing, savedFilterSharing, colorFilterSharing, colorFilterSharing },
                        new JPanel[] { reflectionsPanel, reflectionsPanel, reflectionsPanel, reflectionsPanel },
                        new JPanel[] { otherPanel, otherPanel, otherPanel, otherPanel },
                        new JPanel[] { resetPanel, resetPanel, resetPanel, resetPanel },
                        new JPanel[] { notesPanel, notesPanel, notesPanel, notesPanel }, }, Alignment.TOPMIDDLE, 0, 0);

        this.setViewportView(mainComponent);
    }

    private void toggleEnabledButton(boolean isSelected) {
        tglbtnIsEnabled.setText(APP_NAME + (isSelected ? " is running" : " has been stopped"));
        tglbtnIsEnabled.setSelected(isSelected);
        preferences.setSetting(PREF_ENABLED, isSelected);
    }
}
