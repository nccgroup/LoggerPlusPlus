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

import com.coreyd97.BurpExtenderUtilities.PanelBuilder;
import com.google.gson.reflect.TypeToken;
import loggerplusplus.FileLogger;
import loggerplusplus.LoggerPlusPlus;
import loggerplusplus.MoreHelp;
import loggerplusplus.filter.ColorFilter;
import loggerplusplus.filter.FilterListener;
import loggerplusplus.filter.SavedFilter;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static loggerplusplus.Globals.*;

public class LoggerOptionsPanel extends JScrollPane{

    private final JToggleButton tglbtnIsEnabled;
    private JToggleButton btnAutoSaveLogs;
    private final JToggleButton esEnabled;
    private final JLabel esValueChangeWarning = new JLabel("Warning: Changing preferences while running will disable the upload service and clear all pending values.");
    private final FileLogger fileLogger;


    /**
     * Create the panel.
     */
    public LoggerOptionsPanel() {
        PanelBuilder panelBuilder = new PanelBuilder(LoggerPlusPlus.preferences);
        this.fileLogger = new FileLogger();
        this.esValueChangeWarning.setForeground(Color.RED);
        JPanel innerContainer = new JPanel(new GridBagLayout());


        PanelBuilder.ComponentGroup statusPanel = panelBuilder.createComponentGroup("Status");
        tglbtnIsEnabled = statusPanel.addToggleButton("Logger++ is running", actionEvent -> {
            JToggleButton thisButton = (JToggleButton) actionEvent.getSource();
            toggleEnabledButton(thisButton.isSelected());
        });
        tglbtnIsEnabled.setSelected((Boolean) LoggerPlusPlus.preferences.getSetting(PREF_ENABLED));

                PanelBuilder.ComponentGroup logFromPanel = panelBuilder.createComponentGroup("Log From");
        logFromPanel.addSetting(PREF_RESTRICT_TO_SCOPE, "In scope items only");
        GridBagConstraints strutConstraints = logFromPanel.generateNextConstraints();
        strutConstraints.weighty = strutConstraints.weightx = 0;
        logFromPanel.addComponent((JComponent) Box.createVerticalStrut(10), strutConstraints);
        JCheckBox logAllTools = (JCheckBox) logFromPanel.addSetting(PREF_LOG_GLOBAL, "All Tools");
        JCheckBox logSpider = (JCheckBox) logFromPanel.addSetting(PREF_LOG_SPIDER, "Spider");
        JCheckBox logIntruder = (JCheckBox) logFromPanel.addSetting(PREF_LOG_INTRUDER, "Intruder");
        JCheckBox logScanner = (JCheckBox) logFromPanel.addSetting(PREF_LOG_SCANNER, "Scanner");
        JCheckBox logRepeater = (JCheckBox) logFromPanel.addSetting(PREF_LOG_REPEATER, "Repeater");
        JCheckBox logSequencer = (JCheckBox) logFromPanel.addSetting(PREF_LOG_SEQUENCER, "Sequencer");
        JCheckBox logProxy = (JCheckBox) logFromPanel.addSetting(PREF_LOG_PROXY, "Proxy");
        JCheckBox logTarget = (JCheckBox) logFromPanel.addSetting(PREF_LOG_TARGET_TAB, "Target");
        JCheckBox logExtender = (JCheckBox) logFromPanel.addSetting(PREF_LOG_EXTENDER, "Extender");

        strutConstraints = logFromPanel.generateNextConstraints();
        strutConstraints.weighty = strutConstraints.weightx = 0;
        logFromPanel.addComponent((JComponent) Box.createVerticalStrut(10), strutConstraints);
        logFromPanel.addSetting(PREF_LOG_OTHER_LIVE, "Log Non-Proxy Tools Live");

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

        PanelBuilder.ComponentGroup importGroup = panelBuilder.createComponentGroup("Import");
        importGroup.addSetting(PREF_AUTO_IMPORT_PROXY_HISTORY, "Import proxy history on startup");
        importGroup.addButton("Import Burp Proxy History", actionEvent -> {
            LoggerPlusPlus.instance.getLogManager().importProxyHistory(true);
        });

        importGroup.addButton("Import From CSV (Not Implemented)", null).setEnabled(false);


        PanelBuilder.ComponentGroup exportGroup = panelBuilder.createComponentGroup("Export");
        exportGroup.addButton("Save log table as CSV", actionEvent -> {
            fileLogger.saveLogs(false);
        });
        exportGroup.addButton("Save full logs as CSV (slow)", actionEvent -> {
            fileLogger.saveLogs(true);
        });
        btnAutoSaveLogs = exportGroup.addToggleButton("Autosave as CSV", actionEvent -> {
            fileLogger.setAutoSave(!(boolean) LoggerPlusPlus.preferences.getSetting(PREF_AUTO_SAVE));
        });

        PanelBuilder.ComponentGroup elasticPanel = panelBuilder.createComponentGroup("Elastic Search");
        esEnabled = elasticPanel.addToggleButton("Disabled", actionEvent -> {
            JToggleButton thisButton = (JToggleButton) actionEvent.getSource();
            toggleEsEnabledButton(thisButton.isSelected());
        });

        JSeparator separator = new JSeparator(SwingConstants.HORIZONTAL);
        separator.setBorder(BorderFactory.createEmptyBorder(5,0,5,0));
        elasticPanel.addComponent(separator);

        elasticPanel.addSetting(PREF_ELASTIC_ADDRESS, "Address: ");
        JSpinner elasticPort = (JSpinner) elasticPanel.addSetting(PREF_ELASTIC_PORT, "Port: ");
        ((SpinnerNumberModel) elasticPort.getModel()).setMaximum(65535);
        ((SpinnerNumberModel) elasticPort.getModel()).setMinimum(0);
        elasticPort.setEditor(new JSpinner.NumberEditor(elasticPort,"#"));

        elasticPanel.addSetting(PREF_ELASTIC_CLUSTER_NAME, "Cluster Name: ");
        elasticPanel.addSetting(PREF_ELASTIC_INDEX, "Index: ");
        JSpinner elasticDelay = (JSpinner) elasticPanel.addSetting(PREF_ELASTIC_DELAY, "Upload Delay (Seconds): ");
        ((SpinnerNumberModel) elasticDelay.getModel()).setMaximum(99999);
        ((SpinnerNumberModel) elasticDelay.getModel()).setMinimum(10);
        ((SpinnerNumberModel) elasticDelay.getModel()).setStepSize(10);
        elasticPanel.addSetting(PREF_ELASTIC_INCLUDE_REQ_RESP, "Include Request and Response: ");

        PanelBuilder.ComponentGroup otherPanel = panelBuilder.createComponentGroup("Other");
        JSpinner spnRespTimeout = (JSpinner) otherPanel.addSetting(PREF_RESPONSE_TIMEOUT, "Response Timeout (ms): ");
        ((SpinnerNumberModel) spnRespTimeout.getModel()).setMinimum(10);
        ((SpinnerNumberModel) spnRespTimeout.getModel()).setMaximum(600);
        ((SpinnerNumberModel) spnRespTimeout.getModel()).setStepSize(10);

        JSpinner spnMaxEntries = (JSpinner) otherPanel.addSetting(PREF_MAXIMUM_ENTRIES, "Maximum Log Entries: ");
        ((SpinnerNumberModel) spnMaxEntries.getModel()).setMinimum(10);
        ((SpinnerNumberModel) spnMaxEntries.getModel()).setMaximum(Integer.MAX_VALUE);
        ((SpinnerNumberModel) spnMaxEntries.getModel()).setStepSize(10);

        JSpinner spnSearchThreads = (JSpinner) otherPanel.addSetting(PREF_SEARCH_THREADS, "Search Threads: ");
        ((SpinnerNumberModel) spnSearchThreads.getModel()).setMinimum(1);
        ((SpinnerNumberModel) spnSearchThreads.getModel()).setMaximum(50);
        ((SpinnerNumberModel) spnSearchThreads.getModel()).setStepSize(1);

        if(!LoggerPlusPlus.callbacks.isExtensionBapp()) {
            otherPanel.addSetting(PREF_UPDATE_ON_STARTUP, "Check For Updates");
        }
        
        PanelBuilder.ComponentGroup savedFilterSharing = panelBuilder.createComponentGroup("Saved LogFilter Sharing");
        savedFilterSharing.addButton("Import Saved Filters", actionEvent -> {
            String json = MoreHelp.showLargeInputDialog("Import Saved Filters", null);
            ArrayList<SavedFilter> importedFilters = LoggerPlusPlus.gsonProvider.getGson().fromJson(json,
                    new TypeToken<ArrayList<SavedFilter>>(){}.getType());
            ArrayList<SavedFilter> savedFilters = (ArrayList<SavedFilter>) LoggerPlusPlus.preferences.getSetting(PREF_SAVED_FILTERS);
            ArrayList<SavedFilter> savedFiltersClone = new ArrayList<>(savedFilters);
            for (SavedFilter importedFilter : importedFilters) {
                if(!savedFiltersClone.contains(importedFilter)) savedFiltersClone.add(importedFilter);
            }
            LoggerPlusPlus.preferences.setSetting(PREF_SAVED_FILTERS, savedFiltersClone);
        });
        savedFilterSharing.addButton("Export Saved Filters", actionEvent -> {
            ArrayList<SavedFilter> savedFilters = (ArrayList<SavedFilter>) LoggerPlusPlus.preferences.getSetting(PREF_SAVED_FILTERS);
            String jsonOutput = LoggerPlusPlus.gsonProvider.getGson().toJson(savedFilters);
            MoreHelp.showLargeOutputDialog("Export Saved Filters", jsonOutput);
        });

        PanelBuilder.ComponentGroup colorFilterSharing = panelBuilder.createComponentGroup("Color LogFilter Sharing");
        colorFilterSharing.addButton("Import Color Filters", actionEvent -> {
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
        });
        colorFilterSharing.addButton("Export Color Filters", actionEvent -> {
            HashMap<UUID,ColorFilter> colorFilters = (HashMap<UUID, ColorFilter>) LoggerPlusPlus.preferences.getSetting(PREF_COLOR_FILTERS);
            String jsonOutput = LoggerPlusPlus.gsonProvider.getGson().toJson(colorFilters);
            MoreHelp.showLargeOutputDialog("Export Color Filters", jsonOutput);
        });

        PanelBuilder.ComponentGroup resetPanel = panelBuilder.createComponentGroup("Reset");
        resetPanel.addButton("Reset All Settings", actionEvent -> {
            int result = JOptionPane.showConfirmDialog(null, "Are you sure you wish to reset all settings? This includes the table layout!", "Warning", JOptionPane.YES_NO_OPTION);
            if(result == JOptionPane.YES_OPTION){
                LoggerPlusPlus.preferences.resetSettings(LoggerPlusPlus.preferences.getPreferenceKeys());
                LoggerPlusPlus.instance.getLogTable().getColumnModel().resetToDefaultVariables();
                LoggerPlusPlus.instance.getLogTable().getModel().fireTableStructureChanged();
            }
        });
        resetPanel.addButton("Clear The Logs", actionEvent -> {
            LoggerPlusPlus.instance.reset();
        });


        PanelBuilder.ComponentGroup notesPanel = panelBuilder.createComponentGroup("Notes");
        notesPanel.addComponent(new JLabel("Note 0: Right click on columns' headers to change settings."));
        notesPanel.addComponent(new JLabel("Note 1: Extensive logging  may affect Burp Suite performance."));
        notesPanel.addComponent(new JLabel("Note 2: Automatic logging does not save requests and responses. Only table contents. "));
        notesPanel.addComponent(new JLabel("Note 3: Full request/response logging available in 'Project Options > Misc > Logging'"));
        notesPanel.addComponent(new JLabel("Note 4: Updating the extension will reset the log table settings."));

        JComponent mainComponent;

        try {
            mainComponent = panelBuilder.build(new JPanel[][]{
                    new JPanel[]{statusPanel, statusPanel},
                    new JPanel[]{logFromPanel, importGroup},
                    new JPanel[]{logFromPanel, exportGroup},
                    new JPanel[]{elasticPanel, elasticPanel},
                    new JPanel[]{otherPanel, otherPanel},
                    new JPanel[]{colorFilterSharing, savedFilterSharing},
                    new JPanel[]{resetPanel, resetPanel},
                    new JPanel[]{notesPanel, notesPanel},
            }, PanelBuilder.Alignment.TOPMIDDLE);
        } catch (Exception e) {
            e.printStackTrace();
            mainComponent = new JLabel("Could not buildPreferences the options panel!");
        }

        this.setViewportView(mainComponent);
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

    public FileLogger getFileLogger() {
        return fileLogger;
    }
}
