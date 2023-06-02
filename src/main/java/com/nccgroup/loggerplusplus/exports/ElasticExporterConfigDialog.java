package com.nccgroup.loggerplusplus.exports;

import com.coreyd97.BurpExtenderUtilities.Alignment;
import com.coreyd97.BurpExtenderUtilities.ComponentGroup;
import com.coreyd97.BurpExtenderUtilities.PanelBuilder;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.filter.logfilter.LogTableFilter;
import com.nccgroup.loggerplusplus.filter.parser.ParseException;
import com.nccgroup.loggerplusplus.filterlibrary.FilterLibraryController;
import com.nccgroup.loggerplusplus.logentry.LogEntryField;
import com.nccgroup.loggerplusplus.util.Globals;
import com.nccgroup.loggerplusplus.util.MoreHelp;
import org.apache.commons.lang3.StringUtils;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.util.List;
import java.util.Objects;

import static com.nccgroup.loggerplusplus.util.Globals.*;

public class ElasticExporterConfigDialog extends JDialog {

    ElasticExporterConfigDialog(Frame owner, ElasticExporter elasticExporter){
        super(owner, "Elastic Exporter Configuration", true);

        this.setLayout(new BorderLayout());
        Preferences preferences = elasticExporter.getPreferences();

        JTextField addressField = PanelBuilder.createPreferenceTextField(preferences, PREF_ELASTIC_ADDRESS);
        JSpinner elasticPortSpinner = PanelBuilder.createPreferenceSpinner(preferences, PREF_ELASTIC_PORT);
        ((SpinnerNumberModel) elasticPortSpinner.getModel()).setMaximum(65535);
        ((SpinnerNumberModel) elasticPortSpinner.getModel()).setMinimum(0);
        elasticPortSpinner.setEditor(new JSpinner.NumberEditor(elasticPortSpinner, "#"));

        JComboBox<Protocol> protocolSelector = new JComboBox<>(Protocol.values());
        protocolSelector.addActionListener(actionEvent -> {
            elasticExporter.getPreferences().setSetting(PREF_ELASTIC_PROTOCOL, protocolSelector.getSelectedItem());
        });

        JLabel authUserLabel = new JLabel(), authPassLabel = new JLabel();
        JPanel userPanel = new JPanel(new BorderLayout());
        JPanel passPanel = new JPanel(new BorderLayout());

        JTextField apiKeyId = PanelBuilder.createPreferenceTextField(preferences, PREF_ELASTIC_API_KEY_ID);
        JTextField apiKeySecret = PanelBuilder.createPreferencePasswordField(preferences, PREF_ELASTIC_API_KEY_SECRET);
        JTextField username = PanelBuilder.createPreferenceTextField(preferences, PREF_ELASTIC_USERNAME);
        JTextField password = PanelBuilder.createPreferencePasswordField(preferences, PREF_ELASTIC_PASSWORD);

        JComboBox<ElasticAuthType> elasticAuthType = new JComboBox<>(ElasticAuthType.values());
        elasticAuthType.setSelectedItem(preferences.getSetting(PREF_ELASTIC_AUTH));

        Runnable setAuthFields = () -> {
            ElasticAuthType authType = preferences.getSetting(PREF_ELASTIC_AUTH);

            if (ElasticAuthType.ApiKey.equals(authType)) {
                authUserLabel.setText("Key ID: ");
                authPassLabel.setText("Key Secret: ");
                userPanel.remove(username);
                passPanel.remove(password);
                userPanel.add(apiKeyId, BorderLayout.CENTER);
                passPanel.add(apiKeySecret, BorderLayout.CENTER);
            } else if (ElasticAuthType.Basic.equals(authType)) {
                authUserLabel.setText("Username: ");
                authPassLabel.setText("Password: ");
                userPanel.remove(apiKeyId);
                passPanel.remove(apiKeySecret);
                userPanel.add(username, BorderLayout.CENTER);
                passPanel.add(password, BorderLayout.CENTER);
            }

            if (ElasticAuthType.None.equals(elasticAuthType.getSelectedItem())) {
                authUserLabel.setVisible(false);
                authPassLabel.setVisible(false);
                userPanel.setVisible(false);
                passPanel.setVisible(false);
            } else {
                authUserLabel.setVisible(true);
                authPassLabel.setVisible(true);
                userPanel.setVisible(true);
                passPanel.setVisible(true);
            }
        };

        elasticAuthType.addActionListener(actionEvent -> {
            elasticExporter.getPreferences().setSetting(PREF_ELASTIC_AUTH, elasticAuthType.getSelectedItem());
            setAuthFields.run();
        });


        //TODO Update PanelBuilder to allow labels with custom components

        JTextField indexNameField = PanelBuilder.createPreferenceTextField(preferences, PREF_ELASTIC_INDEX);
        JSpinner elasticDelaySpinner = PanelBuilder.createPreferenceSpinner(preferences, PREF_ELASTIC_DELAY);
        ((SpinnerNumberModel) elasticDelaySpinner.getModel()).setMaximum(99999);
        ((SpinnerNumberModel) elasticDelaySpinner.getModel()).setMinimum(10);
        ((SpinnerNumberModel) elasticDelaySpinner.getModel()).setStepSize(10);

        JButton configureFieldsButton = new JButton(new AbstractAction("Configure") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                List<LogEntryField> selectedFields = MoreHelp.showFieldChooserDialog(indexNameField,
                        preferences, "Elastic Exporter", elasticExporter.getFields());

                if(selectedFields == null){
                    //Cancelled.
                } else if (!selectedFields.isEmpty()) {
                    elasticExporter.setFields(selectedFields);
                } else {
                    JOptionPane.showMessageDialog(indexNameField,
                            "No fields were selected. No changes have been made.",
                            "Elastic Exporter", JOptionPane.INFORMATION_MESSAGE);
                }
            }
        });


        String projectPreviousFilterString = preferences.getSetting(Globals.PREF_ELASTIC_FILTER_PROJECT_PREVIOUS);
        String filterString = preferences.getSetting(Globals.PREF_ELASTIC_FILTER);
        if (projectPreviousFilterString != null && !Objects.equals(projectPreviousFilterString, filterString)) {
            int res = JOptionPane.showConfirmDialog(LoggerPlusPlus.instance.getLoggerFrame(),
                    "Looks like the log filter has been changed since you last used this Burp project.\n" +
                            "Do you want to restore the previous filter used by the project?\n" +
                            "\n" +
                            "Previously used filter: " + projectPreviousFilterString + "\n" +
                            "Current filter: " + filterString, "ElasticSearch Exporter Log Filter",
                    JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            if (res == JOptionPane.YES_OPTION) {
                preferences.setSetting(PREF_ELASTIC_FILTER, projectPreviousFilterString);
            }
        }

        JTextField filterField = PanelBuilder.createPreferenceTextField(preferences, PREF_ELASTIC_FILTER);
        filterField.setMinimumSize(new Dimension(600, 0));

        JCheckBox autostartGlobal = PanelBuilder.createPreferenceCheckBox(preferences, PREF_ELASTIC_AUTOSTART_GLOBAL);
        JCheckBox autostartProject = PanelBuilder.createPreferenceCheckBox(preferences, PREF_ELASTIC_AUTOSTART_PROJECT);

        //If global autostart is on, it overrides the per-project setting.
        autostartProject.setEnabled(!(boolean) preferences.getSetting(PREF_ELASTIC_AUTOSTART_GLOBAL));
        preferences.addSettingListener((source, settingName, newValue) -> {
            if (Objects.equals(settingName, PREF_ELASTIC_AUTOSTART_GLOBAL)) {
                autostartProject.setEnabled(!(boolean) newValue);
                if ((boolean) newValue) {
                    preferences.setSetting(PREF_ELASTIC_AUTOSTART_PROJECT, true);
                }
            }
        });

//        new JComponent[]{new JLabel("Address: "), addressField},
//                new JComponent[]{new JLabel("Port: "), elasticPortSpinner},
//                new JComponent[]{new JLabel("Protocol: "), protocolSelector},

        ComponentGroup connectionGroup = new ComponentGroup(ComponentGroup.Orientation.VERTICAL, "Connection");
        connectionGroup.addComponentWithLabel("Address: ", addressField);
        connectionGroup.addComponentWithLabel("Port: ", elasticPortSpinner);
        connectionGroup.addComponentWithLabel("Protocol: ", protocolSelector);
        connectionGroup.addComponentWithLabel("Index: ", indexNameField);

        ComponentGroup authGroup = new ComponentGroup(ComponentGroup.Orientation.VERTICAL, "Authentication");
        authGroup.add(PanelBuilder.build(new Component[][]{
                new JComponent[]{new JLabel("Auth: "), elasticAuthType},
                new JComponent[]{authUserLabel, userPanel},
                new JComponent[]{authPassLabel, passPanel}
        }, new int[][]{
                new int[]{0, 1},
                new int[]{0, 1},
                new int[]{0, 1}
        }, Alignment.FILL, 1, 1));

        ComponentGroup miscGroup = new ComponentGroup(ComponentGroup.Orientation.VERTICAL, "Misc");
        miscGroup.add(PanelBuilder.build(new Component[][]{
                new JComponent[]{new JLabel("Upload Frequency (Seconds): "), elasticDelaySpinner},
                new JComponent[]{new JLabel("Exported Fields: "), configureFieldsButton},
                new JComponent[]{new JLabel("Log Filter: "), filterField},
                new JComponent[]{new JLabel("Autostart Exporter (All Projects): "), autostartGlobal},
                new JComponent[]{new JLabel("Autostart Exporter (This Project): "), autostartProject},
        }, new int[][]{
                new int[]{0, 1},
                new int[]{0, 1},
                new int[]{0, 1},
                new int[]{0, 1},
                new int[]{0, 1}
        }, Alignment.FILL, 1, 1));


        PanelBuilder panelBuilder = new PanelBuilder();
        panelBuilder.setComponentGrid(new JComponent[][]{
                new JComponent[]{connectionGroup},
                new JComponent[]{authGroup},
                new JComponent[]{miscGroup}
        });
        int[][] weights = new int[][]{
                new int[]{1},
                new int[]{1},
                new int[]{1},
        };
        panelBuilder.setGridWeightsY(weights)
                    .setGridWeightsX(weights)
                    .setAlignment(Alignment.CENTER)
                    .setInsetsX(5)
                    .setInsetsY(5);

        this.add(panelBuilder.build(), BorderLayout.CENTER);

        setAuthFields.run();

        this.setMinimumSize(new Dimension(600, 200));

        this.pack();
        this.setResizable(true);
        this.setDefaultCloseOperation(DO_NOTHING_ON_CLOSE);

        this.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                String logFilter = preferences.getSetting(PREF_ELASTIC_FILTER);

                if (!StringUtils.isBlank(logFilter)) {
                    try {
                        new LogTableFilter(logFilter);
                    } catch (ParseException ex) {
                        JOptionPane.showMessageDialog(ElasticExporterConfigDialog.this,
                                "Cannot save Elastic Exporter configuration. The chosen log filter is invalid: \n" +
                                        ex.getMessage(), "Invalid Elastic Exporter Configuration", JOptionPane.ERROR_MESSAGE);
                        return;
                    }
                }
                ElasticExporterConfigDialog.this.dispose();
                super.windowClosing(e);
            }
        });
    }
}
