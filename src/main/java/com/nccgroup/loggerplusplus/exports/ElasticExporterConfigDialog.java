package com.nccgroup.loggerplusplus.exports;

import com.coreyd97.BurpExtenderUtilities.Alignment;
import com.coreyd97.BurpExtenderUtilities.PanelBuilder;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.loggerplusplus.logentry.LogEntryField;
import com.nccgroup.loggerplusplus.util.MoreHelp;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
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
        JTextField apiKeySecret = PanelBuilder.createPreferenceTextField(preferences, PREF_ELASTIC_API_KEY_SECRET);
        JTextField username = PanelBuilder.createPreferenceTextField(preferences, PREF_ELASTIC_USERNAME);
        JTextField password = PanelBuilder.createPreferenceTextField(preferences, PREF_ELASTIC_PASSWORD);

        JComboBox<ElasticAuthType> elasticAuthType = new JComboBox<>(ElasticAuthType.values());

        Runnable setAuthFields = () -> {
            if (ElasticAuthType.ApiKey.equals(elasticAuthType.getSelectedItem())) {
                authUserLabel.setText("Key ID: ");
                authPassLabel.setText("Key Secret: ");
                userPanel.add(apiKeyId, BorderLayout.CENTER);
                passPanel.add(apiKeySecret, BorderLayout.CENTER);
            } else if (ElasticAuthType.Basic.equals(elasticAuthType.getSelectedItem())) {
                authUserLabel.setText("Username: ");
                authPassLabel.setText("Password: ");
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


        this.add(PanelBuilder.build(new JComponent[][]{
                new JComponent[]{new JLabel("Address: "), addressField},
                new JComponent[]{new JLabel("Port: "), elasticPortSpinner},
                new JComponent[]{new JLabel("Protocol: "), protocolSelector},
                new JComponent[]{new JLabel("Auth: "), elasticAuthType},
                new JComponent[]{authUserLabel, userPanel},
                new JComponent[]{authPassLabel, passPanel},
                new JComponent[]{new JLabel("Index: "), indexNameField},
                new JComponent[]{new JLabel("Upload Frequency (Seconds): "), elasticDelaySpinner},
                new JComponent[]{new JLabel("Exported Fields: "), configureFieldsButton},
                new JComponent[]{new JLabel("Autostart Exporter (All Projects): "), autostartGlobal},
                new JComponent[]{new JLabel("Autostart Exporter (This Project): "), autostartProject},
        }, new int[][]{
                new int[]{0, 1},
                new int[]{0, 1},
                new int[]{0, 1},
                new int[]{0, 1},
                new int[]{0, 1},
                new int[]{0, 1},
        }, Alignment.CENTER, 1.0, 1.0, 5, 5), BorderLayout.CENTER);

        setAuthFields.run();

        this.pack();
        this.setResizable(true);
        this.setDefaultCloseOperation(DISPOSE_ON_CLOSE);
    }
}
