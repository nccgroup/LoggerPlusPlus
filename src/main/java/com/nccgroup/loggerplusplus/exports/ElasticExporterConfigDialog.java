package com.nccgroup.loggerplusplus.exports;

import com.coreyd97.BurpExtenderUtilities.Alignment;
import com.coreyd97.BurpExtenderUtilities.ComponentGroup;
import com.coreyd97.BurpExtenderUtilities.PanelBuilder;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.loggerplusplus.util.FieldSelectorDialog;

import javax.swing.*;

import java.awt.*;
import java.awt.event.ActionEvent;

import static com.nccgroup.loggerplusplus.util.Globals.*;
import static com.nccgroup.loggerplusplus.util.Globals.PREF_ELASTIC_INCLUDE_REQ_RESP;

public class ElasticExporterConfigDialog extends JDialog {

    ElasticExporterConfigDialog(Frame owner, ElasticExporter elasticExporter){
        super(owner, "Elastic Exporter Configuration", true);

        this.setLayout(new BorderLayout());
        Preferences preferences = elasticExporter.getPreferences();

        JTextField addressField = PanelBuilder.createPreferenceTextField(preferences, PREF_ELASTIC_ADDRESS);
        JSpinner elasticPortSpinner = PanelBuilder.createPreferenceSpinner(preferences, PREF_ELASTIC_PORT);
        ((SpinnerNumberModel) elasticPortSpinner.getModel()).setMaximum(65535);
        ((SpinnerNumberModel) elasticPortSpinner.getModel()).setMinimum(0);
        elasticPortSpinner.setEditor(new JSpinner.NumberEditor(elasticPortSpinner,"#"));

        JComboBox<Protocol> protocolSelector = new JComboBox<>(Protocol.values());
        protocolSelector.addActionListener(actionEvent -> {
            elasticExporter.getPreferences().setSetting(PREF_ELASTIC_PROTOCOL, protocolSelector.getSelectedItem());
        });

        //TODO Update PanelBuilder to allow labels with custom components

        JTextField clusterNameField = PanelBuilder.createPreferenceTextField(preferences, PREF_ELASTIC_CLUSTER_NAME);
        JTextField indexNameField = PanelBuilder.createPreferenceTextField(preferences, PREF_ELASTIC_INDEX);
        JSpinner elasticDelaySpinner = PanelBuilder.createPreferenceSpinner(preferences, PREF_ELASTIC_DELAY);
        ((SpinnerNumberModel) elasticDelaySpinner.getModel()).setMaximum(99999);
        ((SpinnerNumberModel) elasticDelaySpinner.getModel()).setMinimum(10);
        ((SpinnerNumberModel) elasticDelaySpinner.getModel()).setStepSize(10);

        JButton configureFieldsButton = new JButton(new AbstractAction("Configure") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                FieldSelectorDialog fieldSelectorDialog = new FieldSelectorDialog(
                        JOptionPane.getFrameForComponent(ElasticExporterConfigDialog.this),
                        "Elastic Exporter", elasticExporter.getFields());
                fieldSelectorDialog.setVisible(true);
                if(fieldSelectorDialog.getSelectedFields() != null){
                    elasticExporter.setFields(fieldSelectorDialog.getSelectedFields());
                }
            }
        });

        this.add(PanelBuilder.build(new JComponent[][]{
                new JComponent[]{new JLabel("Address: "), addressField},
                new JComponent[]{new JLabel("Port: "), elasticPortSpinner},
                new JComponent[]{new JLabel("Protocol: "), protocolSelector},
//                new JComponent[]{new JLabel("Cluster Name: "), clusterNameField},
                new JComponent[]{new JLabel("Index: "), indexNameField},
                new JComponent[]{new JLabel("Upload Delay (Seconds): "), elasticDelaySpinner},
                new JComponent[]{new JLabel("Exported Fields: "), configureFieldsButton},
        }, new int[][]{
                new int[]{0, 1},
                new int[]{0, 1},
                new int[]{0, 1},
                new int[]{0, 1},
                new int[]{0, 1},
                new int[]{0, 1},
        }, Alignment.CENTER, 1.0, 1.0), BorderLayout.CENTER);

        this.pack();
        this.setResizable(true);
        this.setDefaultCloseOperation(DISPOSE_ON_CLOSE);
    }
}
