package com.nccgroup.loggerplusplus.exports;

import com.coreyd97.BurpExtenderUtilities.Alignment;
import com.coreyd97.BurpExtenderUtilities.ComponentGroup;
import com.coreyd97.BurpExtenderUtilities.PanelBuilder;
import com.coreyd97.BurpExtenderUtilities.Preferences;

import javax.swing.*;

import java.awt.*;

import static com.nccgroup.loggerplusplus.util.Globals.*;
import static com.nccgroup.loggerplusplus.util.Globals.PREF_ELASTIC_INCLUDE_REQ_RESP;

public class ElasticExporterConfigDialog extends JDialog {

    ElasticExporterConfigDialog(Frame owner, Preferences preferences){
        super(owner, "Elastic Exporter Configuration", true);

        this.setLayout(new BorderLayout());
        PanelBuilder panelBuilder = new PanelBuilder(preferences);

        JTextField addressField = panelBuilder.createPreferenceTextField(PREF_ELASTIC_ADDRESS);
        JSpinner elasticPortSpinner = panelBuilder.createPreferenceSpinner(PREF_ELASTIC_PORT);
        ((SpinnerNumberModel) elasticPortSpinner.getModel()).setMaximum(65535);
        ((SpinnerNumberModel) elasticPortSpinner.getModel()).setMinimum(0);
        elasticPortSpinner.setEditor(new JSpinner.NumberEditor(elasticPortSpinner,"#"));

        JComboBox<Protocol> protocolSelector = new JComboBox<>(Protocol.values());
        protocolSelector.addActionListener(actionEvent -> {
            preferences.setSetting(PREF_ELASTIC_PROTOCOL, protocolSelector.getSelectedItem());
        });

        //TODO Update PanelBuilder to allow labels with custom components

        JTextField clusterNameField = panelBuilder.createPreferenceTextField(PREF_ELASTIC_CLUSTER_NAME);
        JTextField indexNameField = panelBuilder.createPreferenceTextField(PREF_ELASTIC_INDEX);
        JSpinner elasticDelaySpinner = panelBuilder.createPreferenceSpinner(PREF_ELASTIC_DELAY);
        ((SpinnerNumberModel) elasticDelaySpinner.getModel()).setMaximum(99999);
        ((SpinnerNumberModel) elasticDelaySpinner.getModel()).setMinimum(10);
        ((SpinnerNumberModel) elasticDelaySpinner.getModel()).setStepSize(10);

        JToggleButton includeRequestResponse = panelBuilder.createPreferenceCheckBox(PREF_ELASTIC_INCLUDE_REQ_RESP, "Include Request and Response");

        this.add(panelBuilder.build(new JComponent[][]{
                new JComponent[]{new JLabel("Address: "), addressField},
                new JComponent[]{new JLabel("Port: "), elasticPortSpinner},
                new JComponent[]{new JLabel("Protocol: "), protocolSelector},
//                new JComponent[]{new JLabel("Cluster Name: "), clusterNameField},
                new JComponent[]{new JLabel("Index: "), indexNameField},
                new JComponent[]{new JLabel("Upload Delay (Seconds): "), elasticDelaySpinner},
                new JComponent[]{includeRequestResponse, includeRequestResponse},
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
