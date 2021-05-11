package com.nccgroup.loggerplusplus.exports;

import static com.nccgroup.loggerplusplus.util.Globals.PREF_COBALT_ADDRESS;
import static com.nccgroup.loggerplusplus.util.Globals.PREF_COBALT_AUTOSTART_GLOBAL;
import static com.nccgroup.loggerplusplus.util.Globals.PREF_COBALT_AUTOSTART_PROJECT;
import static com.nccgroup.loggerplusplus.util.Globals.PREF_COBALT_DELAY;

import java.awt.BorderLayout;
import java.awt.Frame;
import java.awt.event.ActionEvent;
import java.util.List;
import java.util.Objects;

import javax.swing.AbstractAction;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComponent;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JSpinner;
import javax.swing.JTextField;
import javax.swing.SpinnerNumberModel;

import com.coreyd97.BurpExtenderUtilities.Alignment;
import com.coreyd97.BurpExtenderUtilities.PanelBuilder;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.loggerplusplus.logentry.LogEntryField;
import com.nccgroup.loggerplusplus.util.MoreHelp;

public class CobaltExporterConfigDialog extends JDialog {

    CobaltExporterConfigDialog(Frame owner, CobaltExporter cobaltExporter){
        super(owner, "Cobalt Exporter Configuration", true);

        this.setLayout(new BorderLayout());
        Preferences preferences = cobaltExporter.getPreferences();

        JTextField addressField = PanelBuilder.createPreferenceTextField(preferences, PREF_COBALT_ADDRESS);

        //TODO Update PanelBuilder to allow labels with custom components

        JSpinner cobaltDelaySpinner = PanelBuilder.createPreferenceSpinner(preferences, PREF_COBALT_DELAY);
        ((SpinnerNumberModel) cobaltDelaySpinner.getModel()).setMaximum(99999);
        ((SpinnerNumberModel) cobaltDelaySpinner.getModel()).setMinimum(10);
        ((SpinnerNumberModel) cobaltDelaySpinner.getModel()).setStepSize(10);

        JButton configureFieldsButton = new JButton(new AbstractAction("Configure") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                List<LogEntryField> selectedFields = MoreHelp.showFieldChooserDialog(addressField,
                        preferences, "Cobalt Exporter", cobaltExporter.getFields());

                if(selectedFields == null){
                    //Cancelled.
                } else if (!selectedFields.isEmpty()) {
                    cobaltExporter.setFields(selectedFields);
                } else {
                    JOptionPane.showMessageDialog(addressField,
                            "No fields were selected. No changes have been made.",
                            "Cobalt Exporter", JOptionPane.INFORMATION_MESSAGE);
                }
            }
        });

        JCheckBox autostartGlobal = PanelBuilder.createPreferenceCheckBox(preferences, PREF_COBALT_AUTOSTART_GLOBAL);
        JCheckBox autostartProject = PanelBuilder.createPreferenceCheckBox(preferences, PREF_COBALT_AUTOSTART_PROJECT);

        //If global autostart is on, it overrides the per-project setting.
        autostartProject.setEnabled(!(boolean) preferences.getSetting(PREF_COBALT_AUTOSTART_GLOBAL));
        preferences.addSettingListener((source, settingName, newValue) -> {
            if (Objects.equals(settingName, PREF_COBALT_AUTOSTART_GLOBAL)) {
                autostartProject.setEnabled(!(boolean) newValue);
                if ((boolean) newValue) {
                    preferences.setSetting(PREF_COBALT_AUTOSTART_PROJECT, true);
                }
            }
        });


        this.add(PanelBuilder.build(new JComponent[][]{
                new JComponent[]{new JLabel("Address: "), addressField},
                new JComponent[]{new JLabel("Upload Frequency (Seconds): "), cobaltDelaySpinner},
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

        this.pack();
        this.setResizable(true);
        this.setDefaultCloseOperation(DISPOSE_ON_CLOSE);
    }
}
