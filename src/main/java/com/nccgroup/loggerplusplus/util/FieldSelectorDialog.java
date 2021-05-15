package com.nccgroup.loggerplusplus.util;

import com.coreyd97.BurpExtenderUtilities.Alignment;
import com.coreyd97.BurpExtenderUtilities.PanelBuilder;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.google.gson.internal.LinkedTreeMap;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.logentry.LogEntryField;
import com.nccgroup.loggerplusplus.util.userinterface.renderer.BooleanRenderer;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.awt.event.*;
import java.util.List;
import java.util.*;

public class FieldSelectorDialog extends JDialog {

    private List<LogEntryField> fieldList;
    private LinkedTreeMap<LogEntryField, Boolean> selectedFields;
    private final Preferences preferences;
    private final LinkedHashMap<String, Map<LogEntryField, Boolean>> savedPresets;
    private JComboBox savedSelectionSelector;
    private JButton saveSelectionButton;
    private JButton deleteSelectionButton;
    private JButton okButton;

    public FieldSelectorDialog(Frame owner, Preferences preferences, String title, List<LogEntryField> defaults){
        super(owner, title, true);
        this.preferences = preferences;
        this.setLayout(new BorderLayout());
        fieldList = new ArrayList<>();
        selectedFields = new LinkedTreeMap<>();
        if (defaults == null) defaults = Collections.emptyList();
        for (LogEntryField field : LogEntryField.values()) {
            if(field == LogEntryField.NUMBER) continue;
            fieldList.add(field);
            selectedFields.put(field, defaults.contains(field));
        }

        savedPresets = preferences.getSetting(Globals.PREF_SAVED_FIELD_SELECTIONS);

        buildDialog();
    }

    private void buildDialog() {

        JLabel message = new JLabel("Select fields to be exported:");
        JTable fieldTable = new JTable(new FieldSelectorTableModel());
        fieldTable.setDefaultRenderer(Boolean.class, new BooleanRenderer());
        fieldTable.addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if (e.getKeyCode() == KeyEvent.VK_SPACE) {
                    Boolean initial = null;
                    for (int selectedRow : fieldTable.getSelectedRows()) {
                        if (initial == null) initial = !(Boolean) fieldTable.getValueAt(selectedRow, 1);
                        fieldTable.setValueAt(initial, selectedRow, 0);
                    }
                }
            }
        });
        fieldTable.addMouseListener(new MouseAdapter() {
            public void mousePressed(MouseEvent e) {
                showContextMenu(e);
            }

            public void mouseReleased(MouseEvent e) {
                showContextMenu(e);
            }

            private void showContextMenu(MouseEvent e) {
                if (e.isPopupTrigger()) {
                    JTable source = (JTable) e.getSource();
                    JPopupMenu popupMenu = new JPopupMenu("Field Selection");

                    if (source.getSelectedRowCount() > 1) {
                        popupMenu.add(new JMenuItem(new AbstractAction("Enable Selected") {
                            @Override
                            public void actionPerformed(ActionEvent e) {
                                for (int selectedRow : source.getSelectedRows()) {
                                    source.setValueAt(true, selectedRow, 0);
                                }
                            }
                        }));
                        popupMenu.add(new JMenuItem(new AbstractAction("Disable Selected") {
                            @Override
                            public void actionPerformed(ActionEvent e) {
                                for (int selectedRow : source.getSelectedRows()) {
                                    source.setValueAt(false, selectedRow, 0);
                                }
                            }
                        }));
                        popupMenu.add(new JSeparator());
                    }
                    popupMenu.add(new JMenuItem(new AbstractAction("Enable All") {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            for (int i = 0; i < source.getRowCount(); i++) {
                                source.setValueAt(true, i, 0);
                            }
                        }
                    }));
                    popupMenu.add(new JMenuItem(new AbstractAction("Disable All") {
                        @Override
                        public void actionPerformed(ActionEvent e) {
                            for (int i = 0; i < source.getRowCount(); i++) {
                                source.setValueAt(false, i, 0);
                            }
                        }
                    }));


                    popupMenu.show(e.getComponent(), e.getX(), e.getY());
                }
            }
        });
        JScrollPane fieldScrollPane = new JScrollPane(fieldTable);
        okButton = new JButton("OK");
        okButton.addActionListener(actionEvent -> this.dispose());

        JButton cancelButton = new JButton("Cancel");
        cancelButton.addActionListener(actionEvent -> {
            selectedFields = null;
            this.dispose();
        });

        JButton selectAllButton = new JButton("Select All");
        selectAllButton.addActionListener(e -> {
            selectedFields.replaceAll((f, v) -> true);
            ((FieldSelectorTableModel) fieldTable.getModel()).fireTableDataChanged();
            setPresetState();
        });
        JButton selectNoneButton = new JButton("Select None");
        selectNoneButton.addActionListener(e -> {
            selectedFields.replaceAll((f, v) -> false);
            ((FieldSelectorTableModel) fieldTable.getModel()).fireTableDataChanged();
            setPresetState();
        });


        List<String> savedKeys = new ArrayList<>();
        savedKeys.add("Unsaved");
        savedKeys.addAll(savedPresets.keySet());
        savedSelectionSelector = new JComboBox(savedKeys.toArray());

        savedSelectionSelector.addItemListener(e -> {
            if(e.getStateChange() == ItemEvent.SELECTED) {
                String key = (String) e.getItem();
                if (key.equals("Unsaved")){
                    String preset = getMatchedPreset();
                    if(preset != null) {
                        savedSelectionSelector.setSelectedItem(preset);
                    }
                }else {
                    Map<LogEntryField, Boolean> selection = savedPresets.get(key);
                    selectedFields.forEach((field, value) -> {
                        //Should new fields be added after a user has saved a selection,
                        //We must do this in a way that will preserve the new fields so cannot simply
                        //Clear selectedFields and add all from saved selection. Instead default not found keys to false.
                        selectedFields.put(field, selection.getOrDefault(field, false));
                    });

                }
                setPresetState();
                okButton.setEnabled(selectedFields.containsValue(true));
                ((FieldSelectorTableModel) fieldTable.getModel()).fireTableDataChanged();
            }
        });

        saveSelectionButton = new JButton(new AbstractAction("Save") {
            @Override
            public void actionPerformed(ActionEvent e) {
                String key = JOptionPane.showInputDialog(JOptionPane.getFrameForComponent(LoggerPlusPlus.instance.getLoggerMenu()),
                        "Enter name for saved selection preset:", "Saving Selection Preset", JOptionPane.PLAIN_MESSAGE);

                if(key == null || key.isEmpty()){
                    JOptionPane.showMessageDialog(JOptionPane.getFrameForComponent(LoggerPlusPlus.instance.getLoggerMenu()),
                            "Saving cancelled.", "Selection Preset", JOptionPane.INFORMATION_MESSAGE);
                }else{
                    if(savedPresets.containsKey(key.toLowerCase())){
                        JOptionPane.showMessageDialog(JOptionPane.getFrameForComponent(LoggerPlusPlus.instance.getLoggerMenu()),
                                "Cannot save selection as " + key + ". A preset with that name already exists.",
                                "Selection Preset", JOptionPane.ERROR_MESSAGE);
                    }else{
                        savedPresets.put(key.toLowerCase(), new LinkedHashMap<>(selectedFields));
                        preferences.setSetting(Globals.PREF_SAVED_FIELD_SELECTIONS, savedPresets);
                        savedSelectionSelector.addItem(key.toLowerCase());
                        savedSelectionSelector.setSelectedItem(key.toLowerCase());
                        setPresetState();
                    }
                }
            }
        });

        deleteSelectionButton = new JButton(new AbstractAction("Delete") {
            @Override
            public void actionPerformed(ActionEvent e) {
                String selectedKey = (String) savedSelectionSelector.getSelectedItem();
                if (selectedKey == null) return;
                int outcome = JOptionPane.showConfirmDialog(JOptionPane.getFrameForComponent(LoggerPlusPlus.instance.getLoggerMenu()),
                        "Are you sure you wish to delete the preset \"" + selectedKey + "\"?", "Delete Selection Preset?", JOptionPane.YES_NO_OPTION);
                if(outcome == JOptionPane.OK_OPTION){
                    savedPresets.remove(selectedKey.toLowerCase());
                    savedSelectionSelector.setSelectedItem("Unsaved");
                    savedSelectionSelector.removeItem(selectedKey.toLowerCase());
                    preferences.setSetting(Globals.PREF_SAVED_FIELD_SELECTIONS, savedPresets);
                    setPresetState();
                }
            }
        });

        okButton.setEnabled(selectedFields.containsValue(true));
        setPresetState();


        JPanel panel = PanelBuilder.build(
                new JComponent[][]{
                        new JComponent[]{message, message, message, message, message},
                        new JComponent[]{savedSelectionSelector, savedSelectionSelector, null, saveSelectionButton, deleteSelectionButton},
                        new JComponent[]{fieldScrollPane, fieldScrollPane, fieldScrollPane, fieldScrollPane, fieldScrollPane},
                        new JComponent[]{selectAllButton, selectNoneButton, null, okButton, cancelButton}
                }, new int[][]{
                        new int[]{0, 0, 0, 0, 0},
                        new int[]{0, 0, 0, 0, 0},
                        new int[]{1, 1, 10, 1, 1},
                        new int[]{0, 0, 1, 0, 0},
                }, Alignment.FILL, 1.0, 1.0);
        panel.setBorder(BorderFactory.createEmptyBorder(10,10,10,10));
        this.add(panel, BorderLayout.CENTER);
        this.pack();
    }

    private class FieldSelectorTableModel extends AbstractTableModel {

        @Override
        public int getRowCount() {
            return selectedFields.size();
        }

        @Override
        public int getColumnCount() {
            return 2;
        }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            return columnIndex == 0 ? String.class : Boolean.class;
        }

        @Override
        public String getColumnName(int column) {
            return column == 0 ? "Field" : "Enabled";
        }

        @Override
        public boolean isCellEditable(int rowIndex, int columnIndex) {
            return columnIndex == 1;
        }

        @Override
        public void setValueAt(Object value, int rowIndex, int columnIndex) {
            LogEntryField field = fieldList.get(rowIndex);
            selectedFields.put(field, (Boolean) value);

            //Check presets to see if our current selection matches a preset
            setPresetState();

            okButton.setEnabled(selectedFields.containsValue(true));
            this.fireTableRowsUpdated(rowIndex, rowIndex);
        }

        @Override
        public Object getValueAt(int row, int col) {
            if(col == 0){
                return fieldList.get(row);
            }else{
                return selectedFields.get(fieldList.get(row));
            }
        }
    }

    public List<LogEntryField> getSelectedFields() {
        List<LogEntryField> selectedList = new ArrayList<>();
        if (selectedFields != null) {
            selectedFields.forEach((field, selected) -> {
                if (selected) selectedList.add(field);
            });
        }

        return selectedList;
    }

    private String getMatchedPreset(){
        for (Map.Entry<String, Map<LogEntryField, Boolean>> e : savedPresets.entrySet()) {
            String presetKey = e.getKey();
            Map<LogEntryField, Boolean> presetSelection = e.getValue();

            presetLoop:
            {
                for (Map.Entry<LogEntryField, Boolean> entry : selectedFields.entrySet()) {
                    LogEntryField field = entry.getKey();
                    Boolean currentValue = entry.getValue();
                    Boolean presetValue = presetSelection.get(field);
                    if (presetSelection.containsKey(field) && presetValue != currentValue) {
                        break presetLoop;
                    }
                }
                return presetKey;
            }
        }
        return null;
    }

    private void setPresetState(){
        String matchedPreset = getMatchedPreset();
        if(matchedPreset == null){
            savedSelectionSelector.setSelectedItem("Unsaved");
            saveSelectionButton.setEnabled(true);
            deleteSelectionButton.setEnabled(false);
        }else{
            savedSelectionSelector.setSelectedItem(matchedPreset);
            saveSelectionButton.setEnabled(false);
            deleteSelectionButton.setEnabled(true);
        }
    }
}
