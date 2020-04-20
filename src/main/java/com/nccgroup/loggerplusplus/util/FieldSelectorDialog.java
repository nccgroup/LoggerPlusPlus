package com.nccgroup.loggerplusplus.util;

import com.coreyd97.BurpExtenderUtilities.Alignment;
import com.coreyd97.BurpExtenderUtilities.PanelBuilder;
import com.google.gson.internal.LinkedTreeMap;
import com.nccgroup.loggerplusplus.logentry.LogEntryField;
import com.nccgroup.loggerplusplus.util.userinterface.renderer.BooleanRenderer;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.util.*;
import java.util.List;

public class FieldSelectorDialog extends JDialog {

    private List<LogEntryField> fieldList;
    private LinkedTreeMap<LogEntryField, Boolean> selectedFields;

    public FieldSelectorDialog(Frame owner, String title, List<LogEntryField> defaults){
        super(owner, title, true);
        this.setLayout(new BorderLayout());
        fieldList = new ArrayList<>();
        selectedFields = new LinkedTreeMap<>();
        if(defaults == null) defaults = Collections.EMPTY_LIST;
        for (LogEntryField field : LogEntryField.values()) {
            if(field == LogEntryField.NUMBER) continue;
            fieldList.add(field);
            selectedFields.put(field, defaults.contains(field));
        }

        buildDialog();
    }

    private void buildDialog(){

        JLabel message = new JLabel("Select fields to be exported:");
        JTable fieldTable = new JTable(new TableModel());
        fieldTable.setDefaultRenderer(Boolean.class, new BooleanRenderer());
        JScrollPane fieldScrollPane = new JScrollPane(fieldTable);
        JButton okButton = new JButton("OK");
        okButton.addActionListener(actionEvent -> {
            this.dispose();
        });
        JButton cancelButton = new JButton("Cancel");
        cancelButton.addActionListener(actionEvent -> {
            selectedFields.clear();
            this.dispose();
        });

        JPanel panel = PanelBuilder.build(
                new JComponent[][]{
                        new JComponent[]{message, message, message},
                        new JComponent[]{fieldScrollPane, fieldScrollPane, fieldScrollPane},
                        new JComponent[]{null, okButton, cancelButton}
                }, new int[][]{
                        new int[]{1, 1, 1},
                        new int[]{0, 0, 0},
                        new int[]{0, 0, 0},
                }, Alignment.FILL, 1.0, 1.0);
        this.add(panel, BorderLayout.CENTER);
        this.pack();
    }

    private class TableModel extends AbstractTableModel {

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
        selectedFields.forEach((field, selected) -> {
            if(selected) selectedList.add(field);
        });

        return selectedList;
    }
}
