package com.nccgroup.loggerplusplus.grepper;


import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.regex.Pattern;

public class UniquePatternMatchTable extends JTable implements GrepperListener {
    private final GrepperController controller;
    private final ArrayList<String> entryKeys;
    private final HashMap<String, UniqueMatch> valueCountMap;

    public UniquePatternMatchTable(GrepperController controller){
        super();
        this.controller = controller;
        this.setModel(new UniqueValueTableModel());
        this.setAutoCreateRowSorter(true);
        this.setColumnSelectionAllowed(true);
        this.entryKeys = new ArrayList<>();
        this.valueCountMap = new LinkedHashMap<>();

        this.controller.addListener(this);
    }

    public void reset(){
        synchronized (this.valueCountMap) {
            this.valueCountMap.clear();
        }
        synchronized (this.entryKeys){
            this.entryKeys.clear();
        }
        SwingUtilities.invokeLater(() -> ((UniqueValueTableModel) this.getModel()).fireTableDataChanged());
    }

    public void addEntry(GrepResults entry) {
        synchronized (valueCountMap) {
            synchronized (entryKeys) {
                for (GrepResults.Match result : entry.getMatches()) {
                    String key = result.groups[0];
                    int index = entryKeys.indexOf(key);
                    if (index == -1) {
                        entryKeys.add(key);
                        valueCountMap.put(key, new UniqueMatch(result.groups));
                    } else {
                        valueCountMap.get(key).increment();
                    }
                }
            }
        }
    }

    @Override
    public void onSearchStarted(Pattern pattern, int searchEntries) {
        reset();
        ((UniqueValueTableModel) getModel()).groups = pattern.matcher("").groupCount();
        ((AbstractTableModel) this.getModel()).fireTableStructureChanged();
    }

    @Override
    public void onEntryProcessed(GrepResults entryResults) {
        if(entryResults != null) addEntry(entryResults);
    }

    @Override
    public void onSearchComplete() {
        ((AbstractTableModel) this.getModel()).fireTableDataChanged();
    }

    @Override
    public void onResetRequested() {
        reset();
    }

    @Override
    public void onShutdownInitiated() {

    }

    @Override
    public void onShutdownComplete() {
        ((AbstractTableModel) this.getModel()).fireTableDataChanged();
    }


    public class UniqueValueTableModel extends AbstractTableModel {

        int groups = 0;

        @Override
        public String getColumnName(int column) {
            if(column == 0) return "Value";
            if(column == groups+1) return "Count";
            return "Group " + column;
        }

        @Override
        public int getRowCount() {
            if(valueCountMap == null) return 0;
            else return valueCountMap.size();
        }

        @Override
        public int getColumnCount() {
            return groups+2;
        }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            if(columnIndex == groups+1) return Integer.class;
            return String.class;
        }

        @Override
        public Object getValueAt(int row, int col) {
            String key = entryKeys.get(row);
            if(col == 0) return key;
            UniqueMatch match = valueCountMap.get(key);
            if(col == groups+1) return match.count;
            return match.groups[col];
        }
    }

    static class UniqueMatch {
        String key;
        String[] groups;
        int count;

        UniqueMatch(String[] match){
            this.key = match[0];
            this.groups = match;
            this.count = 1;
        }

        private void increment(){
            this.count++;
        }
    }
}
