package loggerplusplus.userinterface;


import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.Iterator;

public class UniqueValueTable extends JTable {
    ArrayList<UniqueValueCount> uniqueValues;

    UniqueValueTable(){
        super();
        this.setModel(new UniqueValueTableModel());
        this.setAutoCreateRowSorter(true);
        this.setColumnSelectionAllowed(true);
        uniqueValues = new ArrayList<>();
    }

    public void reset(){
        synchronized (this.uniqueValues) {
            this.uniqueValues.clear();
        }
        ((UniqueValueTableModel) this.getModel()).fireTableStructureChanged();
    }

    public void addMatches(ArrayList<GrepPanel.LogEntryMatches.Match> results) {
        Iterator i = results.iterator();
        while(i.hasNext() && !Thread.currentThread().isInterrupted()){
            GrepPanel.LogEntryMatches.Match match = (GrepPanel.LogEntryMatches.Match) i.next();

            UniqueValueCount uniqueItem = new UniqueValueCount(match.groups, 1);
            int loc;
            synchronized (uniqueValues) {
                if ((loc = uniqueValues.indexOf(uniqueItem)) != -1) {
                    uniqueItem = uniqueValues.get(loc);
                    uniqueItem.count++;
                    uniqueValues.set(loc, uniqueItem);
                } else {
                    uniqueValues.add(uniqueItem);
                }
            }
        }
    }

    class UniqueValueTableModel extends AbstractTableModel {
        String[] columns = {"Value", "Count"};

        public void setColumns(String[] columns) {
            this.columns = columns;
        }

        @Override
        public String getColumnName(int column) {
            if(column >= columns.length) return "";
            return columns[column];
        }

        @Override
        public int getRowCount() {
            if(uniqueValues == null) return 0;
            else return uniqueValues.size();
        }

        @Override
        public int getColumnCount() {
            return columns.length;
        }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            if(columnIndex == columns.length-1) return Integer.class;
            return String.class;
        }

        @Override
        public Object getValueAt(int row, int col) {
            if(row >= uniqueValues.size()) return "ERROR";
            if(col == 0) return uniqueValues.get(row).groups[0];
            if(col == columns.length-1) return uniqueValues.get(row).count;
            return uniqueValues.get(row).groups[col];
        }
    }

    class UniqueValueCount implements Comparable{
        String groups[];
        int count;

        UniqueValueCount(String groups[], int count){
            this.groups = groups;
            this.count = count;
        }

        @Override
        public int compareTo(Object o) {
            if(o instanceof UniqueValueCount) {

                return groups[0].compareTo(((UniqueValueCount) o).groups[0]);
            }
            else return 0;
        }

        @Override
        public boolean equals(Object obj) {
            if(obj instanceof UniqueValueCount) {
                return groups[0].equals(((UniqueValueCount) obj).groups[0]);
            }else{
                return this.equals(obj);
            }
        }
    }
}
