package loggerplusplus.userinterface;

import ca.odell.glazedlists.EventList;
import ca.odell.glazedlists.SortedList;
import ca.odell.glazedlists.gui.AdvancedTableFormat;
import ca.odell.glazedlists.swing.DefaultEventTableModel;
import ca.odell.glazedlists.swing.EventTableModel;
import ca.odell.glazedlists.swing.TableComparatorChooser;

import javax.swing.*;
import java.util.Comparator;

public class UniqueValueTable extends JTable {
    DefaultEventTableModel tableModel;
    EventList eventList;

    UniqueValueTable(EventList list, EventTableModel model){
        super(model);
        this.eventList = list;
        this.tableModel = model;
        TableComparatorChooser tableSorter = new TableComparatorChooser(this, new SortedList(list), true);
    }

    void clearList(){
        eventList.getReadWriteLock().writeLock().lock();
        try {
            eventList.clear();
        }finally {
            eventList.getReadWriteLock().writeLock().unlock();
        }
    }

    public void addItem(String group) {
        UniqueValueCount val = new UniqueValueCount(group, 1);
        eventList.getReadWriteLock().readLock().lock();
        int index;
        try {
            index = eventList.indexOf(val);
        }finally {
            eventList.getReadWriteLock().readLock().unlock();
        }

        eventList.getReadWriteLock().writeLock().lock();
        try{
            if (index == -1) {
                eventList.add(new UniqueValueCount(group, 1));
            } else {
                val = ((UniqueValueCount) eventList.get(index));
                val.count++;
                eventList.add(val);
            }
        }finally {
            eventList.getReadWriteLock().writeLock().unlock();
        }
    }


    public static class UniqueValueTableFormat implements AdvancedTableFormat {

        @Override
        public int getColumnCount() {
            return 2;
        }

        @Override
        public String getColumnName(int i) {
            if(i == 0) return "Value";
            else if(i == 1) return "Count";
            else throw new IllegalStateException();
        }

        @Override
        public Object getColumnValue(Object o, int i) {
            UniqueValueCount value = (UniqueValueCount) o;
            if(i == 0) return value.value;
            else if(i == 1) return value.count;
            else throw new IllegalStateException();
        }

        @Override
        public Class getColumnClass(int i) {
            if(i == 0) return String.class;
            if(i == 1) return Integer.class;
            throw new IllegalStateException();
        }

        @Override
        public Comparator getColumnComparator(int i) {
            if(i == 0) return new Comparator() {
                @Override
                public int compare(Object o, Object t1) {
                    return ((String) o).compareTo((String) t1);
                }
            };
            if(i == 1) return new Comparator() {
                @Override
                public int compare(Object o, Object t1) {
                    return ((Integer) o).compareTo((Integer) t1);
                }
            };
            throw new IllegalStateException();
        }
    }

    class UniqueValueCount implements Comparable{
        String value;
        int count;
        UniqueValueCount(String value, int count){
            this.value = value;
            this.count = count;
        }

        @Override
        public int compareTo(Object o) {
            if(o instanceof UniqueValueCount) {
                return value.compareTo(((UniqueValueCount) o).value);
            }
            else return 0;
        }

        @Override
        public boolean equals(Object obj) {
            if(obj instanceof UniqueValueCount) {
                return value.equals(((UniqueValueCount) obj).value);
            }else{
                return this.equals(obj);
            }
        }
    }
}
