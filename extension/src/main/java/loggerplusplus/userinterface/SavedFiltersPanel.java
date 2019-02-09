package loggerplusplus.userinterface;

import loggerplusplus.Globals;
import loggerplusplus.LoggerPlusPlus;
import loggerplusplus.filter.SavedFilter;
import loggerplusplus.filter.parser.ParseException;
import loggerplusplus.userinterface.renderer.ButtonRenderer;
import loggerplusplus.userinterface.renderer.FilterRenderer;

import javax.swing.*;
import javax.swing.table.JTableHeader;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;

/**
 * Created by corey on 27/08/17.
 */
public class SavedFiltersPanel extends JPanel {
    ArrayList<SavedFilter> library;

    public SavedFiltersPanel(){
        super(new BorderLayout());
        ArrayList<SavedFilter> storedSavedFilters =
                (ArrayList<SavedFilter>) LoggerPlusPlus.preferences.getSetting(Globals.PREF_SAVED_FILTERS);

        library = new ArrayList<>(storedSavedFilters);

        JTable libraryTable = new JTable(new SavedFiltersTableModel(library));
        libraryTable.setRowHeight(25);
        libraryTable.setFillsViewportHeight(true);
        libraryTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        libraryTable.setAutoCreateRowSorter(false);
        libraryTable.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        ((JComponent) libraryTable.getDefaultRenderer(JButton.class)).setOpaque(true);
        libraryTable.getColumnModel().getColumn(1).setCellRenderer(new FilterRenderer());
        libraryTable.getColumnModel().getColumn(2).setCellRenderer(new ButtonRenderer());
        libraryTable.getColumnModel().getColumn(3).setCellRenderer(new ButtonRenderer());

        libraryTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseReleased(MouseEvent mouseEvent) {
                if(SwingUtilities.isLeftMouseButton(mouseEvent)) {
                    int col = libraryTable.columnAtPoint(mouseEvent.getPoint());
                    int row = libraryTable.rowAtPoint(mouseEvent.getPoint());
                    ((SavedFiltersTableModel) libraryTable.getModel()).onClick(row, col);
                }
            }
        });

        JPanel controlPanel = new JPanel(new GridLayout(1,0));
        JButton addFilterButton = new JButton("Add Filter");
        addFilterButton.addActionListener(actionEvent -> {
            try {
                ((SavedFiltersTableModel) libraryTable.getModel()).addRow();
            } catch (ParseException e) {
                e.printStackTrace();
            }
        });
        JButton removeSelectedButton = new JButton("Remove Selected");
        removeSelectedButton.addActionListener(actionEvent -> {
            int selectedRow = libraryTable.getSelectedRow();
            if(selectedRow == -1) return;
            else ((SavedFiltersTableModel) libraryTable.getModel()).removeRowAtIndex(selectedRow);
        });
        controlPanel.add(addFilterButton);
        controlPanel.add(removeSelectedButton);

        JScrollPane tableScrollPane = new JScrollPane(libraryTable);
        this.add(tableScrollPane, BorderLayout.CENTER);
        this.add(controlPanel, BorderLayout.SOUTH);
    }
}
