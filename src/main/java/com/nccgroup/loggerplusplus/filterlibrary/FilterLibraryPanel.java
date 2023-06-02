package com.nccgroup.loggerplusplus.filterlibrary;

import com.nccgroup.loggerplusplus.filter.parser.ParseException;
import com.nccgroup.loggerplusplus.filter.savedfilter.SavedFilter;
import com.nccgroup.loggerplusplus.util.userinterface.renderer.ButtonRenderer;
import com.nccgroup.loggerplusplus.util.userinterface.renderer.FilterRenderer;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;

/**
 * Created by corey on 27/08/17.
 */
public class FilterLibraryPanel extends JPanel {

    private final FilterLibraryController libraryController;

    public FilterLibraryPanel(FilterLibraryController libraryController){
        super(new BorderLayout());

        this.libraryController = libraryController;

        JTable libraryTable = new JTable(new FilterLibraryTableModel(this.libraryController));
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
                    ((FilterLibraryTableModel) libraryTable.getModel()).onClick(row, col);
                }
            }
        });

        JPanel controlPanel = new JPanel(new GridLayout(1,0));
        JButton addFilterButton = new JButton("Add Snippet");
        addFilterButton.setPreferredSize(new Dimension(0, 75));
        addFilterButton.addActionListener(actionEvent -> {
            libraryController.addFilter(new SavedFilter("Unnamed", "Response.body CONTAINS \"Example\""));
        });
        JButton removeSelectedButton = new JButton("Remove Selected");
        removeSelectedButton.setMinimumSize(new Dimension(0, 75));
        removeSelectedButton.addActionListener(actionEvent -> {
            int selectedRow = libraryTable.getSelectedRow();
            if(selectedRow == -1) return;
            SavedFilter filter = libraryController.getFilterSnippets().get(selectedRow);
            libraryController.removeFilter(filter);
        });
        controlPanel.add(addFilterButton);
        controlPanel.add(removeSelectedButton);

        JScrollPane tableScrollPane = new JScrollPane(libraryTable);
        this.add(tableScrollPane, BorderLayout.CENTER);
        this.add(controlPanel, BorderLayout.SOUTH);
    }
}
