package loggerplusplus.userinterface.dialog;

import loggerplusplus.filter.SavedFilter;
import loggerplusplus.userinterface.renderer.ButtonRenderer;
import loggerplusplus.userinterface.renderer.FilterRenderer;

import javax.swing.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;

/**
 * Created by corey on 22/08/17.
 */
public class SavedFiltersTable extends JTable {

    SavedFiltersTable(ArrayList<SavedFilter> filters){
        this.setModel(new SavedFiltersTableModel(filters));
        this.setFillsViewportHeight(true);
        this.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        this.setAutoCreateRowSorter(false);
        this.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        this.setRowHeight(25);
        ((JComponent) this.getDefaultRenderer(Boolean.class)).setOpaque(true); // to remove the white background of the checkboxes!
        ((JComponent) this.getDefaultRenderer(JButton.class)).setOpaque(true);

        this.getColumnModel().getColumn(1).setCellRenderer(new FilterRenderer());
        this.getColumnModel().getColumn(2).setCellRenderer(new ButtonRenderer());

        int[] minWidths = {100, 250, 100};
        for(int i=0; i<minWidths.length; i++) {
            this.getColumnModel().getColumn(i).setMinWidth(minWidths[i]);
        }
        int[] maxWidths = {9999, 9999, 100};
        for(int i=0; i<maxWidths.length; i++) {
            this.getColumnModel().getColumn(i).setMaxWidth(maxWidths[i]);
        }
        this.setMinimumSize(new Dimension(450, 200));

        final JTable _this = this;
        this.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseReleased(MouseEvent mouseEvent) {
                if(SwingUtilities.isLeftMouseButton(mouseEvent)) {
                    int col = _this.columnAtPoint(mouseEvent.getPoint());
                    int row = _this.rowAtPoint(mouseEvent.getPoint());
                    ((SavedFiltersTableModel) getModel()).onClick(row, col);
                }
            }
        });
    }

    public void removeSelected() {
        ((SavedFiltersTableModel) this.getModel()).removeAtIndex(this.getSelectedRow());
    }
}
