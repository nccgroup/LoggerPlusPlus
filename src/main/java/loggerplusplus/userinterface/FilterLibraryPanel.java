package loggerplusplus.userinterface;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import loggerplusplus.LoggerPlusPlus;
import loggerplusplus.MoreHelp;
import loggerplusplus.filter.Filter;
import loggerplusplus.userinterface.dialog.ColorFilterDialog;
import loggerplusplus.userinterface.renderer.ButtonRenderer;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.ArrayList;

/**
 * Created by corey on 27/08/17.
 */
public class FilterLibraryPanel extends JSplitPane {
    ArrayList<SharedFilter> library;
    String[] columnNames = {"Title", "Filter", "Submitted By", "", ""};
    JButton btnFilter;
    JButton btnColorFilter;
    JLabel lblSelectedTitle;
    JLabel lblSelectedFilter;
    JLabel lblSelectedDescription;
    JLabel lblSelectedCreator;
    private final String filterURL = "https://raw.githubusercontent.com/nccgroup/BurpSuiteLoggerPlusPlus/master/FILTERS";

    public FilterLibraryPanel(){
        library = new ArrayList<>();
        btnFilter = new JButton("Set as Filter");
        btnColorFilter = new JButton("Use as Color Filter");
        final JTable libraryTable = new JTable(new LibraryTableModel()){
            @Override
            public void changeSelection(int rowIndex, int columnIndex, boolean toggle, boolean extend) {
                super.changeSelection(rowIndex, columnIndex, toggle, extend);
                SharedFilter filter = ((LibraryTableModel) getModel()).getRow(rowIndex);
                if(filter != null){
                    lblSelectedTitle.setText(filter.title);
                    lblSelectedCreator.setText(filter.creator);
                    lblSelectedFilter.setText(filter.filter);
                    lblSelectedDescription.setText(filter.description);
                }
            }

            @Override
            public boolean getScrollableTracksViewportWidth() {
                return getPreferredSize().width < getParent().getWidth();
            }
        };
        libraryTable.setRowHeight(25);
        libraryTable.setFillsViewportHeight(true);
        libraryTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        libraryTable.setAutoCreateRowSorter(false);
        ((JComponent) libraryTable.getDefaultRenderer(JButton.class)).setOpaque(true);
        libraryTable.getColumnModel().getColumn(3).setCellRenderer(new ButtonRenderer());
        libraryTable.getColumnModel().getColumn(4).setCellRenderer(new ButtonRenderer());

        libraryTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseReleased(MouseEvent mouseEvent) {
                if(SwingUtilities.isLeftMouseButton(mouseEvent)) {
                    int col = libraryTable.columnAtPoint(mouseEvent.getPoint());
                    int row = libraryTable.rowAtPoint(mouseEvent.getPoint());
                    ((LibraryTableModel) libraryTable.getModel()).onClick(row, col);
                }
            }
        });

        this.setTopComponent(new JScrollPane(libraryTable));
        GridBagLayout gridBagLayout = new GridBagLayout();
        gridBagLayout.columnWidths = new int[]{0, 0, 0, 0};
        gridBagLayout.rowHeights = new int[]{0, 0, 0};
        gridBagLayout.columnWeights = new double[]{0, 1, 0, 1};
        gridBagLayout.rowWeights = new double[]{1.0, 1.5, 1.5};
        JPanel detailsPanel = new JPanel(gridBagLayout);
        detailsPanel.setLayout(gridBagLayout);
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.ipadx = gbc.ipady = 15;
        gbc.fill = GridBagConstraints.BOTH;

        gbc.gridy = 0;
        gbc.gridx = 2;
        detailsPanel.add(new JLabel("Creator:"), gbc);
        gbc.gridx++;
        lblSelectedCreator = new JLabel();
        detailsPanel.add(lblSelectedCreator, gbc);

        gbc.gridx = 0;
        gbc.gridy = 2;
        detailsPanel.add(new JLabel("Description:"), gbc);
        gbc.gridx++;
        gbc.gridwidth = 3;
        lblSelectedDescription = new JLabel();
        loggerplusplus.userinterface.ScrollablePanel descScroll = new ScrollablePanel();
        descScroll.setScrollableWidth(ScrollablePanel.ScrollableSizeHint.STRETCH);
        descScroll.setScrollableHeight(ScrollablePanel.ScrollableSizeHint.FIT);
        descScroll.setLayout(new BorderLayout());
        lblSelectedDescription.setHorizontalAlignment(SwingConstants.LEFT);
        descScroll.add(lblSelectedDescription);
        detailsPanel.add(new JScrollPane(descScroll), gbc);

        gbc.gridx = gbc.gridy = 0;
        detailsPanel.add(new JLabel("Title:"), gbc);
        gbc.gridx++;
        lblSelectedTitle = new JLabel();
        detailsPanel.add(lblSelectedTitle, gbc);

        gbc.gridx = 0;
        gbc.gridy = 1;
        detailsPanel.add(new JLabel("Filter:"), gbc);
        gbc.gridx++;
        gbc.gridwidth = 3;
        lblSelectedFilter = new JLabel();
        loggerplusplus.userinterface.ScrollablePanel filterScrollPane = new ScrollablePanel();
        filterScrollPane.setScrollableWidth(ScrollablePanel.ScrollableSizeHint.NONE);
        filterScrollPane.add(lblSelectedFilter);
        detailsPanel.add(new JScrollPane(filterScrollPane), gbc);

        this.setBottomComponent(detailsPanel);
        this.setOrientation(VERTICAL_SPLIT);
        this.setResizeWeight(0.85);

        updateFilterList();
    }

    private void updateFilterList(){
        Thread updateThread = new Thread(){
            @Override
            public void run() {
                InputStream is = null;
                try {
                    is = new URL(filterURL).openStream();
                    BufferedReader rd = new BufferedReader(new InputStreamReader(is, Charset.forName("UTF-8")));
                    library = new Gson().fromJson(rd, new TypeToken<ArrayList<SharedFilter>>(){}.getType());
                }catch (IOException exception){}
                finally {
                    try {
                        if(is != null) is.close();
                    }catch (IOException ioException){}
                }
            }
        };
        updateThread.start();
    }

    class LibraryTableModel extends AbstractTableModel {

        @Override
        public int getRowCount() {
            return library == null ? 0 : library.size();
        }

        @Override
        public int getColumnCount() {
            return columnNames.length;
        }

        @Override
        public Object getValueAt(int row, int column) {
            if(library == null || row >= library.size()) return null;
            switch (column){
                case 0: return library.get(row).title;
                case 1: return library.get(row).filter;
                case 2: return library.get(row).creator;
                case 3: return btnFilter;
                case 4: return btnColorFilter;
            }
            return null;
        }

        @Override
        public String getColumnName(int column) {
            return columnNames[column];
        }

        @Override
        public boolean isCellEditable(int rowIndex, int columnIndex) {
            return false;
        }

        public void onClick(int row, int col) {
            if(library == null || row < 0 || row >= library.size() || library.get(row) == null) return;
            if(col == 3){
                LoggerPlusPlus.getInstance().setFilter(library.get(row).filter);
                LoggerPlusPlus.getInstance().getTabbedPane().setSelectedIndex(0);
                return;
            }
            if(col == 4){
                ColorFilterDialog dialog = new ColorFilterDialog(LoggerPlusPlus.getInstance().getFilterListeners());
                SharedFilter sharedFilter = library.get(row);
                try {
                    dialog.addColorFilter(sharedFilter.title, sharedFilter.filter);
                    dialog.setVisible(true);
                } catch (Filter.FilterException e) {
                    MoreHelp.showMessage("Could not apply Color Filter.");
                }
            }
        }

        public SharedFilter getRow(int rowIndex) {
            if(library == null) return null;
            else return library.get(rowIndex);
        }
    }

    public static class SharedFilter {
        public String title;
        public String filter;
        public String description;
        public String creator;
    }
}
