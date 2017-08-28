package burp;

import burp.dialog.ButtonRenderer;
import burp.dialog.ColorFilterDialog;
import burp.filter.Filter;
import burp.filter.FilterCompiler;
import com.google.gson.*;
import com.google.gson.reflect.TypeToken;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Type;
import java.net.URL;
import java.nio.charset.Charset;
import java.util.ArrayList;

/**
 * Created by corey on 27/08/17.
 */
public class FilterLibrary extends JPanel {
    ArrayList<SharedFilter> library;
    String[] columnNames = {"Title", "Filter", "Submitted By", "", ""};
    JButton btnFilter;
    JButton btnColorFilter;
    private final String filterURL = "https://raw.githubusercontent.com/nccgroup/BurpSuiteLoggerPlusPlus/master/FILTERS";

    FilterLibrary(){
        this.setLayout(new BorderLayout());
        library = new ArrayList<>();
        SharedFilter test = new SharedFilter();
        try {
            test.title = "Test Title";
            test.creator = "CoreyD97";
            test.description = "Some description";
            test.filter = FilterCompiler.parseString("response == /.*ng-bind-html.*/").toString();
            library.add(test);
        } catch (Filter.FilterException e) {
            e.printStackTrace();
        }
        btnFilter = new JButton("Set as Filter");
        btnColorFilter = new JButton("Use as Color Filter");
        final JTable libraryTable = new JTable(new LibraryTableModel());
        libraryTable.setRowHeight(25);
        libraryTable.setFillsViewportHeight(true);
        libraryTable.setAutoResizeMode(JTable.AUTO_RESIZE_SUBSEQUENT_COLUMNS);
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

        this.add(new JScrollPane(libraryTable), BorderLayout.CENTER);
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
                    Gson filtersGson = new GsonBuilder().registerTypeAdapter(SharedFilter.class, new SharedFilterDeserializer()).create();
                    library = filtersGson.fromJson(rd, new TypeToken<ArrayList<SharedFilter>>(){}.getType());
                }catch (IOException exception){}
                finally {
                    try {
                        is.close();
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
                BurpExtender.getInstance().setFilter(library.get(row).filter);
                BurpExtender.getInstance().getTabbedPane().setSelectedIndex(0);
                return;
            }
            if(col == 4){
                ColorFilterDialog dialog =new ColorFilterDialog(BurpExtender.getInstance().getFilterListeners());
                SharedFilter sharedFilter = library.get(row);
                try {
                    dialog.addColorFilter(sharedFilter.title, sharedFilter.filter);
                    dialog.setVisible(true);
                } catch (Filter.FilterException e) {
                    MoreHelp.showMessage("Could not apply Color Filter.");
                }
            }
        }
    }

    class SharedFilter {
        String title;
        String filter;
        String description;
        String creator;
    }

    private class SharedFilterDeserializer implements JsonDeserializer<SharedFilter>{
        @Override
        public SharedFilter deserialize(JsonElement jsonElement, Type type, JsonDeserializationContext jsonDeserializationContext) throws JsonParseException {
            SharedFilter filter = new SharedFilter();
            filter.title = jsonElement.getAsJsonObject().get("title").getAsString();
            filter.filter = jsonElement.getAsJsonObject().get("filter").getAsString();
            filter.description = jsonElement.getAsJsonObject().get("description").getAsString();
            filter.creator = jsonElement.getAsJsonObject().get("creator").getAsString();
            return filter;
        }
    }
}
