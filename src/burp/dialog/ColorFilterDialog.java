package burp.dialog;

import burp.BurpExtender;
import burp.filter.ColorFilter;
import burp.filter.Filter;
import burp.filter.FilterListener;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * Created by corey on 19/07/17.
 */
public class ColorFilterDialog extends JFrame implements WindowListener {
    private static ColorFilterDialog instance;
    private Map<UUID, ColorFilter> filters;
    private ArrayList<FilterListener> filterListeners;
    private Map<UUID, ColorFilter> originalFilters;
    private final ColorFilterTable filterTable;

    public ColorFilterDialog(ArrayList<FilterListener> listeners){
        if(instance != null) instance.dispose();
        instance = this;
        this.filters = BurpExtender.getInstance().getLoggerPreferences().getColorFilters();
        this.originalFilters = new HashMap<UUID, ColorFilter>(filters);
        this.filterListeners = listeners;
        this.filterTable = new ColorFilterTable(filters, filterListeners);
        this.addWindowListener(this);
        buildDialog();
        pack();
    }

    private void buildDialog(){
        this.setLayout(new BorderLayout());
        this.setTitle("Color Filters");
        JPanel content = new JPanel(new GridBagLayout());
        this.add(content, BorderLayout.CENTER);
        final JScrollPane filterListWrapper = new JScrollPane(filterTable);
        GridBagConstraints gbcFilterWrapper = new GridBagConstraints();
        gbcFilterWrapper.gridx = 0;
        gbcFilterWrapper.gridy = 0;
        gbcFilterWrapper.weighty = 999;
        gbcFilterWrapper.weightx = 999;
        gbcFilterWrapper.fill = GridBagConstraints.BOTH;
        this.setMinimumSize(filterTable.getMinimumSize());
        content.add(filterListWrapper, gbcFilterWrapper);

        gbcFilterWrapper.gridx = 1;
        gbcFilterWrapper.weightx = 1;
        gbcFilterWrapper.fill = GridBagConstraints.HORIZONTAL;
        final JPanel priorityControls = new JPanel(new GridLayout(0,1));
        priorityControls.add(new JButton(new AbstractAction("▲") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                filterTable.moveSelectedUp();
            }
        }));
        priorityControls.add(new JButton(new AbstractAction("▼") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                filterTable.moveSelectedDown();
            }
        }));
        content.add(priorityControls, gbcFilterWrapper);

        GridBagConstraints gbcFooter = new GridBagConstraints();
        gbcFooter.gridx = 0;
        gbcFooter.gridy = 1;
        gbcFooter.fill = GridBagConstraints.BOTH;
        gbcFooter.weighty = gbcFooter.weightx = 1;
        gbcFooter.gridwidth = 2;
        JPanel buttonPanel = new JPanel(new BorderLayout());
        JButton btnDeleteAll = new JButton("Delete All");
        btnDeleteAll.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                ((ColorFilterTableModel) filterTable.getModel()).removeAll();
            }
        });
        JPanel rightPanel = new JPanel(new BorderLayout());
        JButton btnAddFilter = new JButton("Add Filter");
        btnAddFilter.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                ((ColorFilterTableModel) filterTable.getModel()).addFilter(new ColorFilter());
            }
        });
        JButton btnClose = new JButton("Close");
        final JFrame _this = this;
        btnClose.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                _this.setVisible(false);
            }
        });
        rightPanel.add(btnAddFilter, BorderLayout.WEST);
        rightPanel.add(btnClose, BorderLayout.EAST);
        buttonPanel.add(btnDeleteAll, BorderLayout.WEST);
        buttonPanel.add(rightPanel, BorderLayout.EAST);
        content.add(buttonPanel, gbcFooter);

    }



    public ColorFilterTable getFilterTable() {
        return filterTable;
    }

    @Override
    public void windowOpened(WindowEvent windowEvent) {}
    @Override
    public void windowClosing(WindowEvent windowEvent) {
        ArrayList<UUID> newFilters = new ArrayList<UUID>(filters.keySet());
        newFilters.removeAll(originalFilters.keySet());

        ArrayList<UUID> modifiedFilters = new ArrayList<UUID>(filters.keySet());
        modifiedFilters.removeAll(newFilters);

        ArrayList<UUID> removedFilters = new ArrayList<UUID>(originalFilters.keySet());
        removedFilters.removeAll(filters.keySet());

        ArrayList<UUID> tempFilters = new ArrayList<>(modifiedFilters);
        for (int i=0; i<tempFilters.size(); i++) {
            UUID uid = tempFilters.get(i);
            if (!filters.get(uid).isModified()) {
                modifiedFilters.remove(uid);
            } else {
                filters.get(uid).setModified(false);
            }
        }
        for (FilterListener listener : filterListeners) {
            for (UUID uid : newFilters) {
                listener.onFilterAdd(filters.get(uid));
            }
            for (UUID uid : modifiedFilters) {
                listener.onFilterChange(filters.get(uid));
            }
            for (UUID uid : removedFilters){
                listener.onFilterRemove(originalFilters.get(uid));
            }
        }
        BurpExtender.getInstance().getLoggerPreferences().setColorFilters(filters);
    }
    @Override
    public void windowClosed(WindowEvent windowEvent) {}
    @Override
    public void windowIconified(WindowEvent windowEvent) {}
    @Override
    public void windowDeiconified(WindowEvent windowEvent) {}
    @Override
    public void windowActivated(WindowEvent windowEvent) {}
    @Override
    public void windowDeactivated(WindowEvent windowEvent) {}

    public void addColorFilter(String title, String filterString) throws Filter.FilterException {
        ((ColorFilterTableModel) filterTable.getModel()).addFilter(new ColorFilter(title, filterString));
    }
}
