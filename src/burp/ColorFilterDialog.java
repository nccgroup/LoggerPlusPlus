package burp;

import burp.filter.ColorFilter;
import burp.filter.FilterListener;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumn;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by corey on 19/07/17.
 */
public class ColorFilterDialog extends JFrame {
    private ArrayList<ColorFilter> filters;
    private ArrayList<FilterListener> filterListeners;


    public ColorFilterDialog(ArrayList<ColorFilter> filters, ArrayList<FilterListener> listeners){
        this.filters = filters;
        this.filterListeners = listeners;
        buildDialog();
        pack();
    }

    private void buildDialog(){
        this.setLayout(new BorderLayout());
        this.setTitle("Color Filters");
        JPanel content = new JPanel(new GridBagLayout());
        this.add(content, BorderLayout.CENTER);

        final ColorFilterTable filterTable = new ColorFilterTable(filters, filterListeners);
        final JScrollPane filterListWrapper = new JScrollPane(filterTable);
        GridBagConstraints gbcFilterWrapper = new GridBagConstraints();
        gbcFilterWrapper.gridx = 0;
        gbcFilterWrapper.gridy = 0;
        gbcFilterWrapper.weighty = 999;
        gbcFilterWrapper.weightx = 1;
        gbcFilterWrapper.fill = GridBagConstraints.BOTH;
        this.setMinimumSize(filterTable.getMinimumSize());
        content.add(filterListWrapper, gbcFilterWrapper);

        GridBagConstraints gbcFooter = new GridBagConstraints();
        gbcFooter.gridx = 0;
        gbcFooter.gridy = 1;
        gbcFooter.fill = GridBagConstraints.BOTH;
        gbcFooter.weighty = gbcFooter.weightx = 1;
        JPanel buttonPanel = new JPanel(new BorderLayout());
        JButton btnDeleteAll = new JButton("Delete All");
        btnDeleteAll.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                ((ColorFilterTableModel) filterTable.getModel()).removeAll();
            }
        });
        JPanel rightPanel = new JPanel();
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
        rightPanel.add(btnAddFilter);
        rightPanel.add(btnClose);
        buttonPanel.add(btnDeleteAll, BorderLayout.WEST);
        buttonPanel.add(rightPanel, BorderLayout.EAST);
        content.add(buttonPanel, gbcFooter);

    }
}
