package loggerplusplus.userinterface;

import loggerplusplus.LogManager;
import loggerplusplus.LoggerPlusPlus;
import loggerplusplus.userinterface.dialog.ColorFilterDialog;
import loggerplusplus.userinterface.dialog.SavedFiltersDialog;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;

/**
 * Created by corey on 24/08/17.
 */
public class LogViewPanel extends JPanel {
    final JScrollPane logTableScrollPane;
    final LogTable logTable;
    final FilterPanel filterPanel;


    public LogViewPanel(LogManager logManager){
        this.setLayout(new GridLayout());

        LogTableModel tableModel = new LogTableModel(logManager);
        logTable = new LogTable(tableModel);
        logTableScrollPane = new JScrollPane(logTable,ScrollPaneConstants.VERTICAL_SCROLLBAR_ALWAYS,ScrollPaneConstants.HORIZONTAL_SCROLLBAR_AS_NEEDED);//View
        logTableScrollPane.addMouseWheelListener(new MouseWheelListener() {
            @Override
            public void mouseWheelMoved(MouseWheelEvent mouseWheelEvent) {
                JScrollBar scrollBar = logTableScrollPane.getVerticalScrollBar();
                LoggerPlusPlus.getInstance().getLoggerPreferences().setAutoScroll(
                        scrollBar.getValue() + scrollBar.getHeight() >= scrollBar.getMaximum());
            }
        });
        logTableScrollPane.getVerticalScrollBar().addMouseListener(new MouseListener() {
            @Override
            public void mouseClicked(MouseEvent mouseEvent) {}
            @Override
            public void mousePressed(MouseEvent mouseEvent) {}
            @Override
            public void mouseReleased(MouseEvent mouseEvent) {
                JScrollBar scrollBar = logTableScrollPane.getVerticalScrollBar();
                LoggerPlusPlus.getInstance().getLoggerPreferences().setAutoScroll(
                        scrollBar.getValue() + scrollBar.getHeight() >= scrollBar.getMaximum());
            }
            @Override
            public void mouseEntered(MouseEvent mouseEvent) {}
            @Override
            public void mouseExited(MouseEvent mouseEvent) {}
        });

        filterPanel = new FilterPanel();

        this.add(this.logTableScrollPane);
    }

    public LogTable getLogTable() {
        return logTable;
    }

    public FilterPanel getFilterPanel() {
        return filterPanel;
    }

    public JScrollPane getScrollPane() {
        return logTableScrollPane;
    }

    public class FilterPanel extends JPanel {
        final private HistoryField filterField;

        FilterPanel(){
            this.setLayout(new GridBagLayout());
            GridBagConstraints gbc = new GridBagConstraints();
            this.filterField = new HistoryField(15, "filterHistory");
            this.filterField.getEditor().getEditorComponent().addKeyListener(new KeyAdapter() {
                @Override
                public void keyReleased(KeyEvent e) {
                    if(e.getKeyChar() == KeyEvent.VK_ENTER){
                        LoggerPlusPlus.getInstance().setFilter((String) filterField.getSelectedItem());
                    }else {
                        super.keyReleased(e);
                    }
                }
            });
            this.filterField.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent actionEvent) {
                    LoggerPlusPlus.getInstance().setFilter((String) filterField.getSelectedItem());
                }
            });

            gbc.fill = GridBagConstraints.BOTH;
            gbc.gridx = 0;
            gbc.weightx = 0;
            gbc.weighty = 1;
            this.add(new JLabel(" Filter: "), gbc);

            gbc.gridx = 1;
            gbc.weightx = 99.0;
            this.add(filterField, gbc);

            final JButton filterButton = new JButton("Saved Filters");
            filterButton.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent actionEvent) {
                    new SavedFiltersDialog().setVisible(true);
                }
            });

            gbc.gridx = 2;
            gbc.weightx = 0;
            this.add(filterButton, gbc);

            final JButton colorFilterButton = new JButton("Colorize");
            colorFilterButton.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent actionEvent) {
                new ColorFilterDialog(LoggerPlusPlus.getInstance().getFilterListeners()).setVisible(true);
                }
            });

            gbc.gridx = 3;
            gbc.weightx = 0;
            this.add(colorFilterButton, gbc);

            final JButton clearLogsButton = new JButton("Clear Logs");
            clearLogsButton.addActionListener(new ActionListener() {
                @Override
                public void actionPerformed(ActionEvent actionEvent) {
                    LoggerPlusPlus.getInstance().getLogManager().reset();
                    LogTable logTable = getLogTable();
                    logTable.getModel().fireTableDataChanged();
                }
            });

            gbc.gridx = 4;
            gbc.weightx = 0;
            this.add(clearLogsButton, gbc);
        }

        public HistoryField getFilterField() {
            return filterField;
        }
    }
}
