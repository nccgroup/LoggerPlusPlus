package com.nccgroup.loggerplusplus.filter.logfilter;

import com.coreyd97.BurpExtenderUtilities.HistoryField;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.util.Globals;
import com.nccgroup.loggerplusplus.filter.parser.ParseException;
import com.nccgroup.loggerplusplus.logentry.LogEntryField;

import javax.swing.*;
import java.awt.*;
import java.awt.event.*;
import java.util.ArrayList;
import java.util.HashMap;

public class LogFilterController {

    private final HistoryField filterField;
    private final JPopupMenu fieldMenu;
    private final ArrayList<LogFilterListener> logFilterListeners;
    private String currentFilterString;

    public LogFilterController(Preferences preferences){
        this.logFilterListeners = new ArrayList<>();
        this.filterField = buildFilterField(preferences);
        this.fieldMenu = buildFieldMenu();
    }

    private HistoryField buildFilterField(Preferences preferences){
        HistoryField filterField = new HistoryField(preferences, Globals.PREF_FILTER_HISTORY, 15);

        filterField.getEditor().getEditorComponent().addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if(e.getKeyChar() == KeyEvent.VK_ENTER){
                    //Update only when pressing enter after typing
                    setFilter((String) filterField.getEditor().getItem());
                }
            }
        });

        filterField.getEditor().getEditorComponent().addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                if(SwingUtilities.isRightMouseButton(e)){
                    fieldMenu.show(filterField, e.getX(), e.getY());
                }
            }
        });

        //Update when clicking an item in the list, but not when using arrow keys to move
        filterField.addActionListener(e -> {
            //Only update from clicking the mouse
            if((e.getModifiers() & (ActionEvent.MOUSE_EVENT_MASK | ActionEvent.FOCUS_EVENT_MASK)) != 0) {
                setFilter((String) filterField.getSelectedItem());
            }
        });

        return filterField;
    }

    private JPopupMenu buildFieldMenu(){
        JTextField editor = (JTextField) filterField.getEditor().getEditorComponent();

        JPopupMenu autoComplete = new JPopupMenu();
        HashMap<LogEntryField.Group, JMenu> groupMenus = new HashMap<>();
        for (LogEntryField.Group group : LogEntryField.Group.values()) {
            groupMenus.put(group, new JMenu(group.getLabel()));
        }

        for (LogEntryField field : LogEntryField.values()) {
            JMenuItem fieldItem = new JMenuItem(field.getLabels()[0]);
            fieldItem.addActionListener((e) -> {
                editor.setText(editor.getText() + field.getFullLabel());
            });
            groupMenus.get(field.getGroup()).add(fieldItem);
        }

        for (JMenu menu : groupMenus.values()) {
            autoComplete.add(menu);
        }

        return autoComplete;
    }

    public void addFilterListener(LogFilterListener logFilterListener){
        this.logFilterListeners.add(logFilterListener);
    }

    public void removeFilterListener(LogFilterListener logFilterListener){
        this.logFilterListeners.remove(logFilterListener);
    }

    public void setFilter(final String filterString){
         SwingUtilities.invokeLater(() -> {
            if (filterString == null || filterString.length() == 0 || filterString.matches(" +")) {
                setFilter((LogFilter) null);
            }else if(!filterString.equals(currentFilterString)){
                currentFilterString = filterString;
                try {
                    LogFilter filter = new LogFilter(LoggerPlusPlus.instance.getLibraryController(), filterString);
                    setFilter(filter);
                } catch (ParseException e) {
                    for (LogFilterListener logFilterListener : logFilterListeners) {
                        try {
                            logFilterListener.onFilterError(filterString, e);
                        }catch (Exception e1){
                            e1.printStackTrace();
                        }
                    }
                    JOptionPane.showMessageDialog(SwingUtilities.getWindowAncestor(this.filterField),
                            "<html><body style='width: 400px; overflow-wrap: break-word;'>Could not parse filter:\n" + e.getMessage(), "Parse Error", JOptionPane.ERROR_MESSAGE);
                    formatFilter(filterString, Color.WHITE, new Color(221, 70, 57));
                }
            }
        });
    }

    public void clearFilter(){
        for (LogFilterListener logFilterListener : this.logFilterListeners) {
            logFilterListener.onFilterCleared();
        }

        formatFilter("", null, null);
    }

    private void setFilter(LogFilter filter){
        if (filter == null) {
            clearFilter();
        } else {
            String filterString = filter.toString();
            formatFilter(filterString, Color.BLACK, new Color(76,255, 155));

            new Thread(()->{
                for (LogFilterListener logFilterListener : logFilterListeners) {
                    logFilterListener.onFilterSet(filter);
                }
            }).start();
        }
    }

    public void formatFilter(String string, Color foregroundColor, Color backgroundColor){
        SwingUtilities.invokeLater(() -> {
            if(!string.equalsIgnoreCase("")) {
                ((HistoryField.HistoryComboModel) filterField.getModel()).addToHistory(string);
                filterField.setSelectedItem(string);
            }else{
                filterField.setSelectedItem(null);
            }
            filterField.setForegroundColor(foregroundColor);
            filterField.setBackgroundColor(backgroundColor);
        });
    }

    public HistoryField getFilterField(){
        return this.filterField;
    }
}
