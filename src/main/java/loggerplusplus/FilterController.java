package loggerplusplus;

import com.coreyd97.BurpExtenderUtilities.HistoryField;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import jdk.nashorn.internal.scripts.JO;
import loggerplusplus.filter.LogFilter;
import loggerplusplus.filter.parser.ParseException;

import javax.swing.*;
import java.awt.*;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.regex.Pattern;

public class FilterController {

    private final HistoryField filterField;
    private final JPopupMenu fieldMenu;
    private final ArrayList<FilterListener> filterListeners;
    private String currentFilterString;

    public FilterController(Preferences preferences){
        this.filterListeners = new ArrayList<>();
        this.filterField = buildFilterField(preferences);
        this.fieldMenu = buildFieldMenu();
    }

    private HistoryField buildFilterField(Preferences preferences){
        HistoryField filterField = new HistoryField(preferences, Globals.PREF_FILTER_HISTORY, 15);

        filterField.getEditor().getEditorComponent().addKeyListener(new KeyAdapter() {
            @Override
            public void keyPressed(KeyEvent e) {
                if(e.getKeyChar() == KeyEvent.VK_ENTER){
                    setFilter((String) filterField.getSelectedItem());
                }else{
                    super.keyReleased(e);
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

        filterField.addActionListener(actionEvent -> {
            if(!actionEvent.getActionCommand().equals("comboBoxEdited"))
                setFilter((String) filterField.getSelectedItem());
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

    public void addFilterListener(FilterListener filterListener){
        this.filterListeners.add(filterListener);
    }

    public void removeFilterListener(FilterListener filterListener){
        this.filterListeners.remove(filterListener);
    }

    public void setFilter(String filterString){
         new Thread(() -> {
            if (filterString == null || filterString.length() == 0) {
                setFilter((LogFilter) null);
            }else if(!filterString.equals(currentFilterString)){
                currentFilterString = filterString;
                try {
                    LogFilter filter = new LogFilter(filterString);
                    setFilter(filter);
                } catch (ParseException e) {
                    for (FilterListener filterListener : filterListeners) {
                        try {
                            filterListener.onFilterError(filterString, e);
                        }catch (Exception e1){
                            e1.printStackTrace();
                        }
                    }
                    JOptionPane.showMessageDialog(SwingUtilities.getWindowAncestor(this.filterField),
                            "<html><body style='width: 400px; overflow-wrap: break-word;'>Could not parse filter:\n" + e.getMessage(), "Parse Error", JOptionPane.ERROR_MESSAGE);
                    formatFilter(filterString, Color.WHITE, new Color(221, 70, 57));
                }
            }
        }).start();
    }

    public void clearFilter(){
        for (FilterListener filterListener : this.filterListeners) {
            filterListener.onFilterCleared();
        }

        formatFilter("", null, null);
    }

    private void setFilter(LogFilter filter){
        if (filter == null) {
            clearFilter();
        } else {
            String filterString = filter.toString();
            ((HistoryField.HistoryComboModel) filterField.getModel()).addToHistory(filterString);
            formatFilter(filterString, Color.BLACK, new Color(76,255, 155));

            new Thread(()->{
                for (FilterListener filterListener : filterListeners) {
                    filterListener.onFilterSet(filter);
                }
            }).start();
        }
    }

    public void formatFilter(String string, Color foregroundColor, Color backgroundColor){
        ((JTextField) filterField.getEditor().getEditorComponent()).setText(string);
        filterField.setForegroundColor(foregroundColor);
        filterField.setBackgroundColor(backgroundColor);
    }

    public HistoryField getFilterField(){
        return this.filterField;
    }
}
