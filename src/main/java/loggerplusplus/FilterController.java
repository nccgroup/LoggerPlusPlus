package loggerplusplus;

import com.coreyd97.BurpExtenderUtilities.HistoryField;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import loggerplusplus.filter.LogFilter;
import loggerplusplus.filter.parser.ParseException;

import java.awt.*;
import java.awt.event.KeyAdapter;
import java.awt.event.KeyEvent;
import java.util.ArrayList;

public class FilterController {

    private final HistoryField filterField;
    private final ArrayList<FilterListener> filterListeners;
    private String currentFilterString;

    public FilterController(Preferences preferences){
        this.filterListeners = new ArrayList<>();
        this.filterField = buildFilterField(preferences);
    }

    private HistoryField buildFilterField(Preferences preferences){
        HistoryField filterField = new HistoryField(preferences, Globals.PREF_FILTER_HISTORY, 15);

        filterField.getEditor().getEditorComponent().addKeyListener(new KeyAdapter() {
            @Override
            public void keyReleased(KeyEvent e) {
                if(e.getKeyChar() == KeyEvent.VK_ENTER){
                    setFilter((String) filterField.getSelectedItem());
                }else {
                    super.keyReleased(e);
                }
            }
        });
        filterField.addActionListener(actionEvent -> {
            if(!actionEvent.getActionCommand().equals("comboBoxEdited"))
                setFilter((String) filterField.getSelectedItem());
        });

        return filterField;
    }

    public void addFilterListener(FilterListener filterListener){
        this.filterListeners.add(filterListener);
    }

    public void removeFilterListener(FilterListener filterListener){
        this.filterListeners.remove(filterListener);
    }

    public void setFilter(String filterString){
        if (filterString == null || filterString.length() == 0) {
            setFilter((LogFilter) null);
        }else if(!filterString.equals(currentFilterString)){
            currentFilterString = filterString;
            try {
                LogFilter filter = new LogFilter(filterString);
                setFilter(filter);
            } catch (ParseException e) {
                for (FilterListener filterListener : filterListeners) {
                    filterListener.onFilterError(filterString, e);
                }
                formatFilter(filterString, Color.WHITE, new Color(221, 70, 57));
            }
        }
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
        if(string != filterField.getSelectedItem()) {
            filterField.setSelectedItem(string);
        }
        filterField.setForegroundColor(foregroundColor);
        filterField.setBackgroundColor(backgroundColor);
    }

    public HistoryField getFilterField(){
        return this.filterField;
    }
}
