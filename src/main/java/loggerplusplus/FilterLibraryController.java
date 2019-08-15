package loggerplusplus;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import loggerplusplus.filter.SavedFilter;
import loggerplusplus.userinterface.FilterLibraryPanel;

import java.util.ArrayList;

public class FilterLibraryController {

    private final Preferences preferences;
    private final FilterLibraryPanel panel;
    private final ArrayList<SavedFilter> savedFilters;
    private final ArrayList<FilterLibraryListener> listeners;

    public FilterLibraryController(Preferences preferences){
        this.preferences = preferences;
        this.listeners = new ArrayList<>();
        this.savedFilters = preferences.getSetting(Globals.PREF_SAVED_FILTERS);
        this.panel = new FilterLibraryPanel(this);
    }

    public FilterLibraryPanel getUIComponent() {
        return panel;
    }

    public ArrayList<SavedFilter> getSavedFilters(){
        return this.savedFilters;
    }

    public void addFilter(SavedFilter savedFilter){
        synchronized (this.savedFilters) {
            this.savedFilters.add(savedFilter);
        }
        for (FilterLibraryListener listener : this.listeners) {
            try{
                listener.onFilterAdded(savedFilter);
            }catch (Exception e){
                e.printStackTrace();
            }
        }
        saveFilters();
    }

    public void removeFilter(int index){
        removeFilter(savedFilters.get(index));
    }

    public void removeFilter(SavedFilter filter){
        synchronized (this.savedFilters){
            this.savedFilters.remove(filter);
        }
        for (FilterLibraryListener listener : this.listeners) {
            try{
                listener.onFilterRemoved(filter);
            }catch (Exception e){
                e.printStackTrace();
            }
        }
        saveFilters();
    }

    public void saveFilters(){
        this.preferences.setSetting(Globals.PREF_SAVED_FILTERS, savedFilters);
    }

    public void addListener(FilterLibraryListener listener){
        this.listeners.add(listener);
    }

    public void removeListener(FilterLibraryListener listener){
        this.listeners.remove(listener);
    }
}
