package com.nccgroup.loggerplusplus.filterlibrary;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.filter.colorfilter.ColorFilter;
import com.nccgroup.loggerplusplus.filter.colorfilter.ColorFilterListener;
import com.nccgroup.loggerplusplus.filter.logfilter.LogFilter;
import com.nccgroup.loggerplusplus.filter.savedfilter.SavedFilter;
import com.nccgroup.loggerplusplus.filter.tag.Tag;
import com.nccgroup.loggerplusplus.filter.tag.TagListener;
import com.nccgroup.loggerplusplus.preferences.PreferencesController;
import com.nccgroup.loggerplusplus.util.Globals;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.awt.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.UUID;

public class FilterLibraryController {

    private final LoggerPlusPlus loggerPlusPlus;
    private final Preferences preferences;
    private final FilterLibraryPanel panel;
    private final ArrayList<FilterLibraryListener> listeners;
    private final ArrayList<SavedFilter> savedFilters;
    private final HashMap<UUID, ColorFilter> colorFilters;
    private final ArrayList<ColorFilterListener> colorFilterListeners;
    private final HashMap<UUID, Tag> tagFilters;
    private final ArrayList<TagListener> tagListeners;

    Logger logger = LogManager.getRootLogger();

    public FilterLibraryController(LoggerPlusPlus loggerPlusPlus, PreferencesController preferencesController) {
        this.loggerPlusPlus = loggerPlusPlus;
        this.preferences = preferencesController.getPreferences();
        this.listeners = new ArrayList<>();
        this.colorFilterListeners = new ArrayList<>();
        this.tagListeners = new ArrayList<>();
        this.savedFilters = preferences.getSetting(Globals.PREF_SAVED_FILTERS);
        this.colorFilters = preferences.getSetting(Globals.PREF_COLOR_FILTERS);
        this.tagFilters = preferences.getSetting(Globals.PREF_TAG_FILTERS);
        this.panel = new FilterLibraryPanel(this);
    }

    public LoggerPlusPlus getLoggerPlusPlus() {
        return loggerPlusPlus;
    }

    public FilterLibraryPanel getFilterLibraryPanel() {
        return panel;
    }

    public ArrayList<SavedFilter> getSavedFilters(){
        return this.savedFilters;
    }

    public void addFilter(SavedFilter savedFilter){
        int index;
        synchronized (this.savedFilters) {
            this.savedFilters.add(savedFilter);
            index = this.savedFilters.size()-1;
        }
        for (FilterLibraryListener listener : this.listeners) {
            try{
                listener.onFilterAdded(savedFilter, index);
            }catch (Exception e){
                e.printStackTrace();
            }
        }
        saveFilters();
    }

    public void removeFilter(SavedFilter filter){
        int index;
        synchronized (this.savedFilters){
            index = this.savedFilters.indexOf(filter);
            this.savedFilters.remove(index);
        }
        for (FilterLibraryListener listener : this.listeners) {
            try{
                listener.onFilterRemoved(filter, index);
            }catch (Exception e){
                e.printStackTrace();
            }
        }
        saveFilters();
    }

    public void saveFilters(){
        this.preferences.setSetting(Globals.PREF_SAVED_FILTERS, savedFilters);
    }

    public void addFilterListener(FilterLibraryListener listener){
        this.listeners.add(listener);
    }

    public void removeFilterListener(FilterLibraryListener listener){
        this.listeners.remove(listener);
    }

    public HashMap<UUID, ColorFilter> getColorFilters() {
        return colorFilters;
    }

    public void addColorFilter(String title, LogFilter filter){
        this.addColorFilter(title, filter, Color.BLACK, Color.WHITE);
    }

    public void addColorFilter(String title, LogFilter filter, Color foreground, Color background){
        this.addColorFilter(new ColorFilter(title, filter, foreground, background));
    }

    public void addColorFilter(ColorFilter colorFilter){
        this.colorFilters.put(colorFilter.getUUID(), colorFilter);

        for (ColorFilterListener colorFilterListener : this.colorFilterListeners) {
            try {
                colorFilterListener.onColorFilterAdd(colorFilter);
            } catch (Exception e) {
                logger.error(e);
            }
        }
        saveColorFilters();
    }

    public void removeColorFilter(ColorFilter colorFilter){
        synchronized (this.colorFilters){
            this.colorFilters.remove(colorFilter.getUUID());
        }
        for (ColorFilterListener listener : this.colorFilterListeners) {
            try{
                listener.onColorFilterRemove(colorFilter);
            }catch (Exception e){
                logger.error(e);
            }
        }
        saveColorFilters();
    }

    //Called when a filter is modified.
    public void updateColorFilter(ColorFilter colorFilter){
        for (ColorFilterListener listener : this.colorFilterListeners) {
            try{
                listener.onColorFilterChange(colorFilter);
            }catch (Exception e){
                logger.error(e);
            }
        }
        saveColorFilters();
    }

    public void saveColorFilters(){
        this.preferences.setSetting(Globals.PREF_COLOR_FILTERS, colorFilters);
    }

    public void addColorFilterListener(ColorFilterListener listener) {
        this.colorFilterListeners.add(listener);
    }

    public void removeColorFilterListener(ColorFilterListener listener) {
        this.colorFilterListeners.remove(listener);
    }

    public HashMap<UUID, Tag> getTags() {
        return tagFilters;
    }

    public void addTag(Tag tag) {
        this.tagFilters.put(tag.getUUID(), tag);

        for (TagListener listener : this.tagListeners) {
            try {
                listener.onTagAdd(tag);
            } catch (Exception error) {
                logger.error(error);
            }
        }
        saveTags();
    }

    public void removeTag(Tag tag) {
        synchronized (this.tagFilters) {
            this.tagFilters.remove(tag.getUUID());
        }
        for (TagListener listener : this.tagListeners) {
            try {
                listener.onTagRemove(tag);
            } catch (Exception error) {
                logger.error(error);
            }
        }
        saveTags();
    }

    //Called when a filter is modified.
    public void updateTag(Tag tag) {
        for (TagListener listener : this.tagListeners) {
            try {
                listener.onTagChange(tag);
            } catch (Exception e) {
                logger.error(e);
            }
        }
        saveTags();
    }

    public void saveTags() {
        this.preferences.setSetting(Globals.PREF_TAG_FILTERS, tagFilters);
    }

    public void addTagListener(TagListener listener) {
        this.tagListeners.add(listener);
    }

    public void removeTagListener(TagListener listener) {
        this.tagListeners.remove(listener);
    }

}
