package com.nccgroup.loggerplusplus.filterlibrary;

import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.loggerplusplus.filter.FilterExpression;
import com.nccgroup.loggerplusplus.filter.colorfilter.TableColorRule;
import com.nccgroup.loggerplusplus.filter.colorfilter.ColorFilterListener;
import com.nccgroup.loggerplusplus.filter.logfilter.LogTableFilter;
import com.nccgroup.loggerplusplus.filter.savedfilter.SavedFilter;
import com.nccgroup.loggerplusplus.filter.tag.Tag;
import com.nccgroup.loggerplusplus.filter.tag.TagListener;
import com.nccgroup.loggerplusplus.preferences.PreferencesController;
import com.nccgroup.loggerplusplus.util.Globals;
import lombok.extern.log4j.Log4j2;

import java.awt.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.UUID;

@Log4j2
public class FilterLibraryController {

    private final Preferences preferences;
    private final FilterLibraryPanel panel;
    private final ArrayList<FilterLibraryListener> listeners;
    private final ArrayList<SavedFilter> savedFilters;
    private final HashMap<UUID, TableColorRule> colorFilters;
    private final ArrayList<ColorFilterListener> colorFilterListeners;
    private final HashMap<UUID, Tag> tagFilters;
    private final ArrayList<TagListener> tagListeners;

    public FilterLibraryController(PreferencesController preferencesController) {
        this.preferences = preferencesController.getPreferences();
        this.listeners = new ArrayList<>();
        this.colorFilterListeners = new ArrayList<>();
        this.tagListeners = new ArrayList<>();
        this.savedFilters = preferences.getSetting(Globals.PREF_SAVED_FILTERS);
        this.colorFilters = preferences.getSetting(Globals.PREF_COLOR_FILTERS);
        this.tagFilters = preferences.getSetting(Globals.PREF_TAG_FILTERS);
        this.panel = new FilterLibraryPanel(this);
    }

    public FilterLibraryPanel getFilterLibraryPanel() {
        return panel;
    }

    public ArrayList<SavedFilter> getFilterSnippets(){
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

    public HashMap<UUID, TableColorRule> getColorFilters() {
        return colorFilters;
    }

    public void addColorFilter(String title, FilterExpression filter){
        this.addColorFilter(title, filter, Color.BLACK, Color.WHITE);
    }

    public void addColorFilter(String title, FilterExpression filter, Color foreground, Color background){
        this.addColorFilter(new TableColorRule(title, filter));
    }

    public void addColorFilter(TableColorRule tableColorRule){
        this.colorFilters.put(tableColorRule.getUuid(), tableColorRule);

        for (ColorFilterListener colorFilterListener : this.colorFilterListeners) {
            try {
                colorFilterListener.onColorFilterAdd(tableColorRule);
            } catch (Exception e) {
                log.error(e);
            }
        }
        saveColorFilters();
    }

    public void removeColorFilter(TableColorRule tableColorRule){
        synchronized (this.colorFilters){
            this.colorFilters.remove(tableColorRule.getUuid());
        }
        for (ColorFilterListener listener : this.colorFilterListeners) {
            try{
                listener.onColorFilterRemove(tableColorRule);
            }catch (Exception e){
                log.error(e);
            }
        }
        saveColorFilters();
    }

    //Called when a filter is modified.
    public void updateColorFilter(TableColorRule tableColorRule){
        for (ColorFilterListener listener : this.colorFilterListeners) {
            try{
                listener.onColorFilterChange(tableColorRule);
            }catch (Exception e){
                log.error(e);
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
        this.tagFilters.put(tag.getUuid(), tag);

        for (TagListener listener : this.tagListeners) {
            try {
                listener.onTagAdd(tag);
            } catch (Exception error) {
                log.error(error);
            }
        }
        saveTags();
    }

    public void removeTag(Tag tag) {
        synchronized (this.tagFilters) {
            this.tagFilters.remove(tag.getUuid());
        }
        for (TagListener listener : this.tagListeners) {
            try {
                listener.onTagRemove(tag);
            } catch (Exception error) {
                log.error(error);
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
                log.error(e);
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

    public void propagateChangesToSnippetUsers(SavedFilter savedFilter) {
        String snippet = savedFilter.getName();
        for (TableColorRule tableColorRule : this.getColorFilters().values()) {
            if(tableColorRule.getFilterExpression().getSnippetDependencies().contains(snippet)){
                updateColorFilter(tableColorRule);
            }
        }

        for (Tag tag : this.getTags().values()) {
            if(tag.getFilterExpression().getSnippetDependencies().contains(snippet)){
                updateTag(tag);
            }
        }
    }
}
