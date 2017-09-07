package loggerplusplus.filter;

/**
 * Created by corey on 19/07/17.
 */
public class SavedFilter {
    private String name;
    private Filter filter;
    private String filterString;

    public SavedFilter(){

    }

    public Filter getFilter() {
        return filter;
    }

    public void setFilter(Filter filter) {
        this.filter = filter;
        if(filter != null)
            this.filterString = filter.toString();
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getFilterString() {
        return filterString;
    }

    public void setFilterString(String filterString) {
        this.filterString = filterString;
    }
}
