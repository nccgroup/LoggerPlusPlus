package loggerplusplus.filter;

/**
 * Created by corey on 20/07/17.
 */
public interface FilterListener {

    void onFilterChange(ColorFilter filter);
    void onFilterAdd(ColorFilter filter);
    void onFilterRemove(ColorFilter filter);
    void onFilterRemoveAll();
}
