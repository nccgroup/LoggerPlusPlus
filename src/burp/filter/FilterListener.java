package burp.filter;

/**
 * Created by corey on 20/07/17.
 */
public interface FilterListener {

    void onChange(ColorFilter filter);
    void onAdd(ColorFilter filter);
    void onRemove(ColorFilter filter);
    void onRemoveAll();
}
