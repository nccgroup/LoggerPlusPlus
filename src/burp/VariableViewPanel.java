package burp;

import javax.swing.*;
import javax.swing.border.Border;
import java.awt.*;

/**
 * Created by corey on 24/08/17.
 */
public class VariableViewPanel extends JPanel {
    public enum View {HORIZONTAL, VERTICAL, TABS}
    private final Component a;
    private final String aTitle;
    private final Component b;
    private final String bTitle;
    private Component wrapper;
    private View view;

    VariableViewPanel(Component a, String aTitle, Component b, String bTitle, View defaultView){
        this.a = a;
        this.aTitle = aTitle;
        this.b = b;
        this.bTitle = bTitle;
        this.setLayout(new BorderLayout());
        this.setView(defaultView);
    }

    public View getView(){
        return this.view;
    }

    public void setView(View view){
        if(view == null) view = View.VERTICAL;
        switch (view){
            case HORIZONTAL:
            case VERTICAL: {
                this.wrapper = new JSplitPane();
                ((JSplitPane) wrapper).setLeftComponent(a);
                ((JSplitPane) wrapper).setRightComponent(b);
                if(view == View.HORIZONTAL){
                    ((JSplitPane) wrapper).setOrientation(JSplitPane.HORIZONTAL_SPLIT);
                }else{
                    ((JSplitPane) wrapper).setOrientation(JSplitPane.VERTICAL_SPLIT);
                }
                ((JSplitPane) wrapper).setDividerLocation(0.5);
                break;
            }
            case TABS: {
                this.wrapper = new JTabbedPane();
                ((JTabbedPane) wrapper).addTab(aTitle, a);
                ((JTabbedPane) wrapper).addTab(bTitle, b);
                break;
            }
        }
        this.removeAll();
        this.add(wrapper, BorderLayout.CENTER);
        this.revalidate();
        this.repaint();
        this.view = view;
    }

}
