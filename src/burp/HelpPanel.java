package burp;

import javax.swing.*;
import java.awt.*;

/**
 * Created by corey on 27/08/17.
 */
public class HelpPanel extends JScrollPane {

    JEditorPane msgpane;

    HelpPanel(){
        JPanel containerPanel = new JPanel(new BorderLayout());
        this.setViewportView(containerPanel);

        msgpane = new JEditorPane();
        msgpane.setEditable(false);
        msgpane.setText("<h3>Help</h3><br /><p>Lorem ipsum dolor sit amer.</p><br /><h3>Filters</h3><p>Filters information, color filters, regex...</p>");
        containerPanel.add(msgpane, BorderLayout.CENTER);
    }
}
