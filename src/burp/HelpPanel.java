package burp;

import javax.swing.*;
import javax.swing.text.html.HTMLDocument;
import javax.swing.text.html.HTMLEditorKit;
import java.awt.*;

/**
 * Created by corey on 27/08/17.
 */
public class HelpPanel extends JPanel {

    JTextPane msgpane;

    HelpPanel(){
        msgpane = new JTextPane();
        this.setLayout(new BorderLayout());
        ScrollablePanel scrollablePanel = new ScrollablePanel();
        scrollablePanel.setScrollableWidth( ScrollablePanel.ScrollableSizeHint.FIT );
        scrollablePanel.setLayout(new BorderLayout());
        scrollablePanel.add(msgpane);

        msgpane.setContentType("text/html");
        msgpane.setEditable(false);
        msgpane.setEditorKit(new HTMLEditorKit());
        msgpane.setText("<html><h1>Logger++</h1><span>Logger++ was developed as an alternative to the log history included within Burp Suite. Advantages over the original implementation are a more comprehensive number of fields, the ability to show only specific entries to better monitor activity via the use of adaptable filters from various fields and row coloring to highlight interesting entries which match a specific filter.</span><br /><br /><h2>Creating Filters</h2><span>Filters were developed with the intention of being highly customisable and therefore may be as simple or complex as you require. Once a filter has been entered, the color of the input field will change to reflect the validity of the filter. If a field is correctly entered, it will be converted to uppercase.</span><br /><br /><span>The basic format of a filter is:</span> <i>FIELD OP VALUE</i><br /><b>FIELD:</b> Most fields are self-descriptively named however to find the name of a filter, right clicking the table header in the field will display the table name and it's filter name in brackets (). <br /><i>E.g. Extension (UrlExtension)</i><br /><b>OP:</b> Comparison operation. <i>Valid operations are <, >, <=, >=, !=, ==.</i><br /><b>VALUE:</b> String, numerical or regex value.<br /><br /><br />Multiple filters can be combined using && and || operators and can be nested on multiple levels.<br />E.g. FILTER && FILTER<br />FILTER || FILTER<br />FILTER && (FILTER || FILTER)<br />FILTER || (FILTER && (FILTER || FILTER))<br /><br /><h2>Using Regular Expressions</h2><span>Instead of static values, regular expressions can be used within filters. To do so simply wrap the regular expression with forward slashes such as /regex/<br />To match a word at any location within a field, wildcards should be placed on either side of the word.</span><br/><span>E.g. RESPONSE == /.*(ng-bind-html|eval).*/</span><br /><br /><h2>Color Filters</h2><span>In addition to standard filters, color filters can be set by clicking the 'Colorize' button in the main tab. To add a filter press the add button and enter a filter as above, and optionally set the title, foreground and background colors. Changes are saved on pressing the close button. </span>");
        this.add(new JScrollPane(scrollablePanel), BorderLayout.CENTER);
    }

    @Override
    public void setSize(Dimension d) {
        super.setSize(d);
        msgpane.setSize(d);
    }
}
