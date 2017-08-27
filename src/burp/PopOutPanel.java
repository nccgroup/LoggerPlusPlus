package burp;

import javax.swing.*;
import javax.swing.border.Border;
import java.awt.*;
import java.awt.event.WindowEvent;
import java.awt.event.WindowListener;

/**
 * Created by corey on 24/08/17.
 */
public class PopOutPanel extends JPanel {
    private final Component component;
    private final JLabel placeholder;
    private String title;
    private boolean isPoppedOut;
    private JFrame popoutFrame;

    PopOutPanel(Component component, String title){
        this.component = component;
        this.title = title;
        this.placeholder = new JLabel(title + " is popped out.");
        this.placeholder.setHorizontalAlignment(SwingConstants.CENTER);
        this.setLayout(new BorderLayout());
        this.add(component, BorderLayout.CENTER);
    }

    public void toggle(){
        if (this.isPoppedOut) popIn();
        else popOut();
    }

    public void popIn(){
        this.remove(placeholder);
        this.add(component, BorderLayout.CENTER);
        this.revalidate();
        this.repaint();
        this.isPoppedOut = false;
        //TODO Set button popout text
    }

    public void popOut(){
        //TODO Set button popin text
        this.popoutFrame = new JFrame();
        final PopOutPanel _this = this;
        popoutFrame.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        popoutFrame.addWindowListener(new WindowListener() {
            @Override
            public void windowOpened(WindowEvent windowEvent) {
                popoutFrame.add(component);
                isPoppedOut = true;
                _this.add(placeholder, BorderLayout.CENTER);
                _this.revalidate();
                _this.repaint();
                popoutFrame.pack();
            }

            @Override
            public void windowClosing(WindowEvent windowEvent) {
                popIn();
            }

            @Override
            public void windowClosed(WindowEvent windowEvent) {}

            @Override
            public void windowIconified(WindowEvent windowEvent) {}

            @Override
            public void windowDeiconified(WindowEvent windowEvent) {}

            @Override
            public void windowActivated(WindowEvent windowEvent) {}

            @Override
            public void windowDeactivated(WindowEvent windowEvent) {}
        });

        popoutFrame.setVisible(true);
    }
}
