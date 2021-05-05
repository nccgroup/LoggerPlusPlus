package com.nccgroup.loggerplusplus.logging;

import org.apache.logging.log4j.core.*;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.plugins.Plugin;
import org.apache.logging.log4j.core.config.plugins.PluginAttribute;
import org.apache.logging.log4j.core.config.plugins.PluginElement;
import org.apache.logging.log4j.core.config.plugins.PluginFactory;

import javax.swing.*;
import java.util.ArrayList;

import static javax.swing.SwingUtilities.invokeLater;
import static org.apache.logging.log4j.core.config.Property.EMPTY_ARRAY;
import static org.apache.logging.log4j.core.layout.PatternLayout.createDefaultLayout;

/**
 * JTextAreaAppender - https://stackoverflow.com/a/29736246
 * Credit to https://stackoverflow.com/users/4544015/vshiro
 */

@Plugin(name = "JTextAreaAppender", category = Core.CATEGORY_NAME, elementType = Appender.ELEMENT_TYPE)
public class JTextAreaAppender extends AbstractAppender {
    private static volatile ArrayList<JTextArea> textAreas = new ArrayList<>();

    private int maxLines;

    private JTextAreaAppender(String name, Layout<?> layout, Filter filter, int maxLines, boolean ignoreExceptions) {
        super(name, filter, layout, ignoreExceptions, EMPTY_ARRAY);
        this.maxLines = maxLines;
    }

    @SuppressWarnings("unused")
    @PluginFactory
    public static JTextAreaAppender createAppender(@PluginAttribute("name") String name,
                                                   @PluginAttribute("maxLines") int maxLines,
                                                   @PluginAttribute("ignoreExceptions") boolean ignoreExceptions,
                                                   @PluginElement("Layout") Layout<?> layout,
                                                   @PluginElement("Filters") Filter filter) {
        if (name == null) {
            LOGGER.error("No name provided for JTextAreaAppender");
            return null;
        }

        if (layout == null) {
            layout = createDefaultLayout();
        }
        return new JTextAreaAppender(name, layout, filter, maxLines, ignoreExceptions);
    }

    // Add the target JTextArea to be populated and updated by the logging information.
    public static void addLog4j2TextAreaAppender(final JTextArea textArea) {
        JTextAreaAppender.textAreas.add(textArea);
    }

    @Override
    public void append(LogEvent event) {
        String message = new String(this.getLayout().toByteArray(event));

        // Append formatted message to text area using the Thread.
        try {
            invokeLater(() ->
            {
                for (JTextArea textArea : textAreas) {
                    try {
                        if (textArea != null) {
                            if (textArea.getText().length() == 0) {
                                textArea.setText(message);
                            } else {
                                textArea.append("\n" + message);
                                if (maxLines > 0 & textArea.getLineCount() > maxLines + 1) {
                                    int endIdx = textArea.getDocument().getText(0, textArea.getDocument().getLength()).indexOf("\n");
                                    textArea.getDocument().remove(0, endIdx + 1);
                                }
                            }
                            String content = textArea.getText();
                            textArea.setText(content.substring(0, content.length() - 1));
                        }
                    } catch (Throwable throwable) {
                        throwable.printStackTrace();
                    }
                }
            });
        } catch (IllegalStateException exception) {
            exception.printStackTrace();
        }
    }
}
