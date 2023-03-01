package com.nccgroup.loggerplusplus.logging;

import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.core.Appender;
import org.apache.logging.log4j.core.Core;
import org.apache.logging.log4j.core.Filter;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.appender.AbstractAppender;
import org.apache.logging.log4j.core.config.plugins.Plugin;
import org.apache.logging.log4j.core.config.plugins.PluginAttribute;
import org.apache.logging.log4j.core.config.plugins.PluginElement;
import org.apache.logging.log4j.core.config.plugins.PluginFactory;
import org.apache.logging.log4j.core.layout.PatternLayout;

@Plugin(name="BurpAppender", category = Core.CATEGORY_NAME, elementType = Appender.ELEMENT_TYPE)
public class BurpAppender extends AbstractAppender {

    public BurpAppender(String name, Filter filter){
        super(name, filter, PatternLayout.createDefaultLayout(), false, null);
    }

    @PluginFactory
    public static BurpAppender createAppender(@PluginAttribute("name") String name, @PluginElement("Filter") Filter filter) {
        return new BurpAppender(name, filter);
    }

    @Override
    public void append(LogEvent event) {
        String message = new String(this.getLayout().toByteArray(event));
        if(LoggerPlusPlus.montoya == null) return;

        if (event.getLevel().isInRange(Level.WARN, Level.FATAL)) {
            LoggerPlusPlus.montoya.logging().logToError(message);
        } else {
            LoggerPlusPlus.montoya.logging().logToOutput(message);
        }
    }
}
