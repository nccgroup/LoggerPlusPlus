package loggerplusplus;

import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import loggerplusplus.filter.ColorFilter;
import loggerplusplus.filter.CompoundFilter;
import loggerplusplus.filter.Filter;
import loggerplusplus.userinterface.LogTable;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

public class LoggerContextMenuFactory implements IContextMenuFactory {

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        JMenuItem filterMenu = new JMenu("Logger++");

        if (invocation.getSelectedMessages().length == 0 ||
                invocation.getSelectionBounds()[0] == invocation.getSelectionBounds()[1]) {
            return null;
        }

        final Pattern matchPattern;
        final String context;
        switch (invocation.getInvocationContext()){
            case IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
            case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST: {
                try {
                    byte[] msg = invocation.getSelectedMessages()[0].getRequest();
                    if(LoggerPlusPlus.getCallbacks().getHelpers().analyzeRequest(msg).getBodyOffset() >= invocation.getSelectionBounds()[0]){
                        context = "REQUESTHEADERS";
                    }else{
                        context = "REQUEST";
                    }
                    matchPattern = Pattern.compile(new String(msg).substring(invocation.getSelectionBounds()[0], invocation.getSelectionBounds()[1]), Pattern.LITERAL);
                }catch (NullPointerException nPException){ return null; }
                break;
            }

            case IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE:
            case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE: {
                try{
                    byte[] msg = invocation.getSelectedMessages()[0].getResponse();
                    if(LoggerPlusPlus.getCallbacks().getHelpers().analyzeRequest(msg).getBodyOffset() >= invocation.getSelectionBounds()[0]){
                        context = "RESPONSEHEADERS";
                    }else{
                        context = "RESPONSE";
                    }
                    matchPattern = Pattern.compile(new String(msg).substring(invocation.getSelectionBounds()[0], invocation.getSelectionBounds()[1]), Pattern.LITERAL);
                }catch (NullPointerException nPException){ return null; }
                break;
            }
            default: return null;
        }

        final LogTable logTable = LoggerPlusPlus.getInstance().getLogTable();

        JMenuItem useAsFilter = new JMenuItem(new AbstractAction("Use Selection As Filter") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                try {
                    Filter filter = new Filter(context, "==", matchPattern);
                    LoggerPlusPlus.getInstance().setFilter(filter);
                } catch (Filter.FilterException e1) {return;}
            }
        });

        filterMenu.add(useAsFilter);

        if(logTable.getCurrentFilter() != null) {
            JMenu addToCurrentFilter = new JMenu("Add Selection To Filter");
            JMenuItem andFilter = new JMenuItem(new AbstractAction("AND") {
                @Override
                public void actionPerformed(ActionEvent actionEvent) {
                    try {
                        Filter rFilter = new Filter(context, "==", matchPattern);
                        Filter filter = new CompoundFilter(logTable.getCurrentFilter(), "&&", rFilter);
                        LoggerPlusPlus.getInstance().setFilter(filter);
                    } catch (Filter.FilterException e1) {
                        return;
                    }
                }
            });
            JMenuItem orFilter = new JMenuItem(new AbstractAction("OR") {
                @Override
                public void actionPerformed(ActionEvent actionEvent) {
                    try {
                        Filter rFilter = new Filter(context, "==", matchPattern);
                        Filter filter = new CompoundFilter(logTable.getCurrentFilter(), "||", rFilter);
                        LoggerPlusPlus.getInstance().setFilter(filter);
                    } catch (Filter.FilterException e1) {
                        return;
                    }
                }
            });
            addToCurrentFilter.add(andFilter);
            addToCurrentFilter.add(orFilter);
            filterMenu.add(addToCurrentFilter);
        }

        JMenuItem colorFilterItem = new JMenuItem(new AbstractAction("Set Selection as Color Filter") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                try {
                    ColorFilter colorFilter = new ColorFilter();
                    colorFilter.setFilter(new Filter(context, "==", matchPattern));
                    LoggerPlusPlus.getInstance().getLoggerPreferences().getColorFilters().put(colorFilter.getUid(), colorFilter);
                } catch (Filter.FilterException e1) {
                    return;
                }
            }
        });
        filterMenu.add(colorFilterItem);
        return Arrays.asList(filterMenu);
    }
}
