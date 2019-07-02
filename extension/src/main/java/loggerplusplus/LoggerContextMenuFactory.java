package loggerplusplus;

import burp.IContextMenuFactory;
import burp.IContextMenuInvocation;
import loggerplusplus.filter.ColorFilter;
import loggerplusplus.filter.LogFilter;
import loggerplusplus.filter.parser.ParseException;
import loggerplusplus.userinterface.LogTable;
import loggerplusplus.userinterface.dialog.ColorFilterDialog;

import javax.swing.*;
import java.awt.event.ActionEvent;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.UUID;
import java.util.regex.Pattern;

import static loggerplusplus.Globals.PREF_COLOR_FILTERS;

public class LoggerContextMenuFactory implements IContextMenuFactory {

    @Override
    public List<JMenuItem> createMenuItems(IContextMenuInvocation invocation) {
        if(invocation == null) return null;
        JMenuItem filterMenu = new JMenu("Logger++");

        if (invocation.getSelectedMessages().length == 0 ||
                invocation.getSelectionBounds()[0] == invocation.getSelectionBounds()[1]) {
            return null;
        }

        final String context;
        final byte[] selectedBytes;
        switch (invocation.getInvocationContext()){
            case IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
            case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_REQUEST: {
                try {
                    byte[] msg = invocation.getSelectedMessages()[0].getRequest();
                    if(LoggerPlusPlus.callbacks.getHelpers().analyzeRequest(msg).getBodyOffset() >= invocation.getSelectionBounds()[0]){
                        context = "REQUESTHEADERS";
                    }else{
                        context = "REQUEST";
                    }
                    selectedBytes = Arrays.copyOfRange(invocation.getSelectedMessages()[0].getRequest(),
                            invocation.getSelectionBounds()[0],invocation.getSelectionBounds()[1]);
                }catch (NullPointerException nPException){ return null; }
                break;
            }

            case IContextMenuInvocation.CONTEXT_MESSAGE_EDITOR_RESPONSE:
            case IContextMenuInvocation.CONTEXT_MESSAGE_VIEWER_RESPONSE: {
                try{
                    byte[] msg = invocation.getSelectedMessages()[0].getResponse();
                    if(LoggerPlusPlus.callbacks.getHelpers().analyzeRequest(msg).getBodyOffset() >= invocation.getSelectionBounds()[0]){
                        context = "RESPONSEHEADERS";
                    }else{
                        context = "RESPONSE";
                    }
                    selectedBytes = Arrays.copyOfRange(invocation.getSelectedMessages()[0].getResponse(),
                            invocation.getSelectionBounds()[0],invocation.getSelectionBounds()[1]);
                }catch (NullPointerException nPException){ return null; }
                break;
            }
            default: return null;
        }

        String sanitizedString = Pattern.quote(new String(selectedBytes));
        final Pattern matchPattern = Pattern.compile(sanitizedString, Pattern.LITERAL);

        final LogTable logTable = LoggerPlusPlus.instance.getLogTable();

        JMenuItem useAsFilter = new JMenuItem(new AbstractAction("Use Selection As LogFilter") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                LoggerPlusPlus.instance.getFilterController().setFilter(context +  " == /" + matchPattern + "/");
            }
        });

        filterMenu.add(useAsFilter);

        if(logTable.getCurrentFilter() != null) {
            JMenu addToCurrentFilter = new JMenu("Add Selection To LogFilter");
            JMenuItem andFilter = new JMenuItem(new AbstractAction("AND") {
                @Override
                public void actionPerformed(ActionEvent actionEvent) {
                    LoggerPlusPlus.instance.getFilterController().setFilter(logTable.getCurrentFilter().toString() + " && "
                            + context + " == /" + matchPattern + "/");
                }
            });
            JMenuItem orFilter = new JMenuItem(new AbstractAction("OR") {
                @Override
                public void actionPerformed(ActionEvent actionEvent) {
                    LoggerPlusPlus.instance.getFilterController().setFilter(logTable.getCurrentFilter().toString() + " || "
                            + context + " == /" + matchPattern + "/");
                }
            });
            addToCurrentFilter.add(andFilter);
            addToCurrentFilter.add(orFilter);
            filterMenu.add(addToCurrentFilter);
        }

        JMenuItem colorFilterItem = new JMenuItem(new AbstractAction("Set Selection as Color LogFilter") {
            @Override
            public void actionPerformed(ActionEvent actionEvent) {
                try {
                    ColorFilter colorFilter = new ColorFilter();
                    colorFilter.setFilter(new LogFilter(context + " == /" + matchPattern + "/"));
                    HashMap<UUID,ColorFilter> colorFilters = (HashMap<UUID, ColorFilter>) LoggerPlusPlus.preferences.getSetting(PREF_COLOR_FILTERS);
                    colorFilters.put(colorFilter.getUid(), colorFilter);
                    new ColorFilterDialog(LoggerPlusPlus.instance.getColorFilterListeners()).setVisible(true);
                } catch (ParseException e) {
                    return;
                }
            }
        });
        filterMenu.add(colorFilterItem);
        return Arrays.asList(filterMenu);
    }
}
