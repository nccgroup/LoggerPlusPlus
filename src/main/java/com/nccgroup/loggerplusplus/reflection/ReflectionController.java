package com.nccgroup.loggerplusplus.reflection;

import burp.api.montoya.http.message.params.HttpParameter;
import com.coreyd97.BurpExtenderUtilities.Alignment;
import com.coreyd97.BurpExtenderUtilities.PanelBuilder;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;
import com.nccgroup.loggerplusplus.reflection.filter.BlacklistFilter;
import com.nccgroup.loggerplusplus.reflection.filter.LengthFilter;
import com.nccgroup.loggerplusplus.reflection.filter.ParameterFilter;
import com.nccgroup.loggerplusplus.reflection.transformer.*;
import com.nccgroup.loggerplusplus.util.AsciiCase;
import com.nccgroup.loggerplusplus.util.userinterface.renderer.BooleanRenderer;
import com.nccgroup.loggerplusplus.util.userinterface.renderer.ButtonRenderer;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.List;

public class ReflectionController {

    List<ParameterFilter> filterList = new ArrayList<>();
    List<ParameterValueTransformer> transformerList = new ArrayList<>();

    public ReflectionController(Preferences preferences){
        filterList.add(new BlacklistFilter(preferences));
        filterList.add(new LengthFilter(preferences));

        transformerList.add(new HexEncodeTransformer(preferences));
        transformerList.add(new URLEncodeTransformer(preferences));
        transformerList.add(new URLDecodeTransformer(preferences));
        transformerList.add(new Base64EncodeTransformer(preferences));
        transformerList.add(new Base64DecodeTransformer(preferences));
        transformerList.add(new HTMLEscapeTransformer(preferences));
        transformerList.add(new HTMLUnescapeTransformer(preferences));
        transformerList.add(new JsonEscapeTransformer(preferences));
        transformerList.add(new JsonUnescapeTransformer(preferences));
        transformerList.add(new XMLEscapeTransformer(preferences));
        transformerList.add(new XMLUnescapeTransformer(preferences));
    }

    public List<HttpParameter> filterParameters(List<? extends HttpParameter> allParameters){
        List<HttpParameter> interestingParameters = new ArrayList<>();
        for (HttpParameter parameter : allParameters) {
            if(!isParameterFiltered(parameter)) interestingParameters.add(parameter);
        }
        return interestingParameters;
    }
    
    public boolean isParameterFiltered(HttpParameter parameter){
        for (ParameterFilter filter : filterList) {
            if(!filter.isEnabled()) continue;
            if(filter.isFiltered(parameter)){
                return true;
            }
        }
        return false;
    }
    
    /** Whether {@code responseBody} reflects the parameter's value; see {@link Scan#reflects}. */
    public boolean validReflection(String responseBody, HttpParameter param){
        return new Scan(responseBody).reflects(param);
    }

    /** A search of one response body, reused for every parameter of its request. */
    public Scan scan(String responseBody){
        return new Scan(responseBody);
    }

    /**
     * One response body searched for parameter values. The body is folded to lower case at most
     * once, however many parameters and encodings are looked for, and each search is a plain
     * substring search: compiling a pattern per value and encoding, and matching it against the
     * whole body, was 96 % of the cost of logging a message.
     */
    public final class Scan {
        private final String body;
        private String loweredBody;

        private Scan(String body){
            this.body = body;
        }

        /**
         * Whether the body contains the parameter's value as sent, or, without regard to the case
         * of the letters A to Z, in one of the enabled encodings.
         */
        public boolean reflects(HttpParameter param){
            String value = param.value();
            if(param.name().isEmpty() || value.isEmpty()) return false;

            if(body.contains(value)) return true;

            //Most encodings leave most values as they are: each distinct form is searched for once.
            String[] searched = new String[transformerList.size()];
            int searchedCount = 0;
            for (ParameterValueTransformer transformer : transformerList) {
                if (!transformer.isEnabled()) continue;

                String encoded;
                try {
                    encoded = AsciiCase.lower(transformer.transform(value));
                }catch (Exception e){
                    //Transformation failed. Ignore and continue.
                    continue;
                }
                if (contains(searched, searchedCount, encoded)) continue;

                searched[searchedCount++] = encoded;
                if (loweredBody().contains(encoded)) {
                    return true;
                }
            }
            return false;
        }

        private String loweredBody(){
            if (loweredBody == null) {
                loweredBody = AsciiCase.lower(body);
            }
            return loweredBody;
        }

        private static boolean contains(String[] values, int count, String value){
            for (int i = 0; i < count; i++) {
                if (values[i].equals(value)) return true;
            }
            return false;
        }
    }

    public void showFilterConfigDialog(){
        JDialog dialog = new JDialog(
                JOptionPane.getFrameForComponent(LoggerPlusPlus.instance.getMainViewController().getUiComponent()),
                "LoggerPlusPlus - Reflections Filters", true);
        dialog.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
        JPanel wrapper = new JPanel(new BorderLayout());

        JTable configurationTable = new JTable(new FilterTableModel());
        configurationTable.setRowHeight(25);
        configurationTable.getColumnModel().getColumn(0).setCellRenderer(new BooleanRenderer());
        configurationTable.getColumnModel().getColumn(1).setMinWidth(200);
        configurationTable.getColumnModel().getColumn(2).setCellRenderer(new ButtonRenderer());
        configurationTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                int col = configurationTable.columnAtPoint(e.getPoint());
                int row = configurationTable.rowAtPoint(e.getPoint());
                if(col == 2) filterList.get(row).showConfigDialog();
            }
        });

        JPanel mainPanel = PanelBuilder.build(new JComponent[][]{
                new JComponent[]{new JLabel("Configure parameter filters for reflections:")},
                new JComponent[]{new JScrollPane(configurationTable)},
        }, new int[][]{new int[]{0}, new int[]{1}}, Alignment.FILL, 1.0, 1.0);
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        wrapper.add(mainPanel, BorderLayout.CENTER);

        dialog.add(wrapper);
        dialog.pack();
        dialog.setVisible(true);
    }

    public void showValueTransformerDialog(){
        JDialog dialog = new JDialog(
                JOptionPane.getFrameForComponent(LoggerPlusPlus.instance.getMainViewController().getUiComponent()),
                "LoggerPlusPlus - Reflections Value Transformers", true);
        dialog.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);
        JPanel wrapper = new JPanel(new BorderLayout());

        JTable configurationTable = new JTable(new TransformerTableModel());
        configurationTable.setRowHeight(25);
        configurationTable.getColumnModel().getColumn(0).setCellRenderer(new BooleanRenderer());
        configurationTable.getColumnModel().getColumn(1).setMinWidth(200);

        JPanel mainPanel = PanelBuilder.build(new JComponent[][]{
                new JComponent[]{new JLabel("Configure parameter value transformers for reflections:")},
                new JComponent[]{new JScrollPane(configurationTable)},
        }, new int[][]{new int[]{0}, new int[]{1}}, Alignment.FILL, 1.0, 1.0);
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));
        wrapper.add(mainPanel, BorderLayout.CENTER);

        dialog.add(wrapper);
        dialog.pack();
        dialog.setVisible(true);
    }

    private class FilterTableModel extends DefaultTableModel{

        @Override
        public int getRowCount() {
            return filterList.size();
        }

        @Override
        public int getColumnCount() {
            return 3;
        }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            switch(columnIndex){
                case 0: return Boolean.class;
                case 2: return JButton.class;
                default: return String.class;
            }
        }

        @Override
        public String getColumnName(int column) {
            switch (column){
                case 0: return "Enabled";
                case 1: return "Name";
                default: return "";
            }
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            switch (columnIndex){
                case 0: return filterList.get(rowIndex).isEnabled();
                case 1: return filterList.get(rowIndex).getName();
                case 2: return new JButton("Configure");
            }
            return "";
        }

        @Override
        public boolean isCellEditable(int row, int column) {
            return column == 0;
        }

        @Override
        public void setValueAt(Object val, int row, int column) {
            if(column == 0) filterList.get(row).setEnabled((Boolean) val);
        }
    }

    private class TransformerTableModel extends DefaultTableModel{

        @Override
        public int getRowCount() {
            return transformerList.size();
        }

        @Override
        public int getColumnCount() {
            return 2;
        }

        @Override
        public Class<?> getColumnClass(int columnIndex) {
            switch(columnIndex){
                case 0: return Boolean.class;
                default: return String.class;
            }
        }

        @Override
        public String getColumnName(int column) {
            switch (column){
                case 0: return "Enabled";
                case 1: return "Name";
                default: return "";
            }
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            switch (columnIndex){
                case 0: return transformerList.get(rowIndex).isEnabled();
                case 1: return transformerList.get(rowIndex).getName();
                default: return "";
            }
        }

        @Override
        public boolean isCellEditable(int row, int column) {
            return column == 0;
        }

        @Override
        public void setValueAt(Object val, int row, int column) {
            if(column == 0) transformerList.get(row).setEnabled((Boolean) val);
        }
    }
}
