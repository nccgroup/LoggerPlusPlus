package burp;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;

import javax.swing.*;
import javax.swing.plaf.basic.BasicComboBoxEditor;
import java.awt.*;
import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.List;

/**
 * Created by corey on 05/09/17.
 */
public class JHistoryField extends JComboBox {
    ArrayList<String> history;
    final int maxHistory;
    String burpSaveLocation;

    JHistoryField(final int maxHistory){
        this.maxHistory = maxHistory;
        history = new ArrayList<String>(){
            @Override
            public boolean add(String s) {
                if(this.size() >= maxHistory) remove(0);
                return super.add(s);
            }
        };
        this.setModel(new HistoryComboModel());
        this.setEditor(new BasicComboBoxEditor(){
            JTextField editorComponent;
            @Override
            protected JTextField createEditorComponent() {
                editorComponent = new JTextField();
                return editorComponent;
            }

            @Override
            public Component getEditorComponent() {
                return editorComponent;
            }
        });
        this.setEditable(true);
        this.setOpaque(true);
    }

    JHistoryField(final int maxHistory, String burpSaveLocation){
        this(maxHistory);
        this.burpSaveLocation = burpSaveLocation;
        String oldSearches = BurpExtender.getInstance().getCallbacks().loadExtensionSetting(burpSaveLocation);
        if(oldSearches != null){
            ArrayList<String> pastHistory = new Gson().fromJson(oldSearches, new TypeToken<List<String>>(){}.getType());
            if(pastHistory != null)
                history.addAll(pastHistory);
        }
    }

    public void setColor(Color color){
        ((JComponent) this.getEditor().getEditorComponent()).setOpaque(false);
        this.getEditor().getEditorComponent().setBackground(color);
    }

    class HistoryComboModel extends DefaultComboBoxModel {

        public void addToHistory(String val){
            if(val.equals("")) return;
            if(history.contains(val)) history.remove(val);
            history.add((String) val);
            if(burpSaveLocation != null){
                BurpExtender.getInstance().getCallbacks().saveExtensionSetting(burpSaveLocation, new Gson().toJson(history, new TypeToken<List<String>>(){}.getType()));
            }
            this.fireContentsChanged(val, history.size()-1, history.size()-1);
        }

        @Override
        public int getSize() {
            return history.size();
        }

        @Override
        public Object getElementAt(int i) {
            return history.get(history.size() - i -1);
        }
    }
}
