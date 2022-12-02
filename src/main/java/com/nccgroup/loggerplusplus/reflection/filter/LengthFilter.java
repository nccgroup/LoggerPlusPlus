package com.nccgroup.loggerplusplus.reflection.filter;

import burp.api.montoya.http.message.params.HttpParameter;
import com.coreyd97.BurpExtenderUtilities.Alignment;
import com.coreyd97.BurpExtenderUtilities.PanelBuilder;
import com.coreyd97.BurpExtenderUtilities.Preferences;
import com.nccgroup.loggerplusplus.LoggerPlusPlus;

import javax.swing.*;

public class LengthFilter extends ParameterFilter {

    private static String LENGTH_MIN_PREF = "lengthMinFilter";
    private static String LENGTH_MAX_PREF = "lengthMaxFilter";
    private int min_length;
    private int max_length;

    public LengthFilter(Preferences preferences){
        super(preferences, "Value Length Range");
        preferences.registerSetting(LENGTH_MAX_PREF, int.class, 999);
        preferences.registerSetting(LENGTH_MIN_PREF, int.class, 3);

        min_length = preferences.getSetting(LENGTH_MIN_PREF);
        max_length = preferences.getSetting(LENGTH_MAX_PREF);
    }

    @Override
    public boolean isFiltered(HttpParameter parameter) {
        int len = parameter.value().length();
        return len < min_length || len > max_length;

    }

    @Override
    public void showConfigDialog() {
        JLabel info = new JLabel("Enter parameter value length range:");
        JSpinner minLengthSpinner = new JSpinner(new SpinnerNumberModel(min_length, 0, 99999, 1));
        JSpinner maxLengthSpinner = new JSpinner(new SpinnerNumberModel(max_length, 0, 99999, 1));
        JPanel panel = PanelBuilder.build(new JComponent[][]{
                new JComponent[]{info, info},
                new JComponent[]{new JLabel("Minimum: "), minLengthSpinner},
                new JComponent[]{new JLabel("Maximum: "), maxLengthSpinner}
        }, new int[][]{
                new int[]{0},
                new int[]{1},
                new int[]{1},
        }, Alignment.FILL, 1.0, 1.0);
        int result = JOptionPane.showConfirmDialog(LoggerPlusPlus.instance.getLoggerFrame(), panel, "Reflection Value Length Filter", JOptionPane.OK_CANCEL_OPTION);
        if(result == JOptionPane.OK_OPTION){
            min_length = (int) minLengthSpinner.getValue();
            max_length = (int) maxLengthSpinner.getValue();
            preferences.setSetting(LENGTH_MIN_PREF, min_length);
            preferences.setSetting(LENGTH_MAX_PREF, max_length);
        }
    }
}
