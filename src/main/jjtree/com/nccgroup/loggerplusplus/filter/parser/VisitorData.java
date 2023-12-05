package com.nccgroup.loggerplusplus.filter.parser;

import java.util.ArrayList;
import java.util.HashMap;

public class VisitorData {

    private ArrayList<String> errors = new ArrayList<>();
    private boolean success = true;
    private HashMap<String, Object> data = new HashMap<>();

    VisitorData(){

    }

    public void addError(String error){
        this.errors.add(error);
        this.success = false;
    }

    public void setSuccess(boolean success){
        this.success = success;
    }

    public boolean isSuccess() {
        return success;
    }

    public ArrayList<String> getErrors() {
        return errors;
    }

    public String getErrorString(){
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < errors.size(); i++) {
            sb.append(errors.get(i));
            if(i != errors.size()-1) sb.append("\n");
        }
        return sb.toString();
    }

    public HashMap<String, Object> getData() {
        return data;
    }

    public void setData(String key, Object value){
        this.data.put(key, value);
    }
}
