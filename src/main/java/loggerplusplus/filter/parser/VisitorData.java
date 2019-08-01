package loggerplusplus.filter.parser;

import java.util.ArrayList;

public class VisitorData {

    private Object data;
    private ArrayList<String> errors = new ArrayList<>();
    private boolean success = true;

    VisitorData(){

    }

    VisitorData(Object data){
        this.data = data;
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

    public Object getData() {
        return data;
    }
}
