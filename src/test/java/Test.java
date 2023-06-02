import com.nccgroup.loggerplusplus.LoggerPlusPlus;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class Test {
    public static void main(String[] args) {
        try {
            Method main = Class.forName("burp.StartBurp").getMethod("main", String[].class);
            ArrayList<String> argList = new ArrayList<>(Arrays.stream(args).toList());
            argList.add("--developer-extension-class-name=" + LoggerPlusPlus.class.getName());
            main.invoke(null, (Object) argList.toArray(new String[]{}));
        }catch (Exception e){
            System.err.println("Cannot start burp. Check the burp jar is correctly included in the classpath.");
            e.printStackTrace();
        }
    }
}
