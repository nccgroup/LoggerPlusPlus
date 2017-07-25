package burp;

import javax.swing.*;
import java.io.UnsupportedEncodingException;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MoreHelp {
	
	// Read the Content-Type value from the header
	public static String findHeaderContentType(String strHeader){
		String contentType="";
		if(!strHeader.equals("")){
			Pattern MY_PATTERN = Pattern.compile("(?im)^content-type:([\\ \\w\\/\\-\\_\\,]*)"); // just in case, it also includes ",_ " 
			Matcher m = MY_PATTERN.matcher(strHeader);
			if (m.find()) {
				contentType = m.group(1);
			}
		}
		return contentType;
	}
	
	// Read the Content-Type value from the header
	public static String findHeaderContentType(List<String> headers){
		String contentType="";
		for(String strHeader : headers){
			if(!strHeader.equals("")){
				Pattern MY_PATTERN = Pattern.compile("(?im)^content-type:([\\ \\w\\/\\-\\_\\,]*)"); // just in case, it also includes ",_ " 
				Matcher m = MY_PATTERN.matcher(strHeader);
				if (m.find()) {
					contentType = m.group(1);
					break;
				}
			}
		}
		return contentType;
	}
	
	// Show a message to the user
	public static void showMessage(final String strMsg){
		new Thread(new Runnable()
		{
			@Override
			public void run()
			{
				JOptionPane.showMessageDialog(null, strMsg);
			}
		}).start();
		
	}
	
	// Show a message to the user
	public static void showWarningMessage(final String strMsg){
		new Thread(new Runnable()
		{
			@Override
			public void run()
			{
				JOptionPane.showMessageDialog(null, strMsg, "Warning", JOptionPane.WARNING_MESSAGE);
			}
		}).start();
		
	}
	
	// Show a message to the user
	public static String showPlainInputMessage(final String strMessage, final String strTitle, final String defaultValue){
			String output = (String)JOptionPane.showInputDialog(null, 
						strMessage,strTitle,JOptionPane.PLAIN_MESSAGE, null, null, defaultValue); 
			if(output==null){
				output = defaultValue;
			}
			return output;	
	}
	
	// Common method to ask a multiple question
	public static Integer askConfirmMessage(final String strTitle, final String strQuestion, String[] msgOptions){
		final Object[] options = msgOptions;
	    final int[] choice = new int[1];
	    choice[0] = 0;
	    choice[0] = JOptionPane.showOptionDialog(null,
					strQuestion,
					strTitle,
					JOptionPane.YES_NO_CANCEL_OPTION,
					JOptionPane.QUESTION_MESSAGE,
					null,
					options,
					options[0]);
	    return choice[0];
	}
	
	// Split header and body of a request or response
	public static String[] getHeaderAndBody(byte[] fullMessage,String encoding) throws UnsupportedEncodingException{
		String[] result = {"",""};
		String strFullMessage = "";
		if(fullMessage != null){
			// splitting the message to retrieve the header and the body
			strFullMessage = new String(fullMessage,encoding);
			if(strFullMessage.contains("\r\n\r\n"))
				result = strFullMessage.split("\r\n\r\n",2);
		}
		return result;
	}
	
}
