package loggerplusplus;

import burp.IExtensionHelpers;

import javax.swing.*;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
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

	public static void checkForUpdate(boolean showMessages) {
		IExtensionHelpers helper = LoggerPlusPlus.getCallbacks().getHelpers();
		Double currenVersion = LoggerPreferences.version;
		Double latestVersion = 0.0;
		int updateStatus = -1;
		String updateMessage = "";
		try{
			URL changeLogURL = new URL(LoggerPreferences.changeLog);
			byte[] request = helper.buildHttpRequest(changeLogURL);
			byte[] response = LoggerPlusPlus.getCallbacks().makeHttpRequest(changeLogURL.getHost(), 443, true, request);

			if(response != null){
				// splitting the message to retrieve the header and the body
				String strFullMessage = new String(response,"UTF-8");
				if(strFullMessage.contains("\r\n\r\n")){
					String strBody = strFullMessage.split("\r\n\r\n",2)[1];
					Pattern MY_PATTERN = Pattern.compile("(?im)^[\\s]*v[\\s]*(\\d+(\\.*\\d*){0,1})$");

					Matcher m = MY_PATTERN.matcher(strBody);

					if (m.find()) {
						latestVersion = Double.parseDouble(m.group(1));

						if (latestVersion > currenVersion){
							updateStatus = 1; // update is available
						}else if (latestVersion.equals(currenVersion)){
							updateStatus = 0; // no update is available
						}else{
							updateStatus = 2; // Future version!
						}
					}
				}

			}
		}catch(Exception e){
			LoggerPlusPlus.getCallbacks().printError(e.getMessage());
		}

		switch(updateStatus){
			case -1:
				updateMessage = "Check for update failed: Could not get a proper response from "+LoggerPreferences.changeLog;
				LoggerPlusPlus.getCallbacks().printError(updateMessage);
				break;
			case 0:
				updateMessage = "This version is up to date.";
				LoggerPlusPlus.getCallbacks().printOutput(updateMessage);
				break;
			case 1:
				updateMessage = "Version "+latestVersion.toString()+" is available via GitHub. Visit the extension homepage.";
				if(LoggerPlusPlus.getCallbacks().isExtensionBapp()){
					updateMessage += "\nAs you are using BApp Store, you have to remove it first and download the Jar file from the GitHub repository. ";
				}else{
					if(LoggerPlusPlus.getCallbacks().getExtensionFilename() != null){
						int res = MoreHelp.askConfirmMessage("Update Available", "An update is available. Would you like to update now?", new String[]{"Yes", "No"});
						if(res == JOptionPane.OK_OPTION){
							try {
								URL updateUrl = new URL(LoggerPreferences.updateURL);
								InputStream input = updateUrl.openStream();
								Path outputPath = Paths.get(LoggerPlusPlus.getCallbacks().getExtensionFilename());
								Files.copy(input, outputPath, StandardCopyOption.REPLACE_EXISTING);
							} catch (Exception e) {
								MoreHelp.showMessage("Could not update the plugin. Please visit the extension page to update manually.");
								return;
							}
							MoreHelp.showMessage("Update complete. Re-enable the plugin in the extensions tab to continue.");
							LoggerPlusPlus.getCallbacks().unloadExtension();
							return;
						}
					}
				}
				LoggerPlusPlus.getCallbacks().printOutput(updateMessage);
				break;
			case 2:
				updateMessage = "This version is more up to date than the GitHub version! Are you a time traveler? or just a keen ninja? ;)";
				LoggerPlusPlus.getCallbacks().printOutput(updateMessage);
				break;
		}
		if(!showMessages) return;
		MoreHelp.showMessage(updateMessage);
	}
}
