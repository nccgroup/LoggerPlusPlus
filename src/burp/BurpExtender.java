//
// Burp Suite Logger++
// 
// Released as open source by NCC Group Plc - https://www.nccgroup.trust/
// 
// Developed by Soroush Dalili (@irsdl)
//
// Project link: http://www.github.com/nccgroup/BurpSuiteLoggerPlusPlus
//
// Released under AGPL see LICENSE for more information
//

package burp;

import loggerplusplus.*;


public class BurpExtender implements IBurpExtender
{
	private static LoggerPlusPlus loggerInstance;
	private static IBurpExtenderCallbacks callbacks;

	@Override
	public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
	{
		//Burp Specific
		BurpExtender.callbacks = callbacks;
		loggerInstance = new LoggerPlusPlus(callbacks);
	}

	public static void main(String [] args){
		System.out.println("You have built the Logger++. You shall play with the jar file now!");
		burp.StartBurp.main(args);
	}

	public static LoggerPlusPlus getLoggerInstance() {
		return loggerInstance;
	}

	public static IBurpExtenderCallbacks getCallbacks() {
		return callbacks;
	}
}
