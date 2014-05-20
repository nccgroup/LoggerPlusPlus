BurpSuiteLoggerPlusPlus
=======================
Sometimes it is necessary to log all the requests and responses of a specific tool in Burp Suite. Logger++ can log activities of all the tools in Burp Suite to show them in a sortable table. It also has an ability to save this data in CSV format.

Released as open source by NCC Group Plc - http://www.nccgroup.com/

Developed by Soroush Dalili, soroush dot dalili at nccgroup dot com

http://www.github.com/nccgroup/BurpSuiteLoggerPlusPlus

Released under AGPL see LICENSE for more information


<b>Using the application:</b>

Step 0- (Downloading) Download ["burplogger++.jar"](burplogger++.jar) file and ["libs"](libs/) directory.

Step 1- (Adding Libraries) Now under "Extender" tab, click on the "Options" tab; in "Java Environment" section, click on "Select folder ..." button and select the "libs" folder that contains "commons-lang3-3.3.2.jar". This library has been used to convert data to CSV format.

Step 2- (Adding Extension) In Burp Suite, click on the "Extender" tab, then click on "Add" button and select "burplogger++.jar" file.

Step 3- (Testing Extension) Now you should be able to see "Logger++" tab in burp suite. If it cannot log anything, check your Burp Suite extension settings. If the save buttons are disabled, make sure that the requested library has been loaded successfully; Unload and then reload the extension and try again. If you have found an issue, please report it as an issue here.

<b>Features:</b>

- Works with the latest version of Burp Suite (tested on 1.6)
- Logs all the tools that are sending requests and receiving responses
- Ability to log from a specific tool
- Ability to save the results in CSV format

<b>Current Limitations:</b>

- Cannot log the requests that do not have any responses.
- Cannot log the requests' time.
- Cannot calculate the delay between a request and its response. 

<b>Reporting bugs:</b>

If you have found an issue, please report it as an issue here.

<b>Tested on:</b>

This extension has been tested on Burp Suite Pro v1.6 with Java v7ux.
If you want to use Java v6, you need to download the source code and compile it yourself. I have used eclipse with Apache Ant  (to create JAR automatically) and Window Builder (to design the UI) modules to build this originally.

<b>Latest version:</b>
Please review the ["CHANGELOG"](CHANGELOG)


<b>Some Screenshots:</b>

![Options Tab](http://i.imgur.com/PWVAoTd.png)
![View Logs Tab (1)](http://i.imgur.com/crt69B5.png)
![View Logs Tab (2)](http://i.imgur.com/V7WWdmg.png)
![In Action](http://i.imgur.com/4FCjEsP.png)
