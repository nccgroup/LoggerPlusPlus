Logger++ - Advanced Logging for Burp Suite
=======================
![GitHub Workflow Status](https://img.shields.io/github/workflow/status/nccgroup/LoggerPlusPlus/Java%20CI%20with%20Gradle?style=for-the-badge) ![GitHub watchers](https://img.shields.io/github/watchers/nccgroup/loggerplusplus?label=Watchers&style=for-the-badge) ![GitHub stars](https://img.shields.io/github/stars/nccgroup/loggerplusplus?style=for-the-badge) ![GitHub All Releases](https://img.shields.io/github/downloads/nccgroup/loggerplusplus/total?style=for-the-badge)
![GitHub](https://img.shields.io/github/license/nccgroup/loggerplusplus?style=for-the-badge)

Sometimes it is necessary to log all the requests and responses of a specific tool in Burp Suite. Logger++ can log activities of all the tools in Burp Suite to show them in a sortable table. It also has an ability to save this data in CSV format.

Developed by Corey Arthur  ![Twitter Follow](https://img.shields.io/twitter/follow/CoreyD97?style=social)

Original by Soroush Dalili  ![Twitter Follow](https://img.shields.io/twitter/follow/irsdl?style=social)

Released as open source by NCC Group Plc - https://www.nccgroup.trust/

Released under AGPL see LICENSE for more information

Screenshots
----------------------

<b>Log Filters</b>

![Log Filters](images/filters.png)

<b>Row Highlights</b>

![Row Highlights](images/colorfilters.png)

<b>Grep Search</b>

![Grep Panel](images/grep.png)


Usage
----
You can use this extension without using the BApp store. In order to install the latest version of this extension from the GitHub repository, follow these steps:

Step 1. Download the [latest release jar](https://github.com/nccgroup/LoggerPlusPlus/releases/latest) .

Step 2. In Burp Suite, click on the "Extender" tab, then in the "Extensions" tab click on the "Add" button and select the downloaded "loggerplusplus.jar" file.

Step 3. You should now be able to see the "Logger++" tab in Burp Suite. If it cannot log anything, check your Burp Suite extension settings. If the save buttons are disabled, make sure that the requested libraries have been loaded successfully; Unload and then reload the extension and try again. If you have found an issue, please report it in the GitHub project.

Step 4. You can configure this extension by using its "option" tab and by right click on the columns' headers.


<b>Features:</b>

- Works with the latest version of Burp Suite (tested on 1.7.27)
- Logs all the tools that are sending requests and receiving responses
- Ability to log from a specific tool
- Ability to save the results in CSV format
- Ability to show results of custom regular expressions in request/response
- User can customise the column headers
- Advanced Filters can be created to display only requests matching a specific string or regex pattern.
- Row highlighting can be added using advanced filters to make interesting requests more visible.
- Grep through logs.
- Live requests and responses.
- Multiple view options.
- Pop out view panel.
- Multithreaded.

<b>Current Limitations:</b>

- Cannot log the requests' actual time unless originating from proxy tool.
- Cannot calculate the actual delay between a request and its response unless originating from proxy tool.

<b>Reporting bugs:</b>

If you have found an issue, please report it in the GitHub project.

<b>Latest version:</b>

Please review the ["CHANGELOG"](CHANGELOG)
