# Threat-Hunting-for-Ransomware-Tactics-Techniques-and-Procedures

****1. Threat Hunting query to detect phishing emails containing links to zip files for download, utilizing MITRE ATT&CK T1566.002 and T1204.002 techniques.****


The following is a Splunk query to detect phishing emails containing links to zip files for download, utilizing MITRE ATT&CK T1566.002 and T1204.002 techniques:

----------------------------------------------------------------------------------------------------------------------------------------------------------
index=<insert_index_name> sourcetype=<insert_sourcetype_name> (file_name="*.zip" OR file_name="*.rar") AND (body="*http*" OR body="*https*") AND (body="*exe*" OR body="*js*") AND (body="*download*" OR body="*click*" OR body="*link*") AND (body="*malicious*" OR body="*virus*" OR body="*ransomware*") | stats count by src_ip, dest_ip, file_name, body
----------------------------------------------------------------------------------------------------------------------------------------------------------
***


****Detection Logic****

This query searches for emails that contain links to zip files for download, and also contain keywords related to malicious activity such as "malicious", "virus", or "ransomware". It also looks for keywords related to the execution of malicious files such as "exe" or "js". The query outputs the source IP, destination IP, file name, and body of the email for further investigation.

::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

****2.Threat Hunting query to detect phishing emails containing links to zip files for download, utilizing MITRE ATT&CK T1566.002 and T1204.002 techniques.****

To detect the execution of a curl command to download a Javascript file, followed by execution of the Qakbot binary via wscript.exe, the following Splunk query can be used:

----------------------------------------------------------------------------------------------------------------------------------------------------------
index=<your_index> sourcetype=<your_sourcetype> (EventCode=1 OR EventCode=5) CommandLine="curl.exe --output %APPDATA%wscript.exe //B %APPDATA%" | stats count by host, EventCode, CommandLine
----------------------------------------------------------------------------------------------------------------------------------------------------------
***

****Detection Logic****

This query searches for events with EventCode 1 or 5 (process creation events) where the command line includes the curl.exe command to download a file to the %APPDATA% directory, followed by the execution of wscript.exe on the downloaded file. The "stats count" command groups the results by host, EventCode, and CommandLine.

This search utilizes the following MITRE ATT&CK techniques:

T1204.002: User Execution: Malicious File
T1059.007: JavaScript
T1219: Remote Access Software
Once this search is created, it can be scheduled to run at regular intervals to detect any occurrences of this activity in your environment.

::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::

****3.To detect the presence of SystemBC remote access tool, including its preconfigured C2 domains and Tor proxy capabilities, as well as scheduled tasks created for persistence, utilizing MITRE ATT&CK T1219 technique.****

The Splunk query to detect the presence of SystemBC remote access tool, including its preconfigured C2 domains and Tor proxy capabilities, as well as scheduled tasks created for persistence, utilizing MITRE ATT&CK T1219 technique can be as follows:

----------------------------------------------------------------------------------------------------------------------------------------------------------
index=main sourcetype="WinEventLog:Security" (EventCode="4688" OR EventCode="7045") (Image="\SystemBC.exe" OR Image="\gemoh.exe") | table _time, EventCode, Account_Name, Image, CommandLine, ComputerName, Subject_User_Name | dedup Image | sort -_time
----------------------------------------------------------------------------------------------------------------------------------------------------------
***

****Detection Logic****

This query searches the main index for events in the Security WinEventLog with EventCode 4688 or 7045, where the Image field contains either "SystemBC.exe" or "gemoh.exe". The query then extracts relevant fields such as time, account name, image, command line, computer name, and subject user name. The dedup command ensures that only unique images are returned, and the sort command sorts the results by descending time.
::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::



