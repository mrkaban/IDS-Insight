# IDS-Insight
Graphical interface to IDS Suricata on Windows

Official website: [https://alekseycheremnykh.ru/](https://alekseycheremnykh.ru/post/ids-insight/)

System requirements
OS: Windows 10/11 (64-bit)
Suricata: Version 6.0.8 or higher
RAM: 4 GB+ (8 GB recommended for large rulesets)
Disk space: 500 MB+ for storing rules and logs

Key features of IDS Insight
Advanced rule management.
Enabling/disabling individual rules or sets of rules.
Importing rules from a file (.rules and experimental archives).
Automatic updating of rule set files from online sources (via link).
Backup configuration (save settings button at the bottom).
Managing online rule sources (adding/removing).
Convenient event monitoring with disabled auto-updates.
Visualization of alerts with color coding by type.
Filtering by event type (alerts, DNS, TLS, all).
Flexible time filter (arbitrary ranges).
"All events" mode for full audit (it may take a very long time to load, and the program stores this setting in the suricata_gui.ini file, which may cause a very long load time the next time).
Saving the latest Event settings (All Events mode, time range, number of events, auto-update).
Search across all event fields (use with auto-update disabled).
Start/stop/restart the service.
Automatic status check.
Configuring the service name via the GUI.
Viewing Suricata logs in real time (experimental).
Integration with WinDivert for traffic blocking (Suricata installer builds without WinDivert cannot block Windows network packets).
Advanced Suricata configuration editor with syntax highlighting.
Validating the configuration before saving it.
Search by configuration file.
Automatic backup of settings (experimental).
Blocking an IP from the event management context menu (a rule is created to block a specific IP).
Managing rule actions (alert/drop/reject) – not all Suricata builds support reject, so it's better not to use it.
View rule details by SID.
Editing rules in an intuitive interface.
Ability to view raw event data.
Checking the integrity of rules at app startup.
Automatically detects issues when the app starts (experimental).
Getting to know the interface
List of Alerts in IDS-Insight

The main page displays events. On this tab, you can filter events by time and filter by type. You can show all events for the entire period and enable auto-updates.

Do not use both display all events and auto-update at the same time, as this can cause a loop of freezes due to a large number of events.

The All Events mode, auto-update, time filter, and the number of displayed events are remembered, so the same settings will be applied the next time the application is launched. If you forget to uncheck the All Events option, the application may take a long time to open. If you forget to uncheck the option and the application does not open at all, you can change these settings in the suricata_gui.ini file.

If you double-click on an event, the event details will be displayed.

Event Details

This is one of the most interesting windows, as it contains an incredible amount of useful information. The main information is the raw data (as it appears in the Suricata log). Interestingly, the Suricata log does not indicate that the package was blocked! Instead, it shows the rule that triggered the event, and the action is only mentioned in the rule itself. I had to use a trick, but the mechanism works (although it is not guaranteed).

You can block the source or destination IP, excluding your own IP.

The event details display information about the rule, and you can immediately disable or open it to view it.

Rule details in Event details

And this is the most convenient thing - you can change the rule right from the event details window! You can change the action! However, keep in mind that the reject action is not supported by all Suricata builds (I recommend studying this topic separately if you really need it).

The next step is to look at managing rules.

Managing Suricata Rules

It's a pretty good rule management interface with everything you need. You can disable and enable individual rules or entire sets of rules. Open the details (the same window as above - Rule Details) and change the action or anything else in the rule.

The most powerful feature of IDS Insight rule management is the ability to add your own links that the program will use to download and install rules!

Managing links to rules

Users can add their own rule sets and install them in Suricata by clicking the Update Rules button in the Rule Management tab.

Managing the Suricata service.

Managing the Suricata Service

Understand that a product like Suricata requires a certain basic set of knowledge, and it is impossible to replace it with even the most sophisticated program. Regardless, this set of knowledge will be necessary for the initial setup of Suricata and the analysis of events and rules.

There is no point in adding all the rules that exist on the Internet and turning them all on. In fact, you need to analyze which rules are aimed at what, and accordingly, if you do not use Oracle BI, then you do not need rules for exploiting vulnerabilities in Oracle BI.

If you are having trouble starting the service, please refer to the instructions at the end of this article.

Managing Suricata Settings

Convenient settings management. With settings backup, settings check and apply. When apply, the service is restarted.

Syntax highlighting.

Paths to your Suricata instance.

By the way, if you import rules, they are automatically added to the settings in the corresponding section.

System requirements
OS: Windows 10/11 (64-bit)

Suricata: Version 6.0.8 or higher

RAM: 4 GB+ (8 GB recommended for large rule sets)

Disk space: 500 MB+ for storing rules and logs

Tips for effective use
Managing rule sources
Add the ETPro, SSLBL, and EmergingThreats sources in the "Source Management" section and update them regularly.

Rapid incident analysis
Double click on the event → "View Rule" for quick analysis of the triggered rule.

Secure editing
Always use "Check Config" before saving changes to suricata. yaml.

Trend Analysis
Use a time filter to identify periodic attacks and anomalies.

Rule sets
Links to public rule sets can be found here.

IP blocking mechanism
When an IP is blocked, a rule is generated:
drop ip 94.156.77.100 any -> any any (msg:"GUI Blocked IP 94.156.77.100"; flow:to_client; sid:1000000; rev:1;)

The special SID range (1000000-1999999) guarantees maximum priority

All blocks are marked with special metadata in the logs:
"flowint": {"gui_blocked_ip": 1, "gui_action_drop": 1}

Configuring custom fields to accurately identify locks in logs

What do you need to know before you start using it?
IDS Suricata requires a certain set of knowledge for initial configuration and subsequent administration, and IDS Insight does not eliminate this requirement. The program only makes life easier for such specialists.
The program is written for itself, and it already achieves its goals, so there is no need to scale it to an enterprise network.
Linux builds are not planned, as this OS already has graphical interfaces for this intrusion detection system.
A graphical interface in the form of a web interface is not planned, as it creates a whole bunch of vulnerabilities that require a team to regularly address.
No remote management is planned – only local management. For such purposes, it is better to use commercial products.
IDS Insight requires IDS Suricata to be installed and configured.
In the program folder, there is a suricata_gui.ini file that specifies the IDS Insight settings. In particular, make sure to change the directories if Suricata is not located in C:\Program Files\Suricata\, otherwise the application may not start.
Installing Suricata on Windows
To block it, you need a version that supports windivert, which means that the installer name must contain windivert.

Download the installer from the official website:
suricata.io/download/
Run the installer and follow the instructions.
Configure the basic configuration:
Open suricata.yaml in a text editor
Specify the network interface (see below for ID information):
af-packet:
 - interface: \Device\NPF_{ВАШ_ID_ИНТЕРФЕЙСА}

Проверьте пути к правилам:
default-rule-path: C:\Program Files\Suricata\rules

rule-files:
 - *.rules
You can find the interface ID using PowerShell:

Get-NetAdapter | ForEach-Object {
 "Имя: $($_.Name)"
 "Описание: $($_.InterfaceDescription)"
 "GUID: {$($_.InterfaceGuid)}"
 "ID: \Device\NPF_{$($_.InterfaceGuid)}"
 "--------------------------------"
}
If you are using windivert, then you need to add the following to your Suricata settings:

windivert:
enabled: true
forward: false
service-name: "WinDivert1" # <- вот это важно!
The entire af-packet block should be commented out, up to the next colon.

The service must be started with the parameters -c "C:\Program Files\Suricata\suricata.yaml" --windivert="true"

Test the launch from the command line:
suricata.exe -c suricata.yaml -i "Your_interface"

Solving Suricata service issues via NSSM
If the standard Suricata service is not working, use NSSM:

Download the utility:
nssm.cc/download
Unpack the archive and copy nssm.exe to the Suricata directory
Create a service using the command line (administrator):
cd "C:\Program Files\Suricata"

nssm install SuricataService

In the Path field: C:\Program Files\Suricata\suricata.exe
In the Arguments field: -c "C:\Program Files\Suricata\suricata.yaml" --windivert="true"
On the Details tab, set the service name to SuricataService
Start the service:
nssm start SuricataService

Recommendations
Problems running IDS Insight
If IDS Insight does not start, you should check the settings in the suricata_gui.ini file, such as the path to Suricata (suricata_path, rules_dir, eve_log, and backup_dir).

The application is developed using Python 3.12, so operating systems below Windows 10 are not supported.

Long launch
If the application takes a very long time to start, check the events_limit and show_all_events parameters in the suricata_gui.ini file. The events_limit parameter indicates the number of events that are loaded when the application is opened. The show_all_events parameter with a value of False means that the show all events checkbox is disabled, and if the value is True, then the show all events checkbox is enabled. You should try to uncheck the show all events checkbox, and if it is not enabled, then reduce the default number of displayed events. The time filter is also remembered.

Do not use All Events and Auto Update at the same time, as this can cause an infinite loop of freezes when there are many events.

Event Analysis
It is impossible to provide the basics of information security even within a series of articles, but it is possible to share some simplifications.

Many very old rules for very old vulnerabilities in very old products trigger false actions that have nothing to do with these products and you have never had these products in the first place. It's no coincidence that these rules are disabled by default in the initial sets, and only some domestic commercial firewalls have them enabled by default.

The rules should be analyzed at least by the vulnerability identifier and try to understand how applicable it is for you. If you do not have such a product, then it is better to disable this rule. Rules for older versions of the product that you have are on the contrary needed - some vulnerabilities are repeated after many versions, and it will be possible to track attempts to attack this product. In other words, it is better to immediately sort out the rules for yourself.

You can analyze IP addresses using reputation services such as AbuseIPDB, but in the case of a targeted attack, the IP address is likely to be clean. These services can help identify legitimate activities, such as when you launch Yandex Browser and there is a trigger, you can look at the IP address and see that it is a Yandex server through which their products receive updates.
