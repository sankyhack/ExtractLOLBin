# ExtractLOLBin

### Purpose & Functioning

This script is written to exctract LOLBin (Living Off The Land Binaries and Scripts) related data from Microsoft **Windows Security Event** (Event ID 4688) & **Sysmon** (https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon#:~:text=System%20Monitor%20(Sysmon)%20is%20a,changes%20to%20file%20creation%20time) event logs  (event ID 1 & 3).

#### Event ID 4688 - Windows Process Creation
#### Event ID 1    - Process Create
#### Event ID 3    - Network connection detected


### Example of Usage:
```
1) extract details from event id 4688 ( windows Security Logs )
.\Extract-LOLBin.ps1 -LogName security -Path_To_LOLBin .\All_LOLBin.txt

2) extrac details from event id 1 & 3 from ( Sysmon logs )
.\Extract-LOLBin.ps1 -LogName sysmon -Path_To_LOLBin .\All_LOLBin.txt

Next two example will fetch details from Offline EVTX log file.
3) extract details from offline Security EVTX file ( Complete EVTX export will work too ) 
.\Extract-LOLBin.ps1 -LogName securityfile -Path_To_LOLBin .\All_LOLBin.txt -Path_To_Logfile .\lolevtx.evtx

4) extract details from offline Sysmon EVTX file ( Complete EVTX export will work too ) 
.\Extract-LOLBin.ps1 -LogName sysmonfile -Path_To_LOLBin .\All_LOLBin.txt -Path_To_Logfile .\lolevtx.evtx

```

### Contact details:

While you can fork and commit to my branch, if you need to contact me I am reachable via Twitter on: @sankyyeram
