<#

Script is Created to extract LOLBin (Living Off The Land Binaries and Scripts) processes/script from event logs
Script will check for only "event id 4688" and Sysmon "event id 1 & 3"
List of binary and scripts is present in repo with name "All_LOLBin.txt"
LOLBin Project :- https://github.com/LOLBAS-Project/LOLBAS

Example
1) extract details from event id 4688 from Security logs
.\Extract-LOLBin.ps1 -LogName sysmon -Path_To_LOLBin .\All_LOLBin.txt

2) extrac details from event id 1 & 3 from Sysmon logs
.\Extract-LOLBin.ps1 -LogName security -Path_To_LOLBin .\All_LOLBin.txt


To work with Offline log file use below parameter ( -Path_To_Logfile )
 
3) extract details from offline Security EVTX file ( Complete EVTX export will work too ) 
.\Extract-LOLBin.ps1 -LogName securityfile -Path_To_LOLBin .\All_LOLBin.txt -Path_To_Logfile .\lolevtx.evtx

4) extract details from offline Sysmon EVTX file ( Complete EVTX export will work too ) 
.\Extract-LOLBin.ps1 -LogName sysmonfile -Path_To_LOLBin .\All_LOLBin.txt -Path_To_Logfile .\lolevtx.evtx

#>

param(
$LogName,                #Name of Logs from where we need to fetch LOLBin "security" or "sysmon"
$Path_To_LOLBin,
$Path_To_Logfile		 #List of all LOLBIN, file is in repo.
)

$header =  "ComputerName" + "," + "TimeCreated" + ","  + "EventID" + "," + "LOLBin"  + "," + "LOLBinCommandLine"  + "," + "ParentProcess" +  "," + "PPCommandLine" + "," + "DestinationIP" + "," + "DestHostname" + "," + "DestinationPort" + "," + "UserName" | Out-File LOLBinData.csv

function FetchFrom-SecurityLogs
{
$proc_event = Get-WinEvent -filterhashtable @{ LogName="security" ; id=4688 }
foreach($e in $proc_event)
{
 $xml_form = [xml]$e.toxml()
 $lolbin = $xml_form.Event.EventData.ChildNodes.Item(5)."#text"
 #$lolbin
 $eventid = $xml_form.Event.System.EventID

  foreach($line in Get-Content $Path_To_LOLBin)
   {
    
    $flag = $lolbin -match $line

    if ($flag)
    {
     
     $comp_name = $xml_form.Event.System.ChildNodes.Item(12)."#text"
     $time_created = $xml_form.Event.System.TimeCreated.SystemTime
              
     $lolbin = $xml_form.Event.EventData.ChildNodes.Item(5)."#text"
     $lolbin_command_line = $xml_form.Event.EventData.ChildNodes.Item(8)."#text"
     
     $parent_proc_name = $xml_form.Event.EventData.ChildNodes.Item(13)."#text"
     
     $username = $xml_form.Event.EventData.ChildNodes.Item(1)."#text"
     
     $data = $comp_name + "," + $time_created + "," + $eventid + "," + $lolbin + "," + "'$lolbin_command_line'" + "," + $parent_proc_name + "," + "NA" + "," + "NA" + "," + "NA" + "," + "NA" + "," + "$username" 
     $data | Out-File LOLBinData.csv -Append
     Write-Host "$lolbin_command_line"

    }
   }
}
}

function FetchFrom-SysmonLogs
{
$proc_event = Get-WinEvent -filterhashtable @{ LogName="Microsoft-Windows-Sysmon/Operational" ; id=1,3}

foreach($e in $proc_event)
{
 $xml_form = [xml]$e.toxml()
 $lolbin = $xml_form.Event.EventData.ChildNodes.Item(4)."#text"
 $eventid = $xml_form.Event.System.EventID
 
  foreach($line in Get-Content $Path_To_LOLBin)
   {

    $flag = $lolbin -match $line
    
    if ($flag)
    {
     if($eventid -eq 1)
      {
         $comp_name = $xml_form.Event.System.Computer
         $time_created = $xml_form.Event.System.TimeCreated.SystemTime

         $parent_proc = $xml_form.Event.EventData.ChildNodes.Item(20)."#text"
         $parent_proc_command_line = $xml_form.Event.EventData.ChildNodes.Item(21)."#text"

         $lolbin = $xml_form.Event.EventData.ChildNodes.Item(4)."#text"
         $lolbin_command_line = $xml_form.Event.EventData.ChildNodes.Item(10)."#text"
         
         $username = $xml_form.Event.EventData.ChildNodes.Item(12)."#text"

         $data = $comp_name + "," + $time_created + "," + $eventid + "," + $lolbin + "," + "'$lolbin_command_line'" + "," + $parent_proc + "," + "'$parent_proc_command_line'" + "," + "NA" + "," + "NA" + "," + "NA" + "," + $username
         
         $data | Out-File LOLBinData.csv -Append
         Write-Host "$lolbin_command_line"       
       }   
     
      Elseif($eventid -eq 3)
      {    
         $comp_name = $xml_form.Event.System.Computer
         $time_created = $xml_form.Event.System.TimeCreated.SystemTime

         $lolbin = $xml_form.Event.EventData.ChildNodes.Item(4)."#text"
         $lolbin

         $destip = $xml_form.Event.EventData.ChildNodes.Item(14)."#text"
         $destip_hostname = $xml_form.Event.EventData.ChildNodes.Item(15)."#text"
         $destination_port = $xml_form.Event.EventData.ChildNodes.Item(16)."#text"

         $username = $xml_form.Event.EventData.ChildNodes.Item(5)."#text"
             
         $data = $comp_name + "," + $time_created + "," + $eventid + "," + $lolbin + "," + "NA" + "," + "NA" + "," + "NA" + "," + $destip + "," + $destip_hostname + "," + $destination_port + "," + $username
         
         $data | Out-File LOLBinData.csv -Append
         Write-Host "$lolbin"
        }
    } 
  } 
}
}


function ReadFrom-SysmonLogs
{
$proc_event = Get-WinEvent -filterhashtable @{ Path=$Path_To_Logfile ; LogName="Microsoft-Windows-Sysmon/Operational" ; id=1,3}

foreach($e in $proc_event)
{
 $xml_form = [xml]$e.toxml()
 $lolbin = $xml_form.Event.EventData.ChildNodes.Item(4)."#text"
 $eventid = $xml_form.Event.System.EventID
 
  foreach($line in Get-Content $Path_To_LOLBin)
   {

    $flag = $lolbin -match $line
    
    if ($flag)
    {
     if($eventid -eq 1)
      {
         $comp_name = $xml_form.Event.System.Computer
         $time_created = $xml_form.Event.System.TimeCreated.SystemTime

         $parent_proc = $xml_form.Event.EventData.ChildNodes.Item(20)."#text"
         $parent_proc_command_line = $xml_form.Event.EventData.ChildNodes.Item(21)."#text"

         $lolbin = $xml_form.Event.EventData.ChildNodes.Item(4)."#text"
         $lolbin_command_line = $xml_form.Event.EventData.ChildNodes.Item(10)."#text"
         
         $username = $xml_form.Event.EventData.ChildNodes.Item(12)."#text"

         $data = $comp_name + "," + $time_created + "," + $eventid + "," + $lolbin + "," + "'$lolbin_command_line'" + "," + $parent_proc + "," + "'$parent_proc_command_line'" + "," + "NA" + "," + "NA" + "," + "NA" + "," + $username
         
         $data | Out-File LOLBinData.csv -Append
         Write-Host "$lolbin_command_line"       
       }   
     
      Elseif($eventid -eq 3)
      {    
         $comp_name = $xml_form.Event.System.Computer
         $time_created = $xml_form.Event.System.TimeCreated.SystemTime

         $lolbin = $xml_form.Event.EventData.ChildNodes.Item(4)."#text"
         $lolbin

         $destip = $xml_form.Event.EventData.ChildNodes.Item(14)."#text"
         $destip_hostname = $xml_form.Event.EventData.ChildNodes.Item(15)."#text"
         $destination_port = $xml_form.Event.EventData.ChildNodes.Item(16)."#text"

         $username = $xml_form.Event.EventData.ChildNodes.Item(5)."#text"
             
         $data = $comp_name + "," + $time_created + "," + $eventid + "," + $lolbin + "," + "NA" + "," + "NA" + "," + "NA" + "," + $destip + "," + $destip_hostname + "," + $destination_port + "," + $username
         
         $data | Out-File LOLBinData.csv -Append
         Write-Host "$lolbin"
        }
    } 
  } 
}
}

function ReadFrom-SecurityLogs
{
$proc_event = Get-WinEvent -filterhashtable @{ Path=$Path_To_Logfile ; LogName="security" ; id=4688 }
foreach($e in $proc_event)
{
 $xml_form = [xml]$e.toxml()
 $lolbin = $xml_form.Event.EventData.ChildNodes.Item(5)."#text"
 #$lolbin
 $eventid = $xml_form.Event.System.EventID

  foreach($line in Get-Content $Path_To_LOLBin)
   {
    
    $flag = $lolbin -match $line

    if ($flag)
    {
     
     $comp_name = $xml_form.Event.System.ChildNodes.Item(12)."#text"
     $time_created = $xml_form.Event.System.TimeCreated.SystemTime
              
     $lolbin = $xml_form.Event.EventData.ChildNodes.Item(5)."#text"
     $lolbin_command_line = $xml_form.Event.EventData.ChildNodes.Item(8)."#text"
     
     $parent_proc_name = $xml_form.Event.EventData.ChildNodes.Item(13)."#text"
     
     $username = $xml_form.Event.EventData.ChildNodes.Item(1)."#text"
     
     $data = $comp_name + "," + $time_created + "," + $eventid + "," + $lolbin + "," + "'$lolbin_command_line'" + "," + $parent_proc_name + "," + "NA" + "," + "NA" + "," + "NA" + "," + "NA" + "," + "$username" 
     $data | Out-File LOLBinData.csv -Append
     Write-Host "$lolbin_command_line"

    }
   }
}
}

if ($LogName -eq "security")
{
  FetchFrom-SecurityLogs
}

if ($LogName -eq "sysmon")
{
  FetchFrom-SysmonLogs
}

if ($LogName -eq "SysmonFile")
{
  ReadFrom-SysmonLogs
}
if ($LogName -eq "SecurityFile")
{
  ReadFrom-SysmonLogs
}
