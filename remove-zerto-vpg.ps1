<#
.SYNOPSIS
  This script removes Zerto VPGs bqsed on the specified status qnd substatus.
.DESCRIPTION
  The script retrieves all VPGs from the specified ZVM, then filters VPGs on specified status and substatus and invokes the delete REST method on them. Status and SubStatus are translated into human readable text as documented in "http://s3.amazonaws.com/zertodownload_docs/Latest/Zerto%20Virtual%20Replication%20REST%20APIs%20Online%20Help/index.html#page/Zerto_Virtual_Replication_REST_APIs%2FStatusAPIs.4.11.html%23"
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER log
  Specifies that you want the output messages to be written in a log file as well as on the screen.
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER zvm
  ZVM fully qualified domain name or IP address.
.PARAMETER zvmport
  TCP port number used to connect to the ZVM (default if not specified is 9669).
.PARAMETER username
  Username used to connect to the ZVM.
.PARAMETER password
  Password used to connect to the ZVM.
.PARAMETER status
  Text status the VPGs should be in.  See "http://s3.amazonaws.com/zertodownload_docs/Latest/Zerto%20Virtual%20Replication%20REST%20APIs%20Online%20Help/index.html#page/Zerto_Virtual_Replication_REST_APIs%2FStatusAPIs.4.11.html%23" for valid entries.
.PARAMETER substatus
  Text substatus the VPGs should be in.  See "http://s3.amazonaws.com/zertodownload_docs/Latest/Zerto%20Virtual%20Replication%20REST%20APIs%20Online%20Help/index.html#page/Zerto_Virtual_Replication_REST_APIs%2FStatusAPIs.4.11.html%23" for valid entries.
.EXAMPLE
  Delete all VPGs which have a NotMeetingSLA status and a NeedsConfiguration sub-status:
  PS> .\remove-zerto-vpg.ps1 -zvm zvm01.local -username admin -password admin -status NotMeetingSLA -substatus NeedsConfiguration
.LINK
  http://www.nutanix.com/services
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: June 2nd 2016
#>

######################################
##   parameters and initial setup   ##
######################################
#let's start with some command line parsing
Param
(
    #[parameter(valuefrompipeline = $true, mandatory = $true)] [PSObject]$myParam1,
    [parameter(mandatory = $false)] [switch]$help,
    [parameter(mandatory = $false)] [switch]$history,
    [parameter(mandatory = $false)] [switch]$log,
    [parameter(mandatory = $false)] [switch]$debugme,
    [parameter(mandatory = $false)] [string]$zvm,
	[parameter(mandatory = $false)] [string]$zvmport,
	[parameter(mandatory = $false)] [string]$username,
	[parameter(mandatory = $false)] [string]$password,
	[parameter(mandatory = $false)] [string]$status,
    [parameter(mandatory = $false)] [string]$substatus
)

# get rid of annoying error messages
if (!$debugme) {$ErrorActionPreference = "SilentlyContinue"}

# Allow the use of self-signed SSL certificates.
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

########################
##   main functions   ##
########################

#this function is used to output log data
Function OutputLogData 
{
	#input: log category, log message
	#output: text to standard output
<#
.SYNOPSIS
  Outputs messages to the screen and/or log file.
.DESCRIPTION
  This function is used to produce screen and log output which is categorized, time stamped and color coded.
.NOTES
  Author: Stephane Bourdeaud
.PARAMETER myCategory
  This the category of message being outputed. If you want color coding, use either "INFO", "WARNING", "ERROR" or "SUM".
.PARAMETER myMessage
  This is the actual message you want to display.
.EXAMPLE
  PS> OutputLogData -mycategory "ERROR" -mymessage "You must specify a cluster name!"
#>
	param
	(
		[string] $category,
		[string] $message
	)

    begin
    {
	    $myvarDate = get-date
	    $myvarFgColor = "Gray"
	    switch ($category)
	    {
		    "INFO" {$myvarFgColor = "Green"}
		    "WARNING" {$myvarFgColor = "Yellow"}
		    "ERROR" {$myvarFgColor = "Red"}
		    "SUM" {$myvarFgColor = "Magenta"}
	    }
    }

    process
    {
	    Write-Host -ForegroundColor $myvarFgColor "$myvarDate [$category] $message"
	    if ($log) {Write-Output "$myvarDate [$category] $message" >>$myvarOutputLogFile}
    }

    end
    {
        Remove-variable category
        Remove-variable message
        Remove-variable myvarDate
        Remove-variable myvarFgColor
    }
}#end function OutputLogData

##Function Definitions
#Get a site identifier by invoking Zerto APIs, given a Zerto API session and a site name:
function ZertogetSiteIdentifierByName ($zertoSessionHeader, $siteName, $BASEURL){
  $url = $BASEURL + "virtualizationsites"
  $response = Invoke-RestMethod -Uri $url -Headers $zertoSessionHeader -ContentType "application/xml"
  ForEach ($site in $response.ArrayOfVirtualizationSiteApi.VirtualizationSiteApi) {
    if ($site.VirtualizationSiteName -eq $siteName){
      return $site.SiteIdentifier
    }
  }
}

#Get a storage identifier by invoking Zerto APIs, given a Zerto Virtual Replication API session and a storage name:
function ZertogetDatastoreIdentifierByName ($zertoSessionHeader, $siteIdentfier, $datastoreName, $BASEURL){
  $url = $BASEURL + "virtualizationsites/"+$siteIdentfier + "/datastores"
  $response = Invoke-RestMethod -Uri $url -Headers $zertoSessionHeader -ContentType "application/xml"
  ForEach ($datastore in $response.ArrayOfDatastoreNativeApi.DatastoreNativeApi) {
    if ($datastore.DatastoreName -eq $datastoreName){
      return $datastore.DatastoreIdentifier
    }
  }
}

#Get unprotected VM identifiers by invoking Zerto APIs, given a Zerto API session, a site identifier, and a list of VMs to add to the VPG:
function ZertogetUnprotectedVMsIdentifiers($zertoSessionHeader, $siteIdentfier, $VMNames, $BASEURL){
  $url = $BASEURL + "virtualizationsites/"+$siteIdentfier + "/vms"
  $unprotectedVMsIdentifiers = @()
  $response = Invoke-RestMethod -Uri $url -Headers $zertoSessionHeader -ContentType "application/xml"
  ForEach ($vm in $response.ArrayOfVmNativeApi.VmNativeApi) {
    if ($VMNames.IndexOf($vm.VmName) -gt -1){
      $unprotectedVMsIdentifiers+=($vm.VmIdentifier)
    }
  }
  return $unprotectedVMsIdentifiers
}

#Authenticate with Zerto APIs: create a Zerto API session and return it, to be used in other APIs
function ZertogetZertoXSession ($myvarZvm, $myvarZvmPort, $myvarUsername, $myvarPassword){
  #Authenticate with Zerto APIs:
  $xZertoSessionURI = "https://" + $myvarZvm + ":"+$myvarZvmPort+"/v1/session/Add"
  $authInfo = ("{0}:{1}" -f $myvarUsername,$myvarPassword)
  $authInfo = [System.Text.Encoding]::UTF8.GetBytes($authInfo)
  $authInfo = [System.Convert]::ToBase64String($authInfo)
  $headers = @{Authorization=("Basic {0}" -f $authInfo)}
  $body = '{"AuthenticationMethod": "1"}'
  $contentType = "application/json"
  $xZertoSessionResponse = Invoke-WebRequest -Uri $xZertoSessionURI -Headers $headers -Method POST -Body $body -ContentType $contentType
  #Extract x-zerto-session from the response and add it to the actual API:
  $xZertoSession = $xZertoSessionResponse.headers.get_item("x-zerto-session")
  return $xZertoSession
}

#Build VM elements to be added to the VPGs API, based on a list of VM identifiers
function ZertobuildVMsElement ($VMs, $BASEURL) {
$response = "<VmsIdentifiers>"
 
  ForEach ($vm in $VMs) {
    $response+="<string xmlns="+'"http://schemas.microsoft.com/2003/10/Serialization/Arrays"'+">"+$vm+"</string>"
  }
  $response += "</VmsIdentifiers>"
  return $response
}

#Get a list of VPGs and their status by invoking Zerto APIs, given a Zerto API session:
function ZertogetVPGs ($zertoSessionHeader, $BASEURL){
  $url = $BASEURL + "vpgs"
  $response = Invoke-RestMethod -Uri $url -Headers $zertoSessionHeader -ContentType "application/json"
  return $response
}

#Get a list of protected VMs and their status by invoking Zerto APIs, given a Zerto API session:
function ZertogetVMs ($zertoSessionHeader, $BASEURL){
  $url = $BASEURL + "vms"
  $response = Invoke-RestMethod -Uri $url -Headers $zertoSessionHeader -ContentType "application/json"
  return $response
}

#Delete a VPG:
function ZertoRemoveVpg ($zertoSessionHeader, $BASEURL, $VPGIdentifier){
  $url = $BASEURL + "vpgs" + "/" + $VPGIdentifier
  $response = Invoke-RestMethod -Uri $url -Method Delete -Headers $zertoSessionHeader
  return $response
}

#########################
##   main processing   ##
#########################

#check if we need to display help and/or history
$HistoryText = @'
 Maintenance Log
 Date       By   Updates (newest updates at the top)
 ---------- ---- ---------------------------------------------------------------
 06/02/2016 sb   Initial release.
################################################################################
'@
$myvarScriptName = ".\remove-zerto-vpg.ps1"
 
if ($help) {get-help $myvarScriptName; exit}
if ($History) {$HistoryText; exit}



#initialize variables
	#misc variables
	$myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
	$myvarvCenterServers = @() #used to store the list of all the vCenter servers we must connect to
	$myvarOutputLogFile = (Get-Date -UFormat "%Y_%m_%d_%H_%M_")
	$myvarOutputLogFile += "OutputLog.log"
	
	############################################################################
	# command line arguments initialization
	############################################################################	
	#let's initialize parameters if they haven't been specified
	[System.Collections.ArrayList]$myvarResults = New-Object System.Collections.ArrayList($null) #used for storing all protected vm entries.  This is what will be exported to csv
	
	if (!$csv) {$csv = "zerto-protectedvms-report.csv"}
	if (!$zvmport) {$zvmport = "9669"}
	if (!$zvm) {$zvm = read-host "Enter the FQDN or IP address of the ZVM"} #prompt for ZVM
	if (!$username) {$username = read-host "Enter the ZVM username"} #prompt for username
	if (!$password) {$password = read-host "Enter the ZVM password"} #prompt for username
    if (!$status) {$status = read-host "Enter the desired VPG status"} #prompt for username
    if (!$substatus) {$substatus = read-host "Enter the desired VPG status"} #prompt for username

    $myvarBASEURL = "https://" + $zvm + ":"+$zvmport+"/v1/" #base URL for all APIs
	
	################################
	##  Main execution here       ##
	################################
	
	#Initialize REST API session with the Zerto ZVM
	OutputLogData -category "INFO" -message "Connecting to ZVM $zvm..."
	$myvarxZertoSession = ZertogetZertoXSession $zvm $zvmport $username $password
	$myvarzertoSessionHeader = @{"x-zerto-session"=$myvarxZertoSession}
	
	#check to see if we have a valid session
	if ($myvarxZertoSession) {
	
		#Iterate protected VMs with JSON:
		OutputLogData -category "INFO" -message "Retrieving list of VPGs from $zvm..."
		$myvarVPGListJSON = ZertogetVPGs $myvarzertoSessionHeader $myvarBASEURL
		
		#process each returned entry/protected vm
		if ($myvarVPGListJSON) {
			OutputLogData -category "INFO" -message "Processing retrieved list of VPGs..."
			foreach ($myvarVPG in $myvarVPGListJSON){  
				#Figure out the status message
			    $myvarStatus = switch($myvarVPG.Status) {
			        0 {"Initializing"} #– The VPG is being initialized. This includes when a VPG is created, and during the initial sync between sites.
			        1 {"MeetingSLA"} #– The VPG is meeting the SLA specification.
			        2 {"NotMeetingSLA"} #– The VPG is not meeting the SLA specification for both the journal history and RPO SLA settings.
			        3 {"HistoryNotMeetingSLA"} #– The VPG is not meeting the SLA specification for the journal history.
			        4 {"RpoNotMeetingSLA"} #– The VPG is not meeting the SLA specification for the RPO SLA setting.
			        5 {"FailingOver"} #– The VPG is in a Failover operation.
			        6 {"Moving"} #– The VPG is in a Move operation.
			        7 {"Deleting"} #– The VPG is being deleted.
			        8 {"Recovered"} #– The VPG has been recovered.
			    }
			 	
				#Figure out the sub-status message
			    $myvarSubStatus = switch($myvarVPG.SubStatus) {
			        0 {"None"}
			        1 {"InitialSync"}
			        2 {"Creating"}
			        3 {"VolumeInitialSync"}
			        4 {"Sync"}
			        5 {"RecoveryPossible"}
			        6 {"DeltaSync"}
			        7 {"NeedsConfiguration"}
			        8 {"Error"}
			        9 {"EmptyProtectionGroup"}
			        10 {"DisconnectedFromPeerNoRecoveryPoints"}
			        11 {"FullSync"}
			        12 {"VolumeDeltaSync"}
			        13 {"VolumeFullSync"}
			        14 {"FailingOverCommitting"}
			        15 {"FailingOverBeforeCommit"}
			        16 {"FailingOverRollingBack"}
			        17 {"Promoting"}
			        18 {"MovingCommitting"}
			        19 {"MovingBeforeCommit"}
			        20 {"MovingRollingBack"}
			        21 {"Deleting"}
			        22 {"PendingRemove"}
			        23 {"BitmapSync"}
			        24 {"DisconnectedFromPeer"}
			        25 {"ReplicationPausedUserInitiated"}
			        26 {"ReplicationPausedSystemInitiated"}
			        27 {"RecoveryStorageProfileError"}
			        28 {"Backup"}
			        29 {"RollingBack"}
			        30 {"RecoveryStorageError"}
			        31 {"JournalStorageError"}
			        32 {"VmNotProtectedError"}
			    }
				
				#remove the vpg if it matches the desired status and/or substatus
                if (($status -eq $myvarStatus) -and ($substatus -eq $myvarSubStatus))
                {
                    $myvarVPGName = $myvarVPG.VpgName
                    OutputLogData -category "INFO" -message "Removing VPG $myvarVPGName on $zvm..."
                    $myvarVPGIdentifier = $myvarVPG.VpgIdentifier
                    if (!(ZertoRemoveVpg $myvarzertoSessionHeader $myvarBASEURL $myvarVPGIdentifier))
                    {
                        $myvarerror = $error[0].Exception.Message
                        OutputLogData -category "ERROR" -message "Could not remove VPG $myvarVPGName on $zvm : $myvarerror"
                    }#endif remove VPG
                }#endif status match
			    
			}
			
			
		}#endif VMListJSON
		else #no VPGs were found
		{
			OutputLogData -category "WARN" -message "Did not find any VPGs on $zvm..."
		}
	}#endif check if valid session
	else #we didn't get a valid session from the ZVM
	{
        $myvarerror = $error[0].Exception.Message
		OutputLogData -category "ERROR" -message "Could not connect to $zvm : $myvarerror"
	}
	
#########################
##       cleanup       ##
#########################

	#let's figure out how much time this all took
	OutputLogData -category "SUM" -message "total processing time: $($myvarElapsedTime.Elapsed.ToString())"
	
	#cleanup after ourselves and delete all custom variables
	Remove-Variable myvar*
	Remove-Variable ErrorActionPreference
	Remove-Variable help
    Remove-Variable history
	Remove-Variable log
	Remove-Variable zvm
	Remove-Variable zvmport
	Remove-Variable csv
	Remove-Variable username
	Remove-Variable password
    Remove-Variable status
    Remove-Variable substatus
    Remove-Variable debugme