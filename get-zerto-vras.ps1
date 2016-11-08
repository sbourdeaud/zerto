<#
.SYNOPSIS
  This script retrieves information about Zerto Virtual Replication Agents (VRA).
.DESCRIPTION
  The script retrieves the following information about VRAs: VRA name, ,ip, count of VPGs, count of protected VMs.
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
.PARAMETER csv
  Output csv file name (default is zerto-protectedvms-report.csv in the current directory).
.EXAMPLE
  Connect to a ZVM of your choice:
  PS> .\get-zerto-vras.ps1 -zvm zvm01.local -username admin -password admin
.LINK
  http://www.nutanix.com/services
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: February 5th 2016
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
	[parameter(mandatory = $false)] [string]$csv
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

#Get a list of VRAs and their status by invoking Zerto APIs, given a Zerto API session:
function ZertogetVRAs ($zertoSessionHeader, $BASEURL){
  $url = $BASEURL + "vras"
  $response = Invoke-RestMethod -Uri $url -Headers $zertoSessionHeader -ContentType "application/json"
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
 02/05/2016 sb   Initial release.
################################################################################
'@
$myvarScriptName = ".\get-zerto-vras.ps1"
 
if ($help) {get-help $myvarScriptName; exit}
if ($History) {$HistoryText; exit}


#let's load the Nutanix cmdlets
#if ((Get-PSSnapin -Name NutanixCmdletsPSSnapin -ErrorAction SilentlyContinue) -eq $null)#is it already there?
#{
#	Add-PSSnapin NutanixCmdletsPSSnapin #no? let's add it
#	if (!$?) #have we been able to add it successfully?
#	{
#		OutputLogData -category "ERROR" -message "Unable to load the Nutanix snapin.  Please make sure the Nutanix Cmdlets are installed on this server."
#		return
#	}
#}

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
	
	if (!$csv) {$csv = "zerto-vras-report.csv"}
	if (!$zvmport) {$zvmport = "9669"}
	if (!$zvm) {$zvm = read-host "Enter the FQDN or IP address of the ZVM"} #prompt for ZVM
	if (!$username) {$username = read-host "Enter the ZVM username"} #prompt for username
	if (!$password) {$password = read-host "Enter the ZVM password"} #prompt for username

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
		OutputLogData -category "INFO" -message "Retrieving list of VRAs from $zvm..."
		$myvarVRAListJSON = ZertogetVRAs $myvarzertoSessionHeader $myvarBASEURL
		
		#process each returned entry/protected vm
		if ($myvarVRAListJSON) {
			OutputLogData -category "INFO" -message "Processing retrieved list of VRAs..."
			foreach ($myvarVRA in $myvarVRAListJSON){  
				
				#populate the hash for this VRA
			    $myvarVRAInfo = @{"IpAddress" = $myvarVRA.IpAddress; `
			                    "NetworkName" = $myvarVRA.NetworkName; `
			                    "ProtectedVms" = $myvarVRA.ProtectedCounters.Vms; `
			                    "Vpgs" = $myvarVRA.ProtectedCounters.Vpgs; `
			                    "VraName" = $myvarVRA.VraName; `
                                "DefaultGateway" = $myvarVRA.VraNetworkDataApi.DefaultGateway; `
                                "SubnetMask" = $myvarVRA.VraNetworkDataApi.SubnetMask; `
                                "VraIPAddress" = $myvarVRA.VraNetworkDataApi.VraIPAddress; `
			                    "VraVersion" = $myvarVRA.VraVersion}
				
				#populate the array for our final report
			    $myvarResults.Add((New-Object PSObject -Property $myvarVRAInfo)) | Out-Null
			}
			
            #displaying results
            $myvarResults | ft -autosize

			#export the results to csv
			OutputLogData -category "INFO" -message "Exporting results to $csv..."
			$myvarResults | export-csv -NoTypeInformation $csv
		}#endif VMListJSON
		else #no protected vms were found
		{
			OutputLogData -category "WARN" -message "Did not find any VRAs on $zvm..."
		}
	}#endif check if valid session
	else #we didn't get a valid session from the ZVM
	{
		OutputLogData -category "ERROR" -message "Could not connect to $zvm..."
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
    Remove-Variable debugme