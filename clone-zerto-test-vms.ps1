<#
.SYNOPSIS
  This is a summary of what the script is.
.DESCRIPTION
  This is a detailed description of what the script does and how it is used.
.PARAMETER help
  Displays a help message (seriously, what did you think this was?)
.PARAMETER history
  Displays a release history for this script (provided the editors were smart enough to document this...)
.PARAMETER log
  Specifies that you want the output messages to be written in a log file as well as on the screen.
.PARAMETER debugme
  Turns off SilentlyContinue on unexpected error messages.
.PARAMETER vcenter
  VMware vCenter server hostname. Default is localhost. You can specify several hostnames by separating entries with commas.
.EXAMPLE
  Connect to a vCenter server of your choice:
  PS> .\template.ps1 -vcenter myvcenter.local
.LINK
  http://www.nutanix.com/services
.NOTES
  Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
  Revision: June 19th 2015
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
    [parameter(mandatory = $false)] [string]$vcenter,
	[parameter(mandatory = $false)] [string]$pool,
    [parameter(mandatory = $false)] [string]$cluster
)

# get rid of annoying error messages
if (!$debugme) {$ErrorActionPreference = "SilentlyContinue"}

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

function Wait-VMPowerState { 
 
<# 
    .SYNOPSIS 
        Changes PowerState of a VMware VM and waits for operation 
to complete. 
 
    .DESCRIPTION 
        Turns a VMware VM on or off and waits for the operation to complete.  Usefull for scripts or instances where a VM needs to be in a given state before the script continues. Returns changed Get-VM output. 
 
    .PARAMETER  VMName 
        The name of a VMware VM.  You must already be connected to a VIServer. 
 
    .PARAMETER  Operation 
        Accepts UP or DOWN as input.  If the VM is already in the  
        requested state the function skips powerstate operations  
        and exits. 
 
    .EXAMPLE 
        C:\PS> Wait-VMPowerState -VMName MyVM -Operation up 
 
    .EXAMPLE 
        C:\PS> $list = get-content .\listofVMs.txt 
        C:\PS> $list | % { Wait-VMPowerState -VMName $_ -Operation down } 
 
    .EXAMPLE 
        C:\PS> $vm = Wait-VMPowerState -VMName MyVM -Operation down 
        C:\PS> $vm | set-vm -MemoryMB 4096 
        C:\PS> Wait-VMPowerState -VMName $vm.Name -Operation up 
         
    .INPUTS 
        System.String,System.String 
 
    .NOTES 
        Requires PowerCLI module.  This function has been tested with  
        PowerShell v2.0, v3.0 CTP and PowerCLI snapin v5.0. 
#> 
 
[CmdletBinding()]   
Param(  
        # The name of a VM 
        [Parameter(Mandatory=$true,   
                   ValueFromPipelineByPropertyName=$true,   
                   Position=0)]   
        $VMName, 
        # The operation (up or down) 
        [Parameter(Mandatory=$true,   
                   ValueFromPipelineByPropertyName=$true,   
                   Position=1)]   
                   [ValidateSet("Up","Down")] 
        $Operation 
    ) 
begin{ 
    $vm = get-vm -Name $vmname 
    } 
process{ 
    switch ($operation) { 
        down { 
                if ($vm.PowerState -eq "PoweredOn") { 
                    OutputLogData -category "INFO" -message "Shutting Down $vmname" 
                    $vm | Stop-VMGuest -Confirm:$false 
                    #Wait for Shutdown to complete 
                    do { 
                       #Wait 5 seconds 
                       Start-Sleep -s 5 
                       #Check the power status 
                       $vm = Get-VM -Name $vmname 
                       $status = $vm.PowerState 
                    }until($status -eq "PoweredOff") 
                } 
                 elseif ($vm.PowerState -eq "PoweredOff") { 
                    OutputLogData -category "INFO" -message "$vmname is powered down" 
                } 
            } 
         up { 
                if ($vm.PowerState -eq "PoweredOff") { 
                    OutputLogData -category "INFO" -message "Starting VM $vmname" 
                    $vm | Start-VM -Confirm:$false 
                    #Wait for startup to complete 
                    do { 
                       #Wait 5 seconds 
                       Start-Sleep -s 5 
                       #Check the power status 
                       $vm = Get-VM -Name $vmname 
                       $status = $vm.PowerState 
                    }until($status -eq "PoweredOn") 
                } 
                 elseif ($vm.PowerState -eq "PoweredOn") { 
                    OutputLogData -category "INFO" -message "$vmname is powered up" 
                } 
            } 
        } 
    } 
end{ 
  
    } 
} 

#########################
##   main processing   ##
#########################

#check if we need to display help and/or history
$HistoryText = @'
 Maintenance Log
 Date       By   Updates (newest updates at the top)
 ---------- ---- ---------------------------------------------------------------
 06/19/2015 sb   Initial release.
################################################################################
'@
$myvarScriptName = ".\clone-zerto-test-vms.ps1"
 
if ($help) {get-help $myvarScriptName; exit}
if ($History) {$HistoryText; exit}



#let's make sure the VIToolkit is being used
if ((Get-PSSnapin VMware.VimAutomation.Core -ErrorAction SilentlyContinue) -eq $null)#is it already there?
{
	Add-PSSnapin VMware.VimAutomation.Core #no? let's add it
	if (!$?) #have we been able to add it successfully?
	{
		OutputLogData -category "ERROR" -message "Unable to load the PowerCLI snapin.  Please make sure PowerCLI is installed on this server."
		return
	}
} 
#Initialize-VIToolkitEnvironment.ps1 | Out-Null

#initialize variables
	#misc variables
	$myvarElapsedTime = [System.Diagnostics.Stopwatch]::StartNew() #used to store script begin timestamp
	$myvarvCenterServers = @() #used to store the list of all the vCenter servers we must connect to
	$myvarOutputLogFile = (Get-Date -UFormat "%Y_%m_%d_%H_%M_")
	$myvarTimeStamp = (Get-Date -UFormat "_%Y_%m_%d_%H_%M")
    $myvarOutputLogFile += "OutputLog.log"
	
	############################################################################
	# command line arguments initialization
	############################################################################	
	#let's initialize parameters if they haven't been specified
	if (!$vcenter) {$vcenter = read-host "Enter vCenter server name or IP address"}#prompt for vcenter server name
	$myvarvCenterServers = $vcenter.Split(",") #make sure we parse the argument in case it contains several entries
	if (!$pool) {$pool = read-host "Enter the target resource pool name"}
    if (!$cluster) {$cluster = read-host "Enter the cluster name"}
	
	################################
	##  foreach vCenter loop      ##
	################################
	foreach ($myvarvCenter in $myvarvCenterServers)	
	{
		OutputLogData -category "INFO" -message "Connecting to vCenter server $myvarvCenter..."
		if (!($myvarvCenterObject = Connect-VIServer $myvarvCenter))#make sure we connect to the vcenter server OK...
		{#make sure we can connect to the vCenter server
			$myvarerror = $error[0].Exception.Message
			OutputLogData -category "ERROR" -message "$myvarerror"
			return
		}
		else #...otherwise show the error message
		{
			OutputLogData -category "INFO" -message "Connected to vCenter server $myvarvCenter."
		}#endelse
		
		if ($myvarvCenterObject)
		{
		
			######################
			#main processing here#
			######################
			
			#get the list of Zerto testing failover VMs
            OutputLogData -category "INFO" -message "Getting the list of VMs to process..."
			$myvarZertoVMList = Get-Cluster $cluster | Get-VM "*testing recovery"
			#shutdown all those Zerto VMs
            OutputLogData -category "INFO" -message "Making sure each VM is powered off..."
			$myvarZertoVMList | %{Wait-VMPowerState -VMName $_.Name -Operation down}
			#clone vms
			foreach ($myvarVM in $myvarZertoVMList)
			{
				$myvarNewVMName = $myvarVM.Name
                $myvarNewVMName = $myvarNewVMName.Trim(" - testing recovery")
				$myvarNewVMName = $myvarNewVMName + "-test-clone" + $myvarTimeStamp
				$myvarDatastore = $myvarVM | Get-Datastore
                OutputLogData -category "INFO" -message "Cloning VM $myvarVM.Name as $myvarNewVMName in datastore $myvarDatastore"
				New-VM -Name $myvarNewVMName -VM $myvarVM.Name -ResourcePool $pool -Datastore $myvarDatastore.Name
			}
			
		}#endif
        OutputLogData -category "INFO" -message "Disconnecting from vCenter server $vcenter..."
		Disconnect-viserver -Confirm:$False #cleanup after ourselves and disconnect from vcenter
	}#end foreach vCenter
	
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
	Remove-Variable vcenter
    Remove-Variable debugme
    Remove-Variable pool
    Remove-Variable cluster