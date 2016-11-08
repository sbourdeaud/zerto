##Function Definitions
#Get a site identifier by invoking Zerto APIs, given a Zerto API session and a site name:
function getSiteIdentifierByName ($sessionHeader, $siteName){
  $url = $BASEURL + "virtualizationsites"
  $response = Invoke-RestMethod -Uri $url -Headers $zertoSessionHeader -ContentType "application/xml"
  ForEach ($site in $response.ArrayOfVirtualizationSiteApi.VirtualizationSiteApi) {
    if ($site.VirtualizationSiteName -eq $siteName){
      return $site.SiteIdentifier
    }
  }
}

#Get a storage identifier by invoking Zerto APIs, given a Zerto Virtual Replication API session and a storage name:
function getDatastoreIdentifierByName ($sessionHeader, $siteIdentfier, $datastoreName){
  $url = $BASEURL + "virtualizationsites/"+$siteIdentfier + "/datastores"
  $response = Invoke-RestMethod -Uri $url -Headers $zertoSessionHeader -ContentType "application/xml"
  ForEach ($datastore in $response.ArrayOfDatastoreNativeApi.DatastoreNativeApi) {
    if ($datastore.DatastoreName -eq $datastoreName){
      return $datastore.DatastoreIdentifier
    }
  }
}

#Get unprotected VM identifiers by invoking Zerto APIs, given a Zerto API session, a site identifier, and a list of VMs to add to the VPG:
function getUnprotectedVMsIdentifiers($sessionHeader, $siteIdentfier, $VMNames){
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
function getZertoXSession (){
  #Authenticate with Zerto APIs:
  $xZertoSessionURI = "https://" + $strZVMIP + ":"+$strZVMPort+"/v1/session/Add"
  $authInfo = ("{0}:{1}" -f $strZVMUser,$strZVMPw)
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
function buildVMsElement ($VMs) {
$response = "<VmsIdentifiers>"
 
  ForEach ($vm in $VMs) {
    $response+="<string xmlns="+'"http://schemas.microsoft.com/2003/10/Serialization/Arrays"'+">"+$vm+"</string>"
  }
  $response += "</VmsIdentifiers>"
  return $response
}


# Allow the use of self-signed SSL certificates.
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

#Parameters Section
$strZVMIP = "10.4.91.3"
$strZVMPort = "9669"
$strZVMUser = "sbourdeaud"
$strZVMPw = "nutanix/4u"
$sourceVirtualizationSiteName = "c01-vcenter.gso.lab"
$targetVirtualizationSiteName = "c01-vcenter.gso.lab"
$targetDataStoreName = "GSO-MGT-NFS01"
$vpgName = "steph-test01"
#$unProtectedVMsCSVFile = "name of the file that has the names of the VMs to add to the VPG. The file must not have headers, and the VM names must be separated with commas, without spaces between the names. For example, the first row in the file would look like this: vm1,vm2,vm3}"
$BASEURL = "https://" + $strZVMIP + ":"+$strZVMPort+"/v1/" #base URL for all APIs




#Script starts here:
$xZertoSession = getZertoXSession
 
$zertoSessionHeader = @{"x-zerto-session"=$xZertoSession}
 
$sourceSiteIdentifier = getSiteIdentifierByName $zertoSessionHeader $sourceVirtualizationSiteName
 
$targetSiteIdentifier = getSiteIdentifierByName $zertoSessionHeader $targetVirtualizationSiteName
 
$dataStoreIdentifier = getDatastoreIdentifierByName $zertoSessionHeader $targetSiteIdentifier $targetDataStoreName
 
#$unprotectedVMNames = Get-Content $unProtectedVMsCSVFile | %{$_.Split(",")}
$unprotectedVMNames = "steph-test01"
 
$vmsIdentifiers = getUnprotectedVMsIdentifiers $zertoSessionHeader $sourceSiteIdentifier $unprotectedVMNames
 
$vmsIdentifiersElement = buildVMsElement $vmsIdentifiers
#Create the URL and body of the VPGs request:
$createVPGUrl = $BASEURL+"vpgs"

$contentType = "application/json"
$vpgsRequestBody = '{"DataStoreIdentifier": "'+$dataStoreIdentifier+'", "SourceSiteIdentifier": "'+$sourceSiteIdentifier+'", "TargetSiteIdentifier":"'+$targetSiteIdentifier+'", "VmsIdentifiers":["'+$vmsIdentifiers+'"], "VpgName":"'+$vpgName+'"}'

#$contentType = "application/xml"
#$vpgsRequestBody = "<VpgCreateDataApi xmlns="+'"http://schemas.zerto.com/zvm/api"'+">"`
#            +"<DatastoreIdentifier>"+$dataStoreIdentifier +"</DatastoreIdentifier>`
#            <SourceSiteIdentifier>"+$sourceSiteIdentifier+"</SourceSiteIdentifier>`
#            <TargetSiteIdentifier>"+$targetSiteIdentifier+"</TargetSiteIdentifier>"`
#            +$vmsIdentifiersElement+"<VpgName>"+$vpgName+"</VpgName> </VpgCreateDataApi>"

#Invoke the Zerto API:
Invoke-RestMethod -Uri $createVPGUrl -Headers $zertoSessionHeader -Body $vpgsRequestBody -ContentType $contentType -method POST
##End of script