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