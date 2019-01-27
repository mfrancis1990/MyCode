# ##############################################################################################################################
#  Module Name: PowervRLCM.psm1                                                           									   
#  Author: Professional Services Engineering                                                                       			   
#  Date: 13th February 2018                                                                                   				   
#  Description: PowerShell module that enables the use of the vRLCM API via PowerShell cmdlets								   
#  Version: 0.0.1                                                                                             		   
# ##############################################################################################################################
import-module ./PSECOMMONPS.psm1


function ConnectVRLCM{
<#
		.SYNOPSIS
			Function to authenticate to a vRLCM Server
		.PARAMETER server
			The url against which the request will be performed. This will be passed to the cmdlet by the originating
            request and does not need any user modification.
        .PARAMETER username
			The url against which the request will be performed. This will be passed to the cmdlet by the originating
            request and does not need any user modification.
        .PARAMETER password
			The url against which the request will be performed. This will be passed to the cmdlet by the originating
            request and does not need any user modification.
        # Returns False if authentication failed or a token if authentication succeeded
		
	#>
    Param (
	    [parameter(Mandatory=$true)][string]$server,
        [parameter(Mandatory=$true)][string]$username,
        [parameter(Mandatory=$true)][securestring]$password
	)
	Process {
        $pwopen = (New-Object PSCredential "user",$password).GetNetworkCredential().Password
        $creds = @"
        {"username":$username,
        "password":$pwopen
    }
"@
        
        
        
        # Login and authenticate to the vRLCM Server returning a token
        $response = Invoke-RestMethod -Uri "https://$server/lcm/api/v1/login" -Method Post -Body $creds -ContentType "application/json" -SkipCertificateCheck

    
        
        
        if($response.token){
        
            write-host "Authenticated successfully to vRealize LifeCycle Manager"
            return $response
        
        
        
        }else{
            write-host "Authentication failed to vRealize Lifecycle Manager"
            return $false
        }

    }
}


function get-inputsvrlcmproductupgrade{
    
        $vRLCMuser = Read-host "vRLCMusername"
        if(!$vRLCMuser){
            do{
                $vRLCMuser= Read-host "You didn't provide a vRLCM username, what is the vRLCM Username "
                
            }until($vRLCMuser)
        }
        $pw = Read-host "vRLCMpassword" -AsSecureString
        $pwopen = (New-Object PSCredential "user",$pw).GetNetworkCredential().Password
        if(!$pwopen){
        do{
            $pw= Read-host "What is the password for the vRLCM User " -AsSecureString
            $pwopen = (New-Object PSCredential "user",$pw).GetNetworkCredential().Password
        }until($pwopen)
        }
        $vrlcmserver = Read-host "What is the IP address or FQDN of the vRLCM Server"
        if(!$vrlcmserver){
        do{
            $vrlcmserver = Read-host "What is the IP address or FQDN of the vRLCM Server"
            
        }until($vrlcmserver)
        }
        $productType = Read-host "What is the vRLCM code name for the Product for example vrops"
        if(!$productType){
        do{
            $productType = Read-host "What is the vRLCM code name for the Product for example vrops"
            
        }until($productType)
        }
        $productversion = Read-host "What is the vRLCM string that represents the product version"
        if(!$productversion){
        do{
            $productversion = Read-host "What is the vRLCM string that represents the product version"
            
        }until($productversion)
        }
        
        $repository = Read-host "What is the full path on the vRLCM Server to the upgrade; for example - /data/productlinks/vrops/6.7.0/upgrade/vRealize_Operations_Manager-VA-OS-6.7.0.8183616.pak,/data/productlinks/vrops/6.7.0/upgrade/vRealize_Operations_Manager-VA-6.7.0.8183616.pak"
        if(!$repository){
        do{
            $repository = Read-host "What is the full path on the vRLCM Server to the upgrade; for example - /data/productlinks/vrops/6.7.0/upgrade/vRealize_Operations_Manager-VA-OS-6.7.0.8183616.pak,/data/productlinks/vrops/6.7.0/upgrade/vRealize_Operations_Manager-VA-6.7.0.8183616.pak"
            
        }until($repository)
        }
        $environmentid = Read-host "What is the vRLCM string that represents the vRLCM Environment ID, for example 5b8b29dde313267556e0ab009aa2a"
        if(!$environmentid){
        do{
            $environmentid = Read-host "What is the vRLCM string that represents the vRLCM Environment ID, for example 5b8b29dde313267556e0ab009aa2a"
            
        }until($environmentid)
        }

    
    [hashtable]$Return=@{}
    $Return.username = $vRLCMuser
    $Return.pw = $pw
    $Return.server = $vrlcmserver
    $Return.productType = $productType
    $Return.repository = $repository
    $Return.productversion = $productversion
    $Return.environmentid = $environmentid
    
    $error.clear()
    return $Return
}




function upgrade-product{
<#
		.SYNOPSIS
			Function to create a new vRLCM Environment
		.PARAMETER server
			The url against which the request will be performed. This will be passed to the cmdlet by the originating
            request and does not need any user modification.
        .PARAMETER token
			The vRLCM Autehnticated token returned from the ConnectVRLCM function.
        .PARAMETER productType
            The vRLCM product code for a vRealize Suite Product. For example - "vrops"
        .PARAMETER environmentId
            The vRLCM environment to be affected by this upgrade request. For example - "5b8b29dde313267556e0ab009aa2a"
        .PARAMETER repositoryURL
            The full path on the vRLCM server for the upgrade. For example - "/data/productlinks/vrops/6.7.0/upgrade/vRealize_Operations_Manager-VA-OS-6.7.0.8183616.pak,/data/productlinks/vrops/6.7.0/upgrade/vRealize_Operations_Manager-VA-6.7.0.8183616.pak"
        .PARAMETER productVersion
            The desired product version, this should be the vRLCM defined string for a given product version. For example "6.7.0"
        
		
	#>
    Param (
	    [parameter(Mandatory=$true)][string]$server,
        [parameter(Mandatory=$true)][string]$token,
        [parameter(Mandatory=$true)][string]$productType,
        [parameter(Mandatory=$true)][string]$environmentId,
        [parameter(Mandatory=$true)][string]$repositoryURL,
        [parameter(Mandatory=$true)][string]$productVersion
	)
	Process {

    $header = @{'x-xenon-auth-token'=$token}
   
    $JSON = @"
    {
        "environmentId": "$environmentId",
        "productType": "$productType",
        "productVersion": "$productVersion"
    }
"@
   try{
   #first we need to make a POST request to get the Request for an upgrade in place in vRLCM - this should return a RequestID
   $requestid = Invoke-RestMethod -Uri "https://$server/lcm/api/v1/action/upgrade/product" -Method Post -Body $JSON -ContentType "application/json" -SkipCertificateCheck -Headers $header
   if($requestid){
    $JSON = @"
    {
            "environmentId": "$environmentId",
            "productType": "$productType",
            "repositoryType": "lcmrepository",
            "repositoryUrl": "$repositoryURL",
            "productVersion": "$productVersion",
            "requestId": "$requestid",
            "preValidate": "false",
            "requestState": "SUBMITTED"
          
    }
"@
       $response = Invoke-RestMethod -Uri "https://$server/lcm/api/v1/action/upgrade/product" -Method Patch -Body $JSON -ContentType "application/json" -SkipCertificateCheck -Headers $header
       write-host "Invoked REST API call to vRealize Lifecycle Manager to upgrade product"
       return $response
   }else{
       write-host "The request for Upgrade Failed to return a RequestID, please review the parameters"
   }
   }catch{
    write-host "Invoked REST API call to vRealize Lifecycle Manager to upgrade product - FAILED - likely malformed JSON content" -ForegroundColor Red
    $response = ""
    return $response
   }
    }



}

function new-environment{
<#
		.SYNOPSIS
			Function to create a new vRLCM Environment
		.PARAMETER server
			The url against which the request will be performed. This will be passed to the cmdlet by the originating
            request and does not need any user modification.
        .PARAMETER token
			The vRLCM Autehnticated token returned from the ConnectVRLCM function.
        .PARAMETER JSON
			The JSON content string that defines the environment that VRLCM should create.
        # Returns a request ID if the request is successful
		
	#>
    Param (
	    [parameter(Mandatory=$true)][string]$server,
        [parameter(Mandatory=$true)][string]$token,
        [parameter(Mandatory=$true)][string]$JSONobj
	)
	Process {

    $header = @{'x-xenon-auth-token'=$token}
   
    $JSON = @"
    $JSONobj
"@
   try{
   $response = Invoke-RestMethod -Uri "https://$server/lcm/api/v1/action/create/environment?prevalidate=false" -Method Post -Body $JSON -ContentType "application/json" -SkipCertificateCheck -Headers $header
    write-host "Invoked REST API call to vRealize Lifecycle Manager to create environment"
   
    return $response
   }catch{
    write-host "Invoked REST API call to vRealize Lifecycle Manager to create environment - FAILED - likely malformed JSON content" -ForegroundColor Red
    $response = ""
    return $response
   }
    }

}

function get-requestongoing{
<#
		.SYNOPSIS
			Returns to console a continual update of the status of a request until the request succeeds or fails
		.PARAMETER server
			The url against which the request will be performed. This will be passed to the cmdlet by the originating
            request and does not need any user modification.
        .PARAMETER token
			The vRLCM Autehnticated token returned from the ConnectVRLCM function.
        .PARAMETER requestid
			The vRLCM requestid from a new-environment request.
        
        # Returns the outcome of a request
		
	#>
    Param (
	    [parameter(Mandatory=$true)][string]$server,
        [parameter(Mandatory=$true)][string]$token,
        [parameter(Mandatory=$true)][string]$requestid
	)
	Process {
        $header = @{'x-xenon-auth-token'=$token}
        $testresponse = Invoke-RestMethod -Uri "https://$server/lcm/api/v1/request/status/$requestid" -Method GET -ContentType "application/json" -SkipCertificateCheck -Headers $header
        $i = 1
        Write-Host
        Write-Host
        Do{
            
            $message = @"
Status of request is $($testresponse.status) - $($testresponse.state)
"@
            write-outprogress -message $message -iteration $i
            $i = $i + 1
           sleep 2
           $testresponse = Invoke-RestMethod -Uri "https://$server/lcm/api/v1/request/status/$requestid" -Method GET -ContentType "application/json" -SkipCertificateCheck -Headers $header
         }while(($testresponse.status -ne "FAILED")-and($testresponse.status -ne "COMPLETED"))
          write-host
         return $testresponse

    }
}

function get-request{
    <#
            .SYNOPSIS
                Returns to console a continual update of the status of a request until the request succeeds or fails
            .PARAMETER server
                The url against which the request will be performed. This will be passed to the cmdlet by the originating
                request and does not need any user modification.
            .PARAMETER token
			    The vRLCM Autehnticated token returned from the ConnectVRLCM function.
            .PARAMETER requestid
                The JSON content string that defines the environment that VRLCM should create.
            # Returns the outcome of a request
            
        #>
        Param (
            [parameter(Mandatory=$true)][string]$server,
            [parameter(Mandatory=$true)][string]$token,
            [parameter(Mandatory=$true)][string]$requestid
        )
        Process {
            $testresponse = Invoke-RestMethod -Uri "https://$server/lcm/api/v1/request/status/$requestid" -Method GET -ContentType "application/json" -SkipCertificateCheck -Headers $header
            return $testresponse
    
        }
    }


function get-rawrequestdata{
<#
		.SYNOPSIS
			Returns to console a continual update of the status of a request until the request succeeds or fails
		.PARAMETER server
			The url against which the request will be performed. This will be passed to the cmdlet by the originating
            request and does not need any user modification.
        .PARAMETER token
			The vRLCM Autehnticated token returned from the ConnectVRLCM function.
        .PARAMETER requestid
			The JSON content string that defines the environment that VRLCM should create.
        # Returns a request ID if the request is successful
		
	#>
    Param (
	    [parameter(Mandatory=$true)][string]$server,
        [parameter(Mandatory=$true)][string]$token,
        [parameter(Mandatory=$true)][string]$requestid
	)
	Process {

  
    $header = @{'x-xenon-auth-token'=$token}
    
    
    
    $response = Invoke-RestMethod -Uri "https://$server/lcm/api/request/$requestid" -Method Get -ContentType "application/json" -SkipCertificateCheck -Headers $header
    write-host "Invoked REST API call to vRealize Lifecycle Manager"
    return $response
    
    }




}
function monitor-vrlcmrequest{
   <#
    .SYNOPSIS
           Function that queries vRLCM for the status of a request and then pending the status asks the user to resolve before testing status again
		.PARAMETER requestid
			The request ID that was returned from the vRLCM request.
        .PARAMETER token
            The vRLCM Autehnticated token returned from the ConnectVRLCM function.
        .PARAMETER vrlcmserver
			The vRLCM server FQDN or IP Address.
        
        # Returns a final status of the VRLCM Request
		
	#>
    Param (
	    [parameter(Mandatory=$true)][string]$requestid,
        [parameter(Mandatory=$true)][string]$token,
        [parameter(mandatory=$true)][string]$vrlcmserver
	)
	Process {
        $testresponse = get-requestongoing -server $vrlcmserver -token $token -requestid $requestid
        write-host "Result of request ID $requestid is $($testresponse.status)"
        if($testresponse.status -eq "FAILED"){
           $decision = Read-host "Would you like us to wait while you investigate and resume the request in vRLCM (Y)es or (N)o"
           if($decision.ToUpper() -eq "Y"){
               $decision=read-host "OK, we will wait, please enter (C) to continue when ready"
               if($decision.ToUpper() -eq "C"){
                $testresponse = get-requestongoing -server $vrlcmserver -token $token -requestid $requestid
                write-host "Response completed with $($testreponse.status)"
               }else{write-host "User chosen abort of process" -ForegroundColor Red;exit}
           }else{write-host "User chosen abort of process" -ForegroundColor Red;exit}
        }
        return $testresponse
    }
}