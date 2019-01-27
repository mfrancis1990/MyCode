$WarningPreference ="silentlycontinue"

Function Get-WebServerSSL {  
# Function original location: http://en-us.sysadmins.lv/Lists/Posts/Post.aspx?List=332991f0-bfed-4143-9eea-f521167d287c&ID=60  
[CmdletBinding()]  
    param(  
        [Parameter(Mandatory = $true, ValueFromPipeline = $true, Position = 0)]  
        [string]$URL,  
        [Parameter(Position = 1)]  
        [ValidateRange(1,65535)]  
        [int]$Port = 443,  
        [Parameter(Position = 2)]  
        [Net.WebProxy]$Proxy,  
        [Parameter(Position = 3)]  
        [int]$Timeout = 15000,  
        [switch]$UseUserContext  
    )  
Add-Type @"  
using System;  
using System.Net;  
using System.Security.Cryptography.X509Certificates;  
namespace PKI {  
    namespace Web {  
        public class WebSSL {  
            public Uri OriginalURi;  
            public Uri ReturnedURi;  
            public X509Certificate2 Certificate;  
            //public X500DistinguishedName Issuer;  
            //public X500DistinguishedName Subject;  
            public string Issuer;  
            public string Subject;  
            public string[] SubjectAlternativeNames;  
            public bool CertificateIsValid;  
            //public X509ChainStatus[] ErrorInformation;  
            public string[] ErrorInformation;  
            public HttpWebResponse Response;  
        }  
    }  
}  
"@  
    $ConnectString = "https://$url`:$port"  
    $WebRequest = [Net.WebRequest]::Create($ConnectString)  
    $WebRequest.Proxy = $Proxy  
    $WebRequest.Credentials = $null  
    $WebRequest.Timeout = $Timeout  
    $WebRequest.AllowAutoRedirect = $true  
    [Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}  
    try {$Response = $WebRequest.GetResponse()}  
    catch {}  
    if ($WebRequest.ServicePoint.Certificate -ne $null) {  
        $Cert = [Security.Cryptography.X509Certificates.X509Certificate2]$WebRequest.ServicePoint.Certificate.Handle 
        try {$SAN = ($Cert.Extensions | Where-Object {$_.Oid.Value -eq "2.5.29.17"}).Format(0) -split ", "}  
        catch {$SAN = $null}  
        $chain = New-Object Security.Cryptography.X509Certificates.X509Chain -ArgumentList (!$UseUserContext)  
        [void]$chain.ChainPolicy.ApplicationPolicy.Add("1.3.6.1.5.5.7.3.1")  
        $Status = $chain.Build($Cert)  
        New-Object PKI.Web.WebSSL -Property @{  
            OriginalUri = $ConnectString;  
            ReturnedUri = $Response.ResponseUri;  
            Certificate = $WebRequest.ServicePoint.Certificate;  
            Issuer = $WebRequest.ServicePoint.Certificate.Issuer;  
            Subject = $WebRequest.ServicePoint.Certificate.Subject;  
            SubjectAlternativeNames = $SAN;  
            CertificateIsValid = $Status;  
            Response = $Response;  
            ErrorInformation = $chain.ChainStatus | ForEach-Object {$_.Status}  
        }  
        $chain.Reset()  
        #[Net.ServicePointManager]::ServerCertificateValidationCallback = $null  
    } else {  
        Write-Error $Error[0]  
    }  
}  
  



function get-filenameonly{
    <# 
        .SYNOPSIS
        Function removes any path information from a string that potentially includes not only the filename but the full path to the filename
        
        Outputs: The function just the filename with any path stripped.
    #>
    Param ([string]$filename)
    
       if(($filename -match "/")){
           write-host "You have provided a filename with a path, your path is being stripped off the filename"
           $index = $filename.split("/")
           $filename = $index[$index.length-1]
           }else {
               
            if ($filename -match "\\"){
            write-host "You have provided a filename with a path, your path is being stripped off the filename"
            $index = $filename.split("\")
            $filename = $index[$index.length-1]
            }   
           }
       
    
    
     return $filename
    }


function get-inputs{
    $runtype=""
    if(($runtype.ToUpper() -ne "C")-and($runtype.ToUpper() -ne "D")-and($runtype.ToUpper() -ne "B")-and($runtype.ToUpper() -ne "Q")){
        do{
            $runtype = Read-Host "What sort of Run is this; is this a (D)eploy only or a (C)onfigure only or (B)oth or (Q)uit"
            $runtype = $runtype.ToUpper()
        }until(($runtype -eq "C")-or($runtype -eq "D")-or($runtype -eq "B")-or($runtype -eq "Q"))
    }
    $runtype = $runtype.ToUpper()
    if($runtype -ne "Q"){
    if(($runtype -eq "D")-or($runtype -eq "B")){
      $Deploytype = Read-host "Is this a (P)owershell based Deployment or a v(R)LCM based Deployment"
      if(!$Deploytype){
        do{
            $Deploytype= Read-host "Is this a (P)owershell based Deployment or a v(R)LCM based Deployment"
            
        }until(($Deploytype.ToUpper() -eq "P")-or($Deploytype.ToUpper() -eq "R"))
       } 
       $Deploytype = $Deploytype.ToUpper()
       if($Deploytype -eq "R"){ 
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
    }else{
        $runtype = "Q"
        write-host "Powershell based deployment is coming in future version of this tooling"
        $Return.runtype = $runtype
        return $Return
    }
}

    $jsonfilename = Read-Host "What is the JSON Filename "
    if(!$jsonfilename){
        do{
            $jsonfilename = Read-Host "You have not entered a JSON File filename, please enter the Filename "
            
        }until($jsonfilename)
        $jsonfilename = get-filenameonly -filename $jsonfilename
    }else{
        $jsonfilename = get-filenameonly -filename $jsonfilename
    }
    $Path1 = $PSScriptRoot
    $testfile = Join-Path -Path $path1 -ChildPath $jsonfilename
    write-host "Looking for JSON file $testfile"
    $found=test-path -path $testfile
    if(!$found){
    do{
        $jsonfilename = Read-Host "The Filename was not found, in the path $testfile, please move the file to this location "
        $testfile = Join-Path -Path $path1 -ChildPath $jsonfilename
        $found=test-path -path $testfile
    }until($found)
    }else{write-host "JSON File found"}
    $CONTENT = get-content -Path $testfile -raw
    write-host "Read JSON file successfully"
    write-host "Splitting the JSON file into vRLCM Deployment Content and Powershell Post Deploy Configuration Script"
    if($PSVersionTable.OS -contains "Darwin Kernel"){
         $CONTENT,$PSHELL = $CONTENT.split("***CONFIGURATION-SECTION***")
    }else{
        $found = $false
        $PSHELL=$null
        foreach($line in Get-Content $testfile) {
            if($line -eq "***CONFIGURATION-SECTION***"){
                $found = $true
            }
            if(($found -eq $true)-and($line -ne "***CONFIGURATION-SECTION***")){
            $PSHELL += "$line`n`r"
            }else{
             if($line -ne "***CONFIGURATION-SECTION***"){
            $CONTENTTMP += "$line`n`r"}
            }
        }
        $CONTENT=$CONTENTTMP
    }
    $psfile = Join-Path -Path $path1 -ChildPath "configautomate.psm1"
    #$PSHELL|out-file $psfile -Encoding ascii
    
    $logfile = Read-host -prompt "What is the name of the log file to generate"
    if(!$logfile){
        do{
            $logfile = Read-Host "You have not entered a log filename, please enter the Filename "
            
        }until($logfile)
        $logfile = get-filenameonly -filename $logfile
    }else{
        $logfile = get-filenameonly -filename $logfile
    }
    $Path1 = $PSScriptRoot
    $logfile = Join-Path -Path $path1 -ChildPath $logfile
    write-host "Writing out log data to $logfile"
}
    [hashtable]$Return=@{}
    $Return.username = $vRLCMuser
    $Return.pw = $pw
    $Return.jsoncontent = $CONTENT
    $Return.pshell = $PSHELL
    $Return.psmodule = $psfile
    $Return.server = $vrlcmserver
    $Return.runtype = $runtype
    $Return.jsonfile = $jsonfilename
    $Return.logfile = $logfile
    $error.clear()
    return $Return
    }








function confirm-module{
    [cmdletbinding()]
    <# 
    .SYNOPSIS
    Function used to gather all the information from the end user necessary to deploy a new environment in vRLCM from a json file
    
    Outputs: The function returns a hashtable that contains all the necessary inputs back to the calling script.
#>
    Param ([string]$modulename)
    try{
        write-host "Checking for presence of $($modulename)"
        if($PSVersionTable.OS -contains "Darwin Kernel"){
          $modname,$isscriptmodule = $modulename.Split(".psm")
        }else{
            $isscriptmodule=$modulename| Select-String -Pattern ".psm1"
            $modname = $modulename.split(".")
            for($i=0;$i -lt $modname.count-1; $i++){
                $modtmp += $modname[$i]
            }
            $modname = $modtmp
            
        }
        if($isscriptmodule){
            write-host "The module specified appears to be a script module"
        }
        try{
            if($isscriptmodule){
               $mod1 = get-module|Where-Object{$_.name -eq $modname}
            }else{
               $mod1 = get-installedmodule|Where-Object{$_.name -eq $modulename}
            }
        if($mod1){
            write-host "Module found, we can continue"
        }else{
            
            if($isscriptmodule){
                write-host "Module was not found, we will try and import from local directory" 
                $Path1 = $PSScriptRoot
                $scriptmodule = Join-Path -Path $path1 -ChildPath $modulename
                write-host "Trying to import script module from $scriptmodule"
                import-module $scriptmodule -Scope Global
                $mod1 = get-module|Where-Object{$_.name -eq $modname}
                if($mod1){
                    write-host "Module installed, we can continue"
                    $true
                    $error.clear()
                    return
                }else{
                    write-host "Failed to install module $modulename, please install manually and rerun this process" -ForegroundColor Red
                    $false
                    $error.clear()
                    return 
                }
             }else{
                write-host "Module was not found, trying to download and install from PS Gallery" - -ForegroundColor Red
                install-module -name $modulename
                $mod1 = get-installedmodule|Where-Object{$_.name -eq $modulename}
                if($mod1){
                    write-host "Module installed, we can continue"
                    $true
                    $error.clear()
                    return
                }else{
                    write-host "Failed to install module $modulename, please install manually and rerun this process" -ForegroundColor Red
                    $false
                    $error.clear()
                    return  
                }
             }
            
            
           
        }
        }catch{write-host "Could not determine what modules are installed" -ForegroundColor Red; $error.clear();exit}




    }catch{write-host "Module $($modulename) is not installed, please install this module and then run this script";$error.clear();exit}
}



function create-module{
<# 
    .SYNOPSIS
    Function to write out new powershell module from an array of strings of powershell commands. The module created will use the PSEREPORTINGPS module
    to generate a logfile using the logfile parameter passed. So this function will read each command line and wrap each command line in a Try and Catch block
    with a log entry written for each line. The first line of the array should be the Function Name with an opening paraenthesis
.PARAMETER psfile
    The name of the module to create.
.PARAMETER psarray
    The array of strings that are the powershell command lines

#>
Param (
[parameter(Mandatory=$true)][string]$psfile,
[parameter(Mandatory=$true)]$psarray
)
Process {
    write-output $psarray[0]|out-file $psfile -Encoding ascii -Append
    write-output $psarray[1]|out-file $psfile -Encoding ascii -Append
    write-output '$error.clear()'|out-file $psfile -Encoding ascii -Append
    For ($i=2; $i -lt $psarray.length; $i++) {
     if (($psarray[$i].trim() -ne "}")-and($psarray[$i].length -gt 1)){
     write-output "try{"|out-file $psfile -Encoding ascii -append
     #$writestring = 'write-host "$($psarray[' + $i + '].ToString())"'
     #write-output $writestring|out-file $psfile -Encoding ascii -Append
     write-output $psarray[$i]|out-file $psfile -Encoding ascii -Append
     $writestring = '$logmessage = "$($psarray[' + $i + '].ToString())"'
     write-output $writestring|out-file $psfile -Encoding ascii -Append
     #write-output 'if($ERROR[0]){write-log -message $ERROR[0] -logfile $logfile}else{'|out-file $psfile -encoding ascii -Append
     write-output 'write-log -message $logmessage -logfile $logfile;$ERROR.clear()'|out-file $psfile -Encoding ascii -Append
     write-output "}"|out-file $psfile -Encoding ascii -append
     write-output "catch{"|out-file $psfile -Encoding ascii -append
     $writestring = '$logmessage = "$($psarray[' + $i + '].ToString())"'
     write-output $writestring|out-file $psfile -Encoding ascii -Append
     write-output 'write-log -message $logmessage -logfile $logfile -type "ERROR";'|out-file $psfile -Encoding ascii -Append
     #$writestring = '$logmessage = $error[0].exception|out-string'
     #write-output $writestring|out-file $psfile -Encoding ascii -Append
     #$writestring = '$logmessage = "Error message - $logmessage"'
     #write-output $writestring|out-file $psfile -Encoding ascii -Append
     #$writestring = '$error[0]'
     write-output $writestring|out-file $psfile -Encoding ascii -Append
     #write-output 'write-log -message $logmessage -logfile $logfile -type "ERROR";$ERROR.clear()'|out-file $psfile -Encoding ascii -Append
     write-output "}"|out-file $psfile -encoding ascii -append
     }
    }
     
     write-output "}"|out-file $psfile -encoding ascii -append
     $error.clear()
}


}





function write-outprogress{
 <# 
    .SYNOPSIS
    Function to write out a message with elipses showing progress
.PARAMETER message
    The url against which the request will be performed. This will be passed to the cmdlet by the originating
    request and does not need any user modification.
.PARAMETER iteration
    The number of times this function has been called by the calling code

#>
Param (
[parameter(Mandatory=$true)][string]$message,
[parameter(Mandatory=$true)]$iteration
)
Process {
$i = $iteration % 5
$k="."

  write-host -NoNewline "`r                                                     "
for ($a=1; $a -le $i; $a++) {
    $k = $k + "."
  }
  
  write-host -NoNewLine "`r $message$k"


}
}

function new-rootvmfolder{

    Param (
[parameter(Mandatory=$true)][string]$vcenterserver,
[parameter(Mandatory=$true)][string]$datacentername,
[parameter(Mandatory=$true)][string]$newfoldername,
[parameter(Mandatory=$true)][string]$vcuser,
[parameter(Mandatory=$true)][string]$vcpw

)
write-host "About to create a new folder in the Datacenter $datacentername called $newfoldername"

connect-viserver -server $vcenterserver -user $vcuser -password $vcpw

try{
$newfolder = (Get-View (Get-View -viewtype datacenter -filter @{"name"=$datacentername}).vmfolder).CreateFolder($newfoldername)
if(!$newfolder){
    write-host "Creating new folder failed" -ForegroundColor Red
    return $false
}else{
    write-host "Successfully created new folder"
    sleep 5
    $newfolder = get-folder -server $vcenterserver -name $newfoldername
    return $newfolder
}
}catch{
    $errormsg = $_.Exception.Message
    $messagepart1,$messagepart2 = $errormsg.Split("$newfoldername`'")
    $error1,$messagepart2 = $messagepart2.Split(".`"")
    $error1 = $error1.Trim()
    if($error1.ToUpper() -eq "ALREADY EXISTS"){
        write-host "Folder already exists"
        $error.Remove($error[0])
        sleep 5
        $newfolder = get-folder -server $vcenterserver -name $newfoldername
        return $newfolder
    }else{return $false}
}

}
function update-addvmsdrsrule{
    Param (
    [parameter(Mandatory=$true)]$cluster,
    [parameter(Mandatory=$true)]$rulename,
    [parameter(Mandatory=$true)]$rulekey, #string representing the rule key
    [parameter(Mandatory=$true)]$newvms, #Should be array of virtual machine objects
    [parameter(Mandatory=$true)]$ruletype
    
    )

    #$cluster = get-cluster -name "Cluster01"
    $initialstr = Get-DrsRule -Cluster $cluster | Select Key, @{Name="VM"; Expression={ $iTemp = @(); $_.VMIds | % { $iTemp += (Get-VM -Id $_).Id }; [string]::Join(",", $iTemp) }}|where-object Key -eq $rulekey|FL VM
    $initialstr0=$initialstr|Out-String
    $garbage,$initialstr1=$initialstr0.Split(":")
    $initialstr2=$initialstr1.Trim()
    [array]$vmnamearray=@()
    [array]$vmarray=@()
    $vmnamearray=$initialstr2.Split(",")
    For ($i=0; $i -lt $newvms.length; $i++) {
        $vmnamearray += $newvms[$i].Id
        write-host "Adding VM $($newvms[$i].name)"
    }
    For ($i=0; $i -lt $vmnamearray.length; $i++) {
        #need to do a bunch of string manipulation
        
        $garbage,$tempstr = $vmnamearray[$i].Split("VirtualMachine-")
        $vmarray += $tempstr
       
    }
    if($ruletype -eq $true){
       write-host "Type of Rule to Modify - VM Affinity Rule"
    }else{
       write-host "Type of Rule to Modify - VM AntiAffinity Rule" 
    }
    
    $spec = New-Object VMware.Vim.ClusterConfigSpecEx
    $spec.rulesSpec = New-Object VMware.Vim.ClusterRuleSpec[] (1)
    $spec.rulesSpec[0] = New-Object VMware.Vim.ClusterRuleSpec
    $spec.rulesSpec[0].operation = 'edit'
    if($ruletype -eq $true){
       $spec.rulesSpec[0].info = New-Object VMware.Vim.ClusterAffinityRuleSpec
    }else{
       $spec.rulesSpec[0].info = New-Object VMware.Vim.ClusterAntiAffinityRuleSpec 
    }
    $spec.rulesSpec[0].info.vm = New-Object VMware.Vim.ManagedObjectReference[] ($vmarray.length)
    For ($i=0; $i -lt $vmarray.length; $i++) {
          $spec.rulesSpec[0].info.vm[$i] = New-Object VMware.Vim.ManagedObjectReference
          $spec.rulesSpec[0].info.vm[$i].value = $vmarray[$i]
          $spec.rulesSpec[0].info.vm[$i].type = 'VirtualMachine'
        }
    
    $spec.rulesSpec[0].info.enabled = $true
    $spec.rulesSpec[0].info.userCreated = $true
    $spec.rulesSpec[0].info.name = $rulename
    $spec.rulesSpec[0].info.key = $rulekey
    $modify = $true
    
    $result=$cluster.ExtensionData.ReconfigureComputeResource_Task($spec, $modify)
    write-host "Updated rule"
    return $result

}

function new-vmdrsgrouprule{

Param (
    [parameter(Mandatory=$true)][string]$vcenterserver,
    [parameter(Mandatory=$true)][string]$datacentername,
    [parameter(Mandatory=$true)][string]$drsrulename,
    [parameter(Mandatory=$true)][string]$drsruletype,
    [parameter(Mandatory=$true)]$vm1,  #this should be a virtual machine object not a string
    [parameter(Mandatory=$true)]$vm2,   #this should be a virtual machine object not a string
    [parameter(Mandatory=$true)]$vcuser,
    [parameter(Mandatory=$true)]$vcpw
    #[parameter(Mandatory=$false)][System.Management.Automation.PSCredential]$credentials
    )
    
    
    $conn= connect-viserver -server $vcenterserver -user $vcuser -password $vcpw
    
    if($drsruletype.ToUpper() -eq "VMAFFINITY"){
        $drsruling = $true
        $type="VMAffinity"
    }else{
        $drsruling = $false
        $type="VMAntiAffinity"
    }
    $cluster = get-cluster -VM $vm1 
    #$vmarray = (get-vm -name $vm1 -server $conn -Location $datacentername),(get-vm -name $vm2 -server $conn -Location $datacentername)
    $vmarray=@()
    $vmarray += $vm1
    $vmarray += $vm2

    $drsrule = Get-Drsrule -Cluster $cluster -Name $drsrulename -ErrorAction SilentlyContinue
    $drstype = $drsrule.type
     
    if($drsrule){
        if($drstype -eq $type){
          Write-host "VM DRS Affinity Rule already exists with the name $drsrulename and is the right type $type"
          
          do{
            $answer = Read-host -NoNewLine "`r Would you like us to place the VM(s) in this rule - (Y)es or (N)o"
          }while(($answer.ToUpper() -ne "Y")-and($answer.ToUpper() -ne "N"))
          if($answer.ToUpper() -eq "N"){
              write-host "You MUST rename the existing rule to another name, at least until we complete this operation"
              do{
               $answer1 = Read-host -NoNewLine "`r Please press (C)ontinue when you are ready for us to continue, if we find the rule with the same name again, we will assume you want to place the VM(s) in this rule"
               
            }while($answer1.ToUpper() -ne "C")
              $drsrule = Get-Drsrule -Cluster $cluster -Name $drsrulename -ErrorAction SilentlyContinue
              if($drsrule){
                   #update the existing rule
                   Write-host "Updating existing DRS Rule"
                   $rulekeystr = $drsrule.Key
                   $result = update-addvmsdrsrule -cluster $cluster -rulename $drsrulename -rulekey $rulekeystr -newvms $vmarray -ruletype $drsruling
                   return $result
              }else{
                  #add this rule as a new rule
                  $result = new-drsrule -KeepTogether $drsruling -Cluster $cluster -Name $drsrulename -vm $vmarray  
                  return $result
              }
          }else{
              #update the existing rule
              Write-host "Updating existing DRS Rule"
              $rulekeystr = $drsrule.Key
              $result = update-addvmsdrsrule -cluster $cluster -rulename $drsrulename -rulekey $rulekeystr -newvms $vmarray -ruletype $drsruling
              return $result
          }

        }else{
          Write-host "VM DRS Affinity Rule already exists with the name $drsrulename but is NOT the right type $type" -ForegroundColor Red
          return $false
        }
    }else{
        Write-host "VM DRS Rule does not exist creating DRS Rule";
        $result = new-drsrule -KeepTogether $drsruling -Cluster $cluster -Name $drsrulename -vm $vmarray; 
        return $result    
    }


}
#Export-ModuleMember -function confirm-module