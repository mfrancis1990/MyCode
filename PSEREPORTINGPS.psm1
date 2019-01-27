
<# 
    
    This Module is used to host any functions relating to the generation of logs or reports.
    A significant portion of the Logging Code has come from  https://github.com/iRon7/Log-Entry rather than reinventing the capability.

#>

function write-log{

    Param (
        [parameter(Mandatory=$true)][string]$message,
        [parameter(Mandatory=$false)]$type,
        [parameter(Mandatory=$true)]$logfile
        )
        Process {
          if($type -eq "ERROR"){
            $message = $message.TrimStart("`r`n")
            $message = $message.Replace("`r","")
            $message = "ERROR:Command = $message"
            #$datestr = (Get-Date).ToString('MM/dd/yyyy hh:mm:ss tt').trim("`r`n")
            $datestr = (Get-Date).ToString().trim("`r`n")
            $message = "$datestr $message"
            $message = $message.Replace("`r","")
            $message = $message.Replace("`n","")
          write-output $message|out-file -encoding ascii -append -filepath $logfile
          }else{
            $message = $message.TrimStart("`r`n")
            $message = $message.Replace("`r","")
            $message = "INFO:Command = $message"
            #$datestr = (Get-Date).ToString('MM/dd/yyyy hh:mm:ss tt').trim("`r`n")
            $datestr = (Get-Date).ToString().trim("`r`n")
            $message = "$datestr $message"
            $message = $message.Replace("`r","")
            $message = $message.Replace("`n","")
            write-output $message|out-file -encoding ascii -append -filepath $logfile
          }




        }


}