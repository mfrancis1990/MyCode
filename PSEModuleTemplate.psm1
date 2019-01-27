# |---------------------------------------------------------------------------------------------------------------------------------|
# | Module Name: <ModuleName>                                                          									            |
# | Author: <PSE Architect Names>                                                                                                   |
# | Date: <Date>                                                                                             				        |
# | Description: <Description of Module>                                                     								        |
# | Version: 0.1                                                                                                		            |
# |---------------------------------------------------------------------------------------------------------------------------------|
import-module "$PSScriptRoot\PSECOMMONPS.psm1" -DisableNameChecking
$WarningPreference ="silentlycontinue"
function <FunctionName> {
	<#
		.SYNOPSIS
			Function to obtain the current time in milliseconds since the Unix epoch
		.DESCRIPTION
			Function used by other functions in the module to convert either the current date/time
			or a previous date/time into milliseconds since the Unix epoch which is what vROps uses
			for all of its time calculations
		.EXAMPLE
			getTimeSinceEpoch
		.EXAMPLE
			getTimeSinceEpoch -date (get-date -day 12 -month 06 -year 2016 -hour 14 -minute 50 -second 30)
		.EXAMPLE
			getTimeSinceEpoch -date $somepreviousvariable
		.PARAMETER date
			PowerShell date object
		.NOTES
			Added in version 0.1
			Updated to include date argument in 0.3.5 testing
	#>
	Param	(
		[parameter(Mandatory=$false)]$date,
		[parameter(Mandatory=$false)]$hourstoadd
		)
	process {
		
		return 	
	}
}

export-modulemember -function 'get*'
export-modulemember -function 'Create*'
export-modulemember -function 'add*'
export-modulemember -function 'set*'
export-modulemember -function 'delete*'
export-modulemember -function 'download*'
export-modulemember -function 'start*'
export-modulemember -function 'stop*'
export-modulemember -function 'acquire*'
export-modulemember -function 'enumerate*'
export-modulemember -function 'update*'
export-modulemember -function 'mark*'
export-modulemember -function 'unmark*'
export-modulemember -function 'modify*'



