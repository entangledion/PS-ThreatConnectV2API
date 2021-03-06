
function New-TCIncident {
<#
.SYNOPSIS
	Creates a new incident in Threat Connect.

.PARAMETER Name
	Name of the incident to create.

.PARAMETER EventDate
	The date the Incident occurred. The code attempts to convert the provided date to the format required by the API, but uses the computer's time zone from which the script is being run.
	
.EXAMPLE
	New-TCIncident -Name <IncidentName> -EventDate "2015-01-01T14:00:00-06:00"
	
.EXAMPLE
	New-TCIncident -Name <IncidentName> -EventDate (Get-Date -Date "10/01/2014 15:00:03" -Format "yyyy-MM-ddThh:mm:sszzzz")

.EXAMPLE
	New-TCIncident -Name <IncidentName> -EventDate "10/01/2014 15:00:03"
#>
[CmdletBinding()]Param(
	[Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][String]$Name,
	[Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][String]$EventDate
)

Try { 
	$EventDate = Get-Date -Date $EventDate -Format "yyyy-MM-ddThh:mm:sszzzz" -ErrorAction Stop

	# Create a Custom Object and add the provided Name and Value variables to the object
	$CustomObject = "" | Select-Object -Property  name, eventDate
	$CustomObject.name = $Name
	$CustomObject.eventDate = $EventDate

	# Convert the Custom Object to JSON format for use with the API
	$JSONData = $CustomObject | ConvertTo-Json
	
	# Child URL for Adversary Creation
	$APIChildURL = "/v2/groups/incidents"
	
	# Generate the appropriate Headers for the API Request
	$AuthorizationHeaders = Get-ThreatConnectHeaders -RequestMethod "POST" -URL $APIChildURL
	
	# Create the URI using System.URI (This fixes the issues with URL encoding)
	$URI = New-Object System.Uri ($Script:APIBaseURL + $APIChildURL)
	
	if ($IndicatorType -eq "URL" -and $Indicator) { [URLFix]::ForceCanonicalPathAndQuery($URI) }
	
	# Query the API
	$Response = Invoke-RestMethod -Method "POST" -Uri $URI -Headers $AuthorizationHeaders -Body $JSONData -ContentType "application/json" -ErrorAction SilentlyContinue
	
	# Verify API Request Status as Success or Print the Error
	if ($Response.Status -eq "Success") {
		$Response.data | Get-Member -MemberType NoteProperty | Where-Object { $_.Name -ne "resultCount" } | Select-Object -ExpandProperty Name | ForEach-Object { $Response.data.$_ }
	} else {
		Write-Verbose "API Request failed with the following error:`n $($Response.Status)"
	}
} Catch {
	return "Error converting EventDate to a properly formatted date/time for Threat Connect's API."
}
}
