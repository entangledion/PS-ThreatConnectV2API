
function New-TCAttribute {
<#
.SYNOPSIS
	Creates a new attribute in Threat Connect.

.DESCRIPTION
	Must supply a specific "group" for which to add an attribute (Adversary, Email, Incident, Threat, Signature).

.PARAMETER Name
	Name of the Attribute to add

.PARAMETER Value
	Value of the Attribute to add

.PARAMETER AdversaryID
	Adversary ID of the Adversary for which you want to create an attribute

.PARAMETER EmailID
	Email ID of the Email for which you want to create an attribute

.PARAMETER IncidentID
	Incident ID of the Incident for which you want to create an attribute

.PARAMETER ThreatID
	Threat ID of the Threat for which you want to create an attribute

.PARAMETER SignatureID
	Signature ID of the Signature for which you want to create an attribute
	
.EXAMPLE
	New-TCAttribute -AdversaryID <AdversaryID> -Name Description -Value "Testing Description Creation"
		
.EXAMPLE
	New-TCAttribute -EmailID <EmailID> -Name Description -Value "Testing Description Creation"
		
.EXAMPLE
	New-TCAttribute -IncidentID <IncidentID> -Name Description -Value "Testing Description Creation"
		
.EXAMPLE
	New-TCAttribute -ThreatID <ThreatID> -Name Description -Value "Testing Description Creation"
		
.EXAMPLE
	New-TCAttribute -SignatureID <SignatureID> -Name Description -Value "Testing Description Creation"


#>
[CmdletBinding()]Param(
	[Parameter(Mandatory=$True,ParameterSetName='AdversaryID')]
		[ValidateNotNullOrEmpty()][int]$AdversaryID,
	[Parameter(Mandatory=$True,ParameterSetName='EmailID')]
		[ValidateNotNullOrEmpty()][int]$EmailID,
	[Parameter(Mandatory=$True,ParameterSetName='IncidentID')]
		[ValidateNotNullOrEmpty()][int]$IncidentID,
	[Parameter(Mandatory=$True,ParameterSetName='ThreatID')]
		[ValidateNotNullOrEmpty()][int]$ThreatID,
	[Parameter(Mandatory=$True,ParameterSetName='SignatureID')]
		[ValidateNotNullOrEmpty()][int]$SignatureID,
	[Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][String]$Name,
	[Parameter(Mandatory=$True)][ValidateNotNullOrEmpty()][String]$Value
)

# Create a Custom Object and add the provided Name and Value variables to the object
$CustomObject = "" | Select-Object -Property  type, value
$CustomObject.type = $Name
$CustomObject.value = $Value

# Convert the Custom Object to JSON format for use with the API
$JSONData = $CustomObject | ConvertTo-Json

# Switch to construct Child URL based on the parameters that were provided
switch ($PSCmdlet.ParameterSetName) {
	"AdversaryID" {
		$APIChildURL = "/v2/groups/adversaries" + "/" + $AdversaryID + "/attributes"
	}
	
	"EmailID" {
		$APIChildURL = "/v2/groups/emails" + "/" + $AdversaryID + "/attributes"
	}
	
	"IncidentID" {
		$APIChildURL = "/v2/groups/incidents" + "/" + $AdversaryID + "/attributes"
	}
	
	"ThreatID" {
		$APIChildURL = "/v2/groups/threats" + "/" + $AdversaryID + "/attributes"
	}
	
	"SignatureID" {
		$APIChildURL = "/v2/groups/signatures" + "/" + $AdversaryID + "/attributes"
	}
}

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
}
