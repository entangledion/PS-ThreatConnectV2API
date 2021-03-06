function Get-TCAttributes {
<#
.SYNOPSIS
	Gets a list of attributes for the specified "group".  (Group being Adversaries, Emails, Incidents, Signatures and Threats)
	
.PARAMETER AdversaryID
	Optional parameter used to list all attributes linked to a specific Adversary ID.

.PARAMETER EmailID
	Optional parameter used to list all attributes linked to a specific Email ID.

.PARAMETER IncidentID
	Optional parameter used to list all attributes linked to a specific Incident ID.

.PARAMETER SignatureID
	Optional parameter used to list all attributes linked to a specific Signature ID.

.PARAMETER ThreatID
	Optional parameter used to list all attributes linked to a specific Threat ID.
	
.PARAMETER IndicatorType
	Optional paramter used to list all attributes linked to a specific Indicator.  IndicatorType could be Host, EmailAddress, File, Address, or URL.
	Must be used along with the Indicator parameter.
	
.PARAMETER Indicator
	Optional paramter used to list all attributes linked to a specific Indicator.
	Must be used along with the IndicatorType parameter.

.PARAMETER Owner
	Optional Parameter to define a specific Community (or other "Owner") from which to retrieve attributes.
	This switch can be used alongside some of the other switches.

.PARAMETER ResultStart
	Optional Parameter. Use when dealing with large number of results.
	If you use ResultLimit of 100, you can use a ResultStart value of 100 to show items 100 through 200.

.PARAMETER ResultLimit
	Optional Parameter. Change the maximum number of results to display. Default is 100, Maximum is 500.

.EXAMPLE
	Get-TCAttributes -AdversaryID "123456"

.EXAMPLE
	Get-TCAttributes -EmailID <EmailID>

.EXAMPLE
	Get-TCAttributes -IncidentID <IncidentID>

.EXAMPLE
	Get-TCAttributes -SignatureID <SignatureID>

.EXAMPLE
	Get-TCAttributes -ThreatID <ThreatID>
	
.EXAMPLE
	Get-TCAttributes -IndicatorType Address -Indicator <Indicator>

.EXAMPLE
	Get-TCAttributes -IndicatorType EmailAddress -Indicator <Indicator>

.EXAMPLE
	Get-TCAttributes -IndicatorType File -Indicator <Indicator>

.EXAMPLE
	Get-TCAttributes -IndicatorType Host -Indicator <Indicator>

.EXAMPLE
	Get-TCAttributes -IndicatorType URL -Indicator <Indicator>
#>
[CmdletBinding()]Param(
	[Parameter(Mandatory=$True,ParameterSetName='AdversaryID')]
		[ValidateNotNullOrEmpty()][String]$AdversaryID,
	[Parameter(Mandatory=$True,ParameterSetName='EmailID')]
		[ValidateNotNullOrEmpty()][String]$EmailID,
	[Parameter(Mandatory=$True,ParameterSetName='IncidentID')]
		[ValidateNotNullOrEmpty()][String]$IncidentID,
	[Parameter(Mandatory=$True,ParameterSetName='Indicator')]
		[ValidateSet('Address','EmailAddress','File','Host','URL')][String]$IndicatorType,
	[Parameter(Mandatory=$True,ParameterSetName='Indicator')]
		[ValidateNotNullOrEmpty()][String]$Indicator,
	[Parameter(Mandatory=$True,ParameterSetName='SignatureID')]
		[ValidateNotNullOrEmpty()][String]$SignatureID,
	[Parameter(Mandatory=$True,ParameterSetName='ThreatID')]
		[ValidateNotNullOrEmpty()][String]$ThreatID,
	[Parameter(Mandatory=$False,ParameterSetName='Indicator')]
		[ValidateNotNullOrEmpty()][String]$Owner,
	[Parameter(Mandatory=$False)][ValidateRange('1','500')][int]$ResultLimit=100,
	[Parameter(Mandatory=$False)][ValidateNotNullOrEmpty()][int]$ResultStart
)

# Construct the Child URL based on the Parameter Set that was chosen
switch ($PSCmdlet.ParameterSetName) {
	"AdversaryID" { 
		$APIChildURL = "/v2/groups/adversaries/" + $AdversaryID + "/attributes"
	}
	
	"EmailID" { 
		$APIChildURL = "/v2/groups/emails/" + $EmailID + "/attributes"
	}
	
	"IncidentID" { 
		$APIChildURL = "/v2/groups/incidents/" + $IncidentID + "/attributes"
	}
	
	"Indicator" {
		# Craft Indicator Child URL based on Indicator Type
		switch ($IndicatorType) {
			"Address" {
				$APIChildURL = "/v2/indicators/addresses/" + $Indicator + "/attributes"
			}
			"EmailAddress" {
				$APIChildURL = "/v2/indicators/emailAddresses/" + $Indicator + "/attributes"
			}
			"File" {
				$APIChildURL = "/v2/indicators/files/" + $Indicator + "/attributes"
			}
			"Host" {
				$APIChildURL = "/v2/indicators/hosts/" + $Indicator + "/attributes"
			}
			"URL" {
				# URLs need to be converted to a friendly format first
				$Indicator = Get-EscapedURIString -String $Indicator
				$APIChildURL = "/v2/indicators/urls/" + $Indicator + "/attributes"
			}
		}
	}
	
	"SignatureID" { 
		$APIChildURL = "/v2/groups/signatures/" + $SignatureID + "/attributes"
	}
	
	"ThreatID" { 
		$APIChildURL = "/v2/groups/threats/" + $ThreatID + "/attributes"
	}
}

# Add to the URI if Owner, ResultStart, or ResultLimit was specified
if ($Owner -and $ResultStart -and $ResultLimit -ne 100) {
	$APIChildURL = $APIChildURL + "?owner=" + (Get-EscapedURIString -String $Owner) + "&resultStart=" + $ResultStart + "&resultLimit=" + $ResultLimit
} elseif ($Owner -and $ResultStart -and $ResultLimit -eq 100) {
	$APIChildURL = $APIChildURL + "?owner=" + (Get-EscapedURIString -String $Owner) + "&resultStart=" + $ResultStart
} elseif ($Owner -and (-not $ResultStart) -and $ResultLimit -ne 100) {
	$APIChildURL = $APIChildURL + "?owner=" + (Get-EscapedURIString -String $Owner) + "&resultLimit=" + $ResultLimit
} elseif ($Owner -and (-not $ResultStart) -and $ResultLimit -eq 100) {
	$APIChildURL = $APIChildURL + "?owner=" + (Get-EscapedURIString -String $Owner)
} elseif ((-not $Owner) -and $ResultStart -and $ResultLimit -ne 100) {
	$APIChildURL = $APIChildURL + "?resultStart=" + $ResultStart + "&resultLimit=" + $ResultLimit
} elseif ((-not $Owner) -and $ResultStart -and $ResultLimit -eq 100) {
	$APIChildURL = $APIChildURL + "?resultStart=" + $ResultStart
} elseif ((-not $Owner) -and (-not $ResultStart) -and $ResultLimit -ne 100) {
	$APIChildURL = $APIChildURL + "?resultLimit=" + $ResultLimit
}

# Generate the appropriate Headers for the API Request
$AuthorizationHeaders = Get-ThreatConnectHeaders -RequestMethod "GET" -URL $APIChildURL

# Create the URI using System.URI (This fixes the issues with URL encoding)
$URI = New-Object System.Uri ($Script:APIBaseURL + $APIChildURL)

if ($IndicatorType -eq "URL" -and $Indicator) { [URLFix]::ForceCanonicalPathAndQuery($URI) }

# Query the API
$Response = Invoke-RestMethod -Method "GET" -Uri $URI -Headers $AuthorizationHeaders -ErrorAction SilentlyContinue

# Verify API Request Status as Success or Print the Error
if ($Response.Status -eq "Success") {
	$Response.data | Get-Member -MemberType NoteProperty | Where-Object { $_.Name -ne "resultCount" } | Select-Object -ExpandProperty Name | ForEach-Object { $Response.data.$_ }
} else {
	Write-Verbose "API Request failed with the following error:`n $($Response.Status)"
}
}