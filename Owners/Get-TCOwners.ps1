function Get-TCOwners {
<#
.SYNOPSIS
	Gets a list of Owners visible to your API key.

.DESCRIPTION
	Owners include your API Key's Organization, and any other communities to which it subscribes.
	
.PARAMETER IndicatorType
	Optional paramter used to list all owners linked to a specific Indicator.  IndicatorType could be Host, EmailAddress, File, Address, or URL.
	Must be used along with the Indicator parameter.
	
.PARAMETER Indicator
	Optional paramter used to list all owners linked to a specific Indicator.
	Must be used along with the IndicatorType parameter.

.EXAMPLE
	Get-TCOwners
	
.EXAMPLE
	Get-TCOwners -IndicatorType Address -Indicator <Indicator>

.EXAMPLE
	Get-TCOwners -IndicatorType EmailAddress -Indicator <Indicator>

.EXAMPLE
	Get-TCOwners -IndicatorType File -Indicator <Indicator>

.EXAMPLE
	Get-TCOwners -IndicatorType Host -Indicator <Indicator>

.EXAMPLE
	Get-TCOwners -IndicatorType URL -Indicator <Indicator>
#>

[CmdletBinding(DefaultParameterSetName='Default')]Param(
	[Parameter(Mandatory=$True,ParameterSetName='Indicator')]
		[ValidateSet('Address','EmailAddress','File','Host','URL')][String]$IndicatorType,
	[Parameter(Mandatory=$True,ParameterSetName='Indicator')]
		[ValidateNotNullOrEmpty()][String]$Indicator
)

# Construct the Child URL based on the Parameter Set that was chosen
switch ($PSCmdlet.ParameterSetName) {
	"Indicator" {
		# Craft Indicator Child URL based on Indicator Type
		switch ($IndicatorType) {
			"Address" {
				$APIChildURL = "/v2/indicators/addresses/" + $Indicator + "/owners"
			}
			"EmailAddress" {
				$APIChildURL = "/v2/indicators/emailAddresses/" + $Indicator + "/owners"
			}
			"File" {
				$APIChildURL = "/v2/indicators/files/" + $Indicator + "/owners"
			}
			"Host" {
				$APIChildURL = "/v2/indicators/hosts/" + $Indicator + "/owners"
			}
			"URL" {
				# URLs need to be converted to a friendly format first
				$Indicator = Get-EscapedURIString -String $Indicator
				$APIChildURL = "/v2/indicators/urls/" + $Indicator + "/owners"
			}
		}
	}
	
	"Default" {
		$APIChildURL = "/v2/owners"
	}
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