<#
Author: David Howell  @DavidHowellTX
Last Modified: 04/29/2015
Version: 0 [incomplete]

Thanks to Threat Connect for their awesome documentation on how to use the API.
#>

# Set the API Access ID, Secret Key, and Base URL for the API
# Place the values within the single quotes. If your Secret Key has a single quote in it, you may need to escape it by using the backtick before the single quote
[String]$Script:AccessID = ''
[String]$Script:SecretKey = ''
[String]$Script:APIBaseURL = 'https://api.threatconnect.com'
# I currently have not implemented any work with the Default Organization setting, but here is a place holder
# [String]$Script:DefaultOrg = ''

function Get-ThreatConnectHeaders {
	<#
	.SYNOPSIS
		Generates the HTTP headers for an API request.
		
	.DESCRIPTION
		Each API request must contain headers that include a HMAC-SHA256, Base64 encoded signature and the Unix Timestamp. This function handles creation of those headers.
		This command is intended to be used by other commands in the Threat Connect Module.  It is not intended to be used manually at the command line, unless for testing purposes.
	
	.PARAMETER RequestMethod
		The HTTP Request Method for the API request (GET, PUT, POST, DELETE)
	
	.PARAMETER URL
		The Child URL for the API Request (Exclude the root, eg. https://api.threatconnect.com should not be included)
		
	.EXAMPLE
		Get-ThreatConnectHeaders -RequestMethod "GET" -URL "/v2/owners"
	#>
	[CmdletBinding()]Param(
		[Parameter(Mandatory=$True)][String]$RequestMethod,
		[Parameter(Mandatory=$True)][String]$URL
	)
	# Calculate Unix UTC time
	[String]$Timestamp = [Math]::Floor([Decimal](Get-Date -Date (Get-Date).ToUniversalTime() -UFormat "%s"))
	# Create the HMAC-SHA256 Object to work with
	$HMACSHA256 = New-Object System.Security.Cryptography.HMACSHA256
	# Set the HMAC Key to the API Secret Key
	$HMACSHA256.Key = [System.Text.Encoding]::UTF8.GetBytes($Script:SecretKey)
	# Generate the HMAC Signature using API URI, Request Method, and Unix Time
	$HMACSignature = $HMACSHA256.ComputeHash([System.Text.Encoding]::UTF8.GetBytes("$URL`:$RequestMethod`:$Timestamp"))
	# Base 64 Encode the HMAC Signature
	$HMACBase64 = [System.Convert]::ToBase64String($HMACSignature)
	# Craft the full Authorization Header
	$Authorization = "TC $($Script:AccessID)`:$HMACBase64"
	# Create a HashTable where we will add the Authorization information
	$Headers = New-Object System.Collections.Hashtable
	$Headers.Add("Timestamp",$Timestamp)
	$Headers.Add("Authorization",$Authorization)
	return $Headers
}

function Get-EscapedURIString {
	<#
	.SYNOPSIS
		Escapes special characters in the provided URI string (spaces become %20, etc.)
	
	.DESCRIPTION
		Uses System.URI's method "EscapeDataString" to convert special characters into their hex representation.
	
	.PARAMETER String
		The string that requires conversion
	
	.EXAMPLE
		Get-EscapedURIString -String "Test Escaping"
	#>
	
	[CmdletBinding()]Param(
		[Parameter(Mandatory=$True)][String]$String
	)
	
	# Use System.URI's "EscapeDataString" method to convert
	[System.Uri]::EscapeDataString($String)
}

function Get-Owners {
	<#
	.SYNOPSIS
		Gets a list of Owners visible to your API key.
	
	.DESCRIPTION
		Owners include your API Key's Organization, and any other communities to which it subscribes.
	#>
	
	# Child URL for the API query
	$APIChildURL = "/v2/owners"
	
	# Generate the appropriate Headers for the API Request
	$AuthorizationHeaders = Get-ThreatConnectHeaders -RequestMethod "GET" -URL $APIChildURL
	
	# Query the API
	$Response = Invoke-RestMethod -Method "GET" -Uri ($Script:APIBaseURL + $APIChildURL) -Headers $AuthorizationHeaders -ErrorAction SilentlyContinue
	
	# Check for Status=Success and print the results or the Error
	if ($Response.Status -eq "Success") {
		$Response.data.owner
	} else {
		Write-Error "API Request failed with the following error:`n $($Response.Status)"
	}
}

function Get-Adversaries {
	<#
	.SYNOPSIS
		Gets a list of Adversaries from Threat Connect.  Default is all Adversaries for the API Key's organization
	
	.PARAMETER Owner
		Optional Parameter to define a specific Community (or other "Owner") from which to retrieve adversaries.
	
	.PARAMETER AdversaryID
		Optional Parameter to specify an Adversary ID for which to query.
	
	.PARAMETER TagName
		Optional parameter used to list all Adversaries with a specific Tag.
	
	.PARAMETER SecurityLabel
		Optional parameter used to list all Adversaries with a specific Security Label.
	
	.PARAMETER IncidentID
		Optional parameter used to list all Adversaries linked to a specific Incident ID.
	
	.PARAMETER ThreatID
		Optional parameter used to list all Adversaries linked to a specific Threat.
	
	.PARAMETER EmailID
		Optional parameter used to list all Adversaries linked to a specific Email.
	
	.PARAMETER SignatureID
		Optional parameter used to list all Adversaries linked to a specific Signature.
	
	.PARAMETER VictimID
		Optional parameter used to list all Adversaries linked to a specific Victim.

	.EXAMPLE
		Get-Adversaries
	
	.EXAMPLE
		Get-Adversaries -Owner "Common Community"
	
	.EXAMPLE
		Get-Adversaries -AdversaryID 123456
	
	.EXAMPLE
		Get-Adversaries -TagName "BadStuff"
		
	.EXAMPLE
		Get-Adversaries -SecurityLabel "Confidential"
		
	.EXAMPLE
		Get-Adversaries -IncidentID 123456
		
	.EXAMPLE
		Get-Adversaries -ThreatID 123456
		
	.EXAMPLE
		Get-Adversaries -EmailID 123456
		
	.EXAMPLE
		Get-Adversaries -SignatureID 123456
	
	.EXAMPLE
		Get-Adversaries -VictimID 123456
	#>
	[CmdletBinding(DefaultParameterSetName='Default')]Param(
		[Parameter(Mandatory=$False,ParameterSetName='Default')]
		[Parameter(Mandatory=$False,ParameterSetName='AdversaryID')]
		[Parameter(Mandatory=$False,ParameterSetName='TagName')]
		[Parameter(Mandatory=$False,ParameterSetName='SecurityLabel')]
		[Parameter(Mandatory=$False,ParameterSetName='Incident')]
		[Parameter(Mandatory=$False,ParameterSetName='Threat')]
		[Parameter(Mandatory=$False,ParameterSetName='Email')]
		[Parameter(Mandatory=$False,ParameterSetName='Signature')]
		[Parameter(Mandatory=$False,ParameterSetName='Victim')]
			[ValidateNotNullOrEmpty()][String]$Owner,
		[Parameter(Mandatory=$True,ParameterSetName='AdversaryID')]
			[ValidateNotNullOrEmpty()][String]$AdversaryID,
		[Parameter(Mandatory=$True,ParameterSetName='TagName')]
			[ValidateNotNullOrEmpty()][String]$TagName,
		[Parameter(Mandatory=$True,ParameterSetName='SecurityLabel')]
			[ValidateNotNullOrEmpty()][String]$SecurityLabel,
		[Parameter(Mandatory=$True,ParameterSetName='Incident')]
			[ValidateNotNullOrEmpty()][String]$IncidentID,
		[Parameter(Mandatory=$True,ParameterSetName='Threat')]
			[ValidateNotNullOrEmpty()][String]$ThreatID,
		[Parameter(Mandatory=$True,ParameterSetName='Email')]
			[ValidateNotNullOrEmpty()][String]$EmailID,
		[Parameter(Mandatory=$True,ParameterSetName='Signature')]
			[ValidateNotNullOrEmpty()][String]$SignatureID,
		[Parameter(Mandatory=$True,ParameterSetName='Victim')]
			[ValidateNotNullOrEmpty()][String]$VictimID
	)
	
	# Construct the Child URL based on the Parameter Set that was chosen
	switch ($PSCmdlet.ParameterSetName) {
		"AdversaryID" {
			$APIChildURL = "/v2/groups/adversaries/" + $AdversaryID
		}
		
		"TagName" {
			$APIChildURL = "/v2/tags/" + $TagName + "/groups/adversaries"		
		}
		
		"SecurityLabel" {
			$APIChildURL = "/v2/securityLabels/" + $SecurityLabel + "/groups/adversaries"
		}
		
		"Incident" {
			$APIChildURL = "/v2/groups/incidents/" + $IncidentID + "/groups/adversaries"
		}
		
		"Threat" {
			$APIChildURL = "/v2/groups/threats/" + $ThreatID + "/groups/adversaries"
		}
		
		"Email" {
			$APIChildURL = "/v2/groups/emails/" + $EmailID + "/groups/adversaries"
		}
		
		"Signature" {
			$APIChildURL = "/v2/groups/signatures/" + $SignatureID + "/groups/adversaries"
		}
		
		"Victim" {
			$APIChildURL = "/v2/victims/" + $VictimID + "/groups/adversaries"
		}
		
		Default {
			# Use this if nothing else is specified
			$APIChildURL ="/v2/groups/adversaries"
		}
	}

	# Add to the Child URL if an Owner was supplied
	if ($Owner) {
		# Escape the provided Owner using Get-EscapedURIString, and add the value to the end of the Child URL
		$APIChildURL = $APIChildURL + "?owner=" + (Get-EscapedURIString -String $Owner)
	}
	
	# Generate the appropriate Headers for the API Request
	$AuthorizationHeaders = Get-ThreatConnectHeaders -RequestMethod "GET" -URL $APIChildURL
	
	# Query the API
	$Response = Invoke-RestMethod -Method "GET" -Uri ($Script:APIBaseURL + $APIChildURL) -Headers $AuthorizationHeaders -ErrorAction SilentlyContinue
	
	# Check for Status=Success and print the results or the Error
	if ($Response.Status -eq "Success") {
		$Response.data.adversary
	} else {
		Write-Error "API Request failed with the following error:`n $($Response.Status)"
	}
}


















