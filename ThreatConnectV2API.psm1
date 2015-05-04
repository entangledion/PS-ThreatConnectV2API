<#
Author: David Howell  @DavidHowellTX
Last Modified: 05/04/2015
Version: 0 [incomplete]

Thanks to Threat Connect for their awesome documentation on how to use the API.
#>

# Set the API Access ID, Secret Key, and Base URL for the API
# Place the values within the single quotes. If your Secret Key has a single quote in it, you may need to escape it by using the backtick before the single quote
[String]$Script:AccessID = ''
[String]$Script:SecretKey = ''
[String]$Script:APIBaseURL = 'https://api.threatconnect.com'

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

function Get-TCOwners {
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

function Get-TCGroups {
	<#
	.SYNOPSIS
		Gets a list of Groups from Threat Connect.  Default is all Groups for the API Key's organization
		
	.PARAMETER Owner
		Optional Parameter to define a specific Community (or other "Owner") from which to retrieve groups.
		This switch can be used alongside the other switches.
	
	.PARAMETER AdversaryID
		Optional parameter use to list all groups linked to a specific Adversary ID.
		
	.PARAMETER EmailID
		Optional parameter used to list all groups linked to a specific Email ID.
		
	.PARAMETER IncidentID
		Optional parameter used to list all groups linked to a specific Incident ID.
		
	.PARAMETER SecurityLabel
		Optional parameter used to list all groups with a specific Security Label.
		
	.PARAMETER SignatureID
		Optional parameter used to list all groups linked to a specific Signature ID.
	
	.PARAMETER TagName
		Optional parameter used to list all groups with a specific Tag.
	
	.PARAMETER ThreatID
		Optional parameter used to list all groups linked to a specific Threat ID.
	
	.PARAMETER VictimID
		Optional parameter used to list all groups linked to a specific Victim ID.

	.EXAMPLE
		Get-TCGroups
		
	.EXAMPLE
		Get-TCGroups -AdversaryID 123456
		
	.EXAMPLE
		Get-TCGroups -EmailID "123456"
		
	.EXAMPLE
		Get-TCGroups -IncidentID "123456"
	
	.EXAMPLE
		Get-TCGroups -SecurityLabel "Confidential"
		
	.EXAMPLE
		Get-TCGroups -SignatureID "123456"
		
	.EXAMPLE
		Get-TCGroups -TagName "BadStuff"
		
	.EXAMPLE
		Get-TCGroups -ThreatID "123456"
		
	.EXAMPLE
		Get-TCGroups -VictimID "123456"
	#>
	[CmdletBinding(DefaultParameterSetName='Default')]Param(
		[Parameter(Mandatory=$False,ParameterSetName='Default')]
		[Parameter(Mandatory=$False,ParameterSetName='AdversaryID')]
		[Parameter(Mandatory=$False,ParameterSetName='EmailID')]
		[Parameter(Mandatory=$False,ParameterSetName='IncidentID')]
		[Parameter(Mandatory=$False,ParameterSetName='SecurityLabel')]
		[Parameter(Mandatory=$False,ParameterSetName='SignatureID')]
		[Parameter(Mandatory=$False,ParameterSetName='TagName')]
		[Parameter(Mandatory=$False,ParameterSetName='ThreatID')]
		[Parameter(Mandatory=$False,ParameterSetName='VictimID')]
			[ValidateNotNullOrEmpty()][String]$Owner,
		[Parameter(Mandatory=$True,ParameterSetName='AdversaryID')]
			[ValidateNotNullOrEmpty()][String]$AdversaryID,
		[Parameter(Mandatory=$True,ParameterSetName='EmailID')]
			[ValidateNotNullOrEmpty()][String]$EmailID,
		[Parameter(Mandatory=$True,ParameterSetName='IncidentID')]
			[ValidateNotNullOrEmpty()][String]$IncidentID,
		[Parameter(Mandatory=$True,ParameterSetName='SecurityLabel')]
			[ValidateNotNullOrEmpty()][String]$SecurityLabel,
		[Parameter(Mandatory=$True,ParameterSetName='SignatureID')]
			[ValidateNotNullOrEmpty()][String]$SignatureID,
		[Parameter(Mandatory=$True,ParameterSetName='TagName')]
			[ValidateNotNullOrEmpty()][String]$TagName,
		[Parameter(Mandatory=$True,ParameterSetName='ThreatID')]
			[ValidateNotNullOrEmpty()][String]$ThreatID,
		[Parameter(Mandatory=$True,ParameterSetName='VictimID')]
			[ValidateNotNullOrEmpty()][String]$VictimID
	)
	
	# Construct the Child URL based on the Parameter Set that was chosen
	switch ($PSCmdlet.ParameterSetName) {
		"AdversaryID" {
			$APIChildURL = "/v2/groups/adversaries/" + $AdversaryID + "/groups"
		}
		
		"EmailID" {
			$APIChildURL = "/v2/groups/emails/" + $EmailID + "/groups"
		}
		
		"IncidentID" {
			$APIChildURL = "/v2/groups/incidents/" + $IncidentID + "/groups"
		}

		"SecurityLabel" {
			# Need to escape the URI in case there are any spaces or special characters
			$SecurityLabel = Get-EscapedURIString -String $SecurityLabel
			$APIChildURL = "/v2/securityLabels/" + $SecurityLabel + "/groups"
		}
		
		"SignatureID" {
			$APIChildURL = "/v2/groups/signatures/" + $SignatureID + "/groups"
		}
		
		"TagName" {
			# Need to escape the URI in case there are any spaces or special characters
			$TagName = Get-EscapedURIString -String $TagName
			$APIChildURL = "/v2/tags/" + $TagName + "/groups"		
		}
		
		"ThreatID" {
			$APIChildURL = "/v2/groups/threats/" + $ThreatID + "/groups"
		}
		
		"VictimID" {
			$APIChildURL = "/v2/victims/" + $VictimID + "/groups"
		}
		
		Default {
			# Use this if nothing else is specified
			$APIChildURL ="/v2/groups"
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
		$Response.data.group
	} else {
		Write-Error "API Request failed with the following error:`n $($Response.Status)"
	}
}

function Get-TCAdversaries {
	<#
	.SYNOPSIS
		Gets a list of Adversaries from Threat Connect.  Default is all Adversaries for the API Key's organization
		
	.PARAMETER Owner
		Optional Parameter to define a specific Community (or other "Owner") from which to retrieve adversaries.
		This switch can be used alongside the other switches.
	
	.PARAMETER AdversaryID
		Optional Parameter to specify an Adversary ID for which to query.
		
	.PARAMETER EmailID
		Optional parameter used to list all Adversaries linked to a specific Email ID.
		
	.PARAMETER IncidentID
		Optional parameter used to list all Adversaries linked to a specific Incident ID.
		
	.PARAMETER SecurityLabel
		Optional parameter used to list all Adversaries with a specific Security Label.
		
	.PARAMETER SignatureID
		Optional parameter used to list all Adversaries linked to a specific Signature ID.
	
	.PARAMETER TagName
		Optional parameter used to list all Adversaries with a specific Tag.
	
	.PARAMETER ThreatID
		Optional parameter used to list all Adversaries linked to a specific Threat ID.
	
	.PARAMETER VictimID
		Optional parameter used to list all Adversaries linked to a specific Victim ID.
		
	.PARAMETER IndicatorType
		Optional paramter used to list all Adversaries linked to a specific Indicator.  IndicatorType could be Host, EmailAddress, File, Address, or URL.
		Must be used along with the Indicator parameter.
		
	.PARAMETER Indicator
		Optional paramter used to list all Adversaries linked to a specific Indicator.
		Must be used along with the IndicatorType parameter.
	
	.EXAMPLE
		Get-TCAdversaries
		
	.EXAMPLE
		Get-TCAdversaries -AdversaryID 123456
		
	.EXAMPLE
		Get-TCAdversaries -EmailID "123456"
		
	.EXAMPLE
		Get-TCAdversaries -IncidentID "123456"
	
	.EXAMPLE
		Get-TCAdversaries -SecurityLabel "Confidential"
		
	.EXAMPLE
		Get-TCAdversaries -SignatureID "123456"
		
	.EXAMPLE
		Get-TCAdversaries -TagName "BadStuff"
		
	.EXAMPLE
		Get-TCAdversaries -ThreatID "123456"
		
	.EXAMPLE
		Get-TCAdversaries -VictimID "123456"
		
	.EXAMPLE
		Get-TCAdversaries -IndicatorType Address -Indicator "127.0.0.1"
	
	.EXAMPLE
		Get-TCAdversaries -IndicatorType EmailAddress -Indicator "test@baddomain.com"
	
	.EXAMPLE
		Get-TCAdversaries -IndicatorType File -Indicator "d41d8cd98f00b204e9800998ecf8427e"
	
	.EXAMPLE
		Get-TCAdversaries -IndicatorType Host -Indicator "baddomain.com"
	
	.EXAMPLE
		Get-TCAdversaries -IndicatorType URL -Indicator "http://baddomain.com/phishies
	#>
	[CmdletBinding(DefaultParameterSetName='Default')]Param(
		[Parameter(Mandatory=$False,ParameterSetName='Default')]
		[Parameter(Mandatory=$False,ParameterSetName='AdversaryID')]
		[Parameter(Mandatory=$False,ParameterSetName='EmailID')]
		[Parameter(Mandatory=$False,ParameterSetName='IncidentID')]
		[Parameter(Mandatory=$False,ParameterSetName='Indicator')]
		[Parameter(Mandatory=$False,ParameterSetName='SecurityLabel')]
		[Parameter(Mandatory=$False,ParameterSetName='SignatureID')]
		[Parameter(Mandatory=$False,ParameterSetName='TagName')]
		[Parameter(Mandatory=$False,ParameterSetName='ThreatID')]
		[Parameter(Mandatory=$False,ParameterSetName='VictimID')]
			[ValidateNotNullOrEmpty()][String]$Owner,
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
		[Parameter(Mandatory=$True,ParameterSetName='SecurityLabel')]
			[ValidateNotNullOrEmpty()][String]$SecurityLabel,
		[Parameter(Mandatory=$True,ParameterSetName='SignatureID')]
			[ValidateNotNullOrEmpty()][String]$SignatureID,
		[Parameter(Mandatory=$True,ParameterSetName='TagName')]
			[ValidateNotNullOrEmpty()][String]$TagName,
		[Parameter(Mandatory=$True,ParameterSetName='ThreatID')]
			[ValidateNotNullOrEmpty()][String]$ThreatID,
		[Parameter(Mandatory=$True,ParameterSetName='VictimID')]
			[ValidateNotNullOrEmpty()][String]$VictimID
	)
	
	# Construct the Child URL based on the Parameter Set that was chosen
	switch ($PSCmdlet.ParameterSetName) {
		"AdversaryID" {
			$APIChildURL = "/v2/groups/adversaries/" + $AdversaryID
		}
		
		"EmailID" {
			$APIChildURL = "/v2/groups/emails/" + $EmailID + "/groups/adversaries"
		}
		
		"IncidentID" {
			$APIChildURL = "/v2/groups/incidents/" + $IncidentID + "/groups/adversaries"
		}
		
		"Indicator" {
			# Craft Indicator Child URL based on Indicator Type
			switch ($IndicatorType) {
				"Address" {
					$APIChildURL = "/v2/indicators/addresses/" + $Indicator + "/groups/adversaries"
				}
				"EmailAddress" {
					$APIChildURL = "/v2/indicators/emailAddresses/" + $Indicator + "/groups/adversaries"
				}
				"File" {
					$APIChildURL = "/v2/indicators/files/" + $Indicator + "/groups/adversaries"
				}
				"Host" {
					$APIChildURL = "/v2/indicators/hosts/" + $Indicator + "/groups/adversaries"
				}
				"URL" {
					# URLs need to be converted to a friendly format first
					$Indicator = Get-EscapedURIString -String $Indicator
					Write-Host $Indicator
					$APIChildURL = "/v2/indicators/urls/" + $Indicator + "/groups/adversaries"
				}
			}
		}

		"SecurityLabel" {
			# Need to escape the URI in case there are any spaces or special characters
			$SecurityLabel = Get-EscapedURIString -String $SecurityLabel
			$APIChildURL = "/v2/securityLabels/" + $SecurityLabel + "/groups/adversaries"
		}
		
		"SignatureID" {
			$APIChildURL = "/v2/groups/signatures/" + $SignatureID + "/groups/adversaries"
		}
		
		"TagName" {
			# Need to escape the URI in case there are any spaces or special characters
			$TagName = Get-EscapedURIString -String $TagName
			$APIChildURL = "/v2/tags/" + $TagName + "/groups/adversaries"		
		}
		
		"ThreatID" {
			$APIChildURL = "/v2/groups/threats/" + $ThreatID + "/groups/adversaries"
		}
		
		"VictimID" {
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

function Get-TCEmails {
	<#
	.SYNOPSIS
		Gets a list of emails from Threat Connect.  Default is all emails for the API Key's organization
		
	.PARAMETER Owner
		Optional Parameter to define a specific Community (or other "Owner") from which to retrieve emails.
		This switch can be used alongside the other switches.
	
	.PARAMETER AdversaryID
		Optional parameter used to list all emails linked to a specific Adversary ID.
		
	.PARAMETER EmailID
		Optional parameter used to specify an Email ID for which to query.
		
	.PARAMETER IncidentID
		Optional parameter used to list all emails linked to a specific Incident ID.
		
	.PARAMETER SecurityLabel
		Optional parameter used to list all emails with a specific Security Label.
		
	.PARAMETER SignatureID
		Optional parameter used to list all emails linked to a specific Signature ID.
	
	.PARAMETER TagName
		Optional parameter used to list all emails with a specific Tag.
	
	.PARAMETER ThreatID
		Optional parameter used to list all emails linked to a specific Threat ID.
	
	.PARAMETER VictimID
		Optional parameter used to list all emails linked to a specific Victim ID.

	.EXAMPLE
		Get-TCEmails
		
	.EXAMPLE
		Get-TCEmails -AdversaryID 123456
		
	.EXAMPLE
		Get-TCEmails -EmailID "123456"
		
	.EXAMPLE
		Get-TCEmails -IncidentID "123456"
	
	.EXAMPLE
		Get-TCEmails -SecurityLabel "Confidential"
		
	.EXAMPLE
		Get-TCEmails -SignatureID "123456"
		
	.EXAMPLE
		Get-TCEmails -TagName "BadStuff"
		
	.EXAMPLE
		Get-TCEmails -ThreatID "123456"
		
	.EXAMPLE
		Get-TCEmails -VictimID "123456"
	#>
	[CmdletBinding(DefaultParameterSetName='Default')]Param(
		[Parameter(Mandatory=$False,ParameterSetName='Default')]
		[Parameter(Mandatory=$False,ParameterSetName='AdversaryID')]
		[Parameter(Mandatory=$False,ParameterSetName='EmailID')]
		[Parameter(Mandatory=$False,ParameterSetName='IncidentID')]
		[Parameter(Mandatory=$False,ParameterSetName='SecurityLabel')]
		[Parameter(Mandatory=$False,ParameterSetName='SignatureID')]
		[Parameter(Mandatory=$False,ParameterSetName='TagName')]
		[Parameter(Mandatory=$False,ParameterSetName='ThreatID')]
		[Parameter(Mandatory=$False,ParameterSetName='VictimID')]
			[ValidateNotNullOrEmpty()][String]$Owner,
		[Parameter(Mandatory=$True,ParameterSetName='AdversaryID')]
			[ValidateNotNullOrEmpty()][String]$AdversaryID,
		[Parameter(Mandatory=$True,ParameterSetName='EmailID')]
			[ValidateNotNullOrEmpty()][String]$EmailID,
		[Parameter(Mandatory=$True,ParameterSetName='IncidentID')]
			[ValidateNotNullOrEmpty()][String]$IncidentID,
		[Parameter(Mandatory=$True,ParameterSetName='SecurityLabel')]
			[ValidateNotNullOrEmpty()][String]$SecurityLabel,
		[Parameter(Mandatory=$True,ParameterSetName='SignatureID')]
			[ValidateNotNullOrEmpty()][String]$SignatureID,
		[Parameter(Mandatory=$True,ParameterSetName='TagName')]
			[ValidateNotNullOrEmpty()][String]$TagName,
		[Parameter(Mandatory=$True,ParameterSetName='ThreatID')]
			[ValidateNotNullOrEmpty()][String]$ThreatID,
		[Parameter(Mandatory=$True,ParameterSetName='VictimID')]
			[ValidateNotNullOrEmpty()][String]$VictimID
	)
	
	# Construct the Child URL based on the Parameter Set that was chosen
	switch ($PSCmdlet.ParameterSetName) {
		"AdversaryID" {
			$APIChildURL = "/v2/groups/adversaries/" + $AdversaryID + "/groups/emails"
		}
		
		"EmailID" {
			$APIChildURL = "/v2/groups/emails/" + $EmailID
		}
		
		"IncidentID" {
			$APIChildURL = "/v2/groups/incidents/" + $IncidentID + "/groups/emails"
		}
		
		"SecurityLabel" {
			# Need to escape the URI in case there are any spaces or special characters
			$SecurityLabel = Get-EscapedURIString -String $SecurityLabel
			$APIChildURL = "/v2/securityLabels/" + $SecurityLabel + "/groups/emails"
		}
		
		"SignatureID" {
			$APIChildURL = "/v2/groups/signatures/" + $SignatureID + "/groups/emails"
		}
		
		"TagName" {
			# Need to escape the URI in case there are any spaces or special characters
			$TagName = Get-EscapedURIString -String $TagName
			$APIChildURL = "/v2/tags/" + $TagName + "/groups/emails"		
		}		
		
		"ThreatID" {
			$APIChildURL = "/v2/groups/threats/" + $ThreatID + "/groups/emails"
		}

		"VictimID" {
			$APIChildURL = "/v2/victims/" + $VictimID + "/groups/emails"
		}
		
		Default {
			# Use this if nothing else is specified
			$APIChildURL ="/v2/groups/emails"
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
		$Response.data.email
	} else {
		Write-Error "API Request failed with the following error:`n $($Response.Status)"
	}
}

function Get-TCIncidents {
	<#
	.SYNOPSIS
		Gets a list of incidents from Threat Connect.  Default is all incidents for the API Key's organization
		
	.PARAMETER Owner
		Optional Parameter to define a specific Community (or other "Owner") from which to retrieve incidents.
		This switch can be used alongside the other switches.
	
	.PARAMETER AdversaryID
		Optional parameter used to list all incidents linked to a specific Adversary ID.
		
	.PARAMETER EmailID
		Optional parameter used to list all incidents linked to a specific Email ID.
		
	.PARAMETER IncidentID
		Optional parameter used to specify an Incident ID for which to query.
		
	.PARAMETER SecurityLabel
		Optional parameter used to list all incidents with a specific Security Label.
		
	.PARAMETER SignatureID
		Optional parameter used to list all incidents linked to a specific Signature ID.
	
	.PARAMETER TagName
		Optional parameter used to list all incidents with a specific Tag.
	
	.PARAMETER ThreatID
		Optional parameter used to list all incidents linked to a specific Threat ID.
	
	.PARAMETER VictimID
		Optional parameter used to list all incidents linked to a specific Victim ID.

	.EXAMPLE
		Get-TCIncidents
		
	.EXAMPLE
		Get-TCIncidents -AdversaryID 123456
		
	.EXAMPLE
		Get-TCIncidents -EmailID "123456"
		
	.EXAMPLE
		Get-TCIncidents -IncidentID "123456"
	
	.EXAMPLE
		Get-TCIncidents -SecurityLabel "Confidential"
		
	.EXAMPLE
		Get-TCIncidents -SignatureID "123456"
		
	.EXAMPLE
		Get-TCIncidents -TagName "BadStuff"
		
	.EXAMPLE
		Get-TCIncidents -ThreatID "123456"
		
	.EXAMPLE
		Get-TCIncidents -VictimID "123456"
	#>
	[CmdletBinding(DefaultParameterSetName='Default')]Param(
		[Parameter(Mandatory=$False,ParameterSetName='Default')]
		[Parameter(Mandatory=$False,ParameterSetName='AdversaryID')]
		[Parameter(Mandatory=$False,ParameterSetName='EmailID')]
		[Parameter(Mandatory=$False,ParameterSetName='IncidentID')]
		[Parameter(Mandatory=$False,ParameterSetName='SecurityLabel')]
		[Parameter(Mandatory=$False,ParameterSetName='SignatureID')]
		[Parameter(Mandatory=$False,ParameterSetName='TagName')]
		[Parameter(Mandatory=$False,ParameterSetName='ThreatID')]
		[Parameter(Mandatory=$False,ParameterSetName='VictimID')]
			[ValidateNotNullOrEmpty()][String]$Owner,
		[Parameter(Mandatory=$True,ParameterSetName='AdversaryID')]
			[ValidateNotNullOrEmpty()][String]$AdversaryID,
		[Parameter(Mandatory=$True,ParameterSetName='EmailID')]
			[ValidateNotNullOrEmpty()][String]$EmailID,
		[Parameter(Mandatory=$True,ParameterSetName='IncidentID')]
			[ValidateNotNullOrEmpty()][String]$IncidentID,
		[Parameter(Mandatory=$True,ParameterSetName='SecurityLabel')]
			[ValidateNotNullOrEmpty()][String]$SecurityLabel,
		[Parameter(Mandatory=$True,ParameterSetName='SignatureID')]
			[ValidateNotNullOrEmpty()][String]$SignatureID,
		[Parameter(Mandatory=$True,ParameterSetName='TagName')]
			[ValidateNotNullOrEmpty()][String]$TagName,
		[Parameter(Mandatory=$True,ParameterSetName='ThreatID')]
			[ValidateNotNullOrEmpty()][String]$ThreatID,
		[Parameter(Mandatory=$True,ParameterSetName='VictimID')]
			[ValidateNotNullOrEmpty()][String]$VictimID
	)
	
	# Construct the Child URL based on the Parameter Set that was chosen
	switch ($PSCmdlet.ParameterSetName) {
		"AdversaryID" {
			$APIChildURL = "/v2/groups/adversaries/" + $AdversaryID + "/groups/incidents"
		}
		
		"EmailID" {
			$APIChildURL = "/v2/groups/emails/" + $EmailID + "/groups/incidents"
		}
		
		"IncidentID" {
			$APIChildURL = "/v2/groups/incidents/" + $IncidentID
		}
		
		"SecurityLabel" {
			# Need to escape the URI in case there are any spaces or special characters
			$SecurityLabel = Get-EscapedURIString -String $SecurityLabel
			$APIChildURL = "/v2/securityLabels/" + $SecurityLabel + "/groups/incidents"
		}
		
		"SignatureID" {
			$APIChildURL = "/v2/groups/signatures/" + $SignatureID + "/groups/incidents"
		}
		
		"TagName" {
			# Need to escape the URI in case there are any spaces or special characters
			$TagName = Get-EscapedURIString -String $TagName
			$APIChildURL = "/v2/tags/" + $TagName + "/groups/incidents"		
		}
		
		"ThreatID" {
			$APIChildURL = "/v2/groups/threats/" + $ThreatID  + "/groups/incidents"
		}
		
		"VictimID" {
			$APIChildURL = "/v2/victims/" + $VictimID + "/groups/incidents"
		}
		
		Default {
			# Use this if nothing else is specified
			$APIChildURL ="/v2/groups/incidents"
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
		$Response.data.incident
	} else {
		Write-Error "API Request failed with the following error:`n $($Response.Status)"
	}
}

function Get-TCSignatures {
	<#
	.SYNOPSIS
		Gets a list of signatures from Threat Connect.  Default is all signatures for the API Key's organization
		
	.PARAMETER Owner
		Optional Parameter to define a specific Community (or other "Owner") from which to retrieve signatures.
		This switch can be used alongside the other switches.
	
	.PARAMETER AdversaryID
		Optional parameter used to list all signatures linked to a specific Adversary ID.
		
	.PARAMETER EmailID
		Optional parameter used to list all signatures linked to a specific Email ID.
		
	.PARAMETER IncidentID
		Optional parameter used to list all signatures linked to a specific Incident ID.
		
	.PARAMETER SecurityLabel
		Optional parameter used to list all signatures with a specific Security Label.
		
	.PARAMETER SignatureID
		Optional parameter used to specify a Signature ID for which to query.
	
	.PARAMETER TagName
		Optional parameter used to list all signatures with a specific Tag.
	
	.PARAMETER ThreatID
		Optional parameter used to list all signatures linked to a specific Threat ID.
	
	.PARAMETER VictimID
		Optional parameter used to list all signatures linked to a specific Victim ID.

	.EXAMPLE
		Get-TCSignatures
		
	.EXAMPLE
		Get-TCSignatures -AdversaryID 123456
		
	.EXAMPLE
		Get-TCSignatures -EmailID "123456"
		
	.EXAMPLE
		Get-TCSignatures -IncidentID "123456"
	
	.EXAMPLE
		Get-TCSignatures -SecurityLabel "Confidential"
		
	.EXAMPLE
		Get-TCSignatures -SignatureID "123456"
		
	.EXAMPLE
		Get-TCSignatures -TagName "BadStuff"
		
	.EXAMPLE
		Get-TCSignatures -ThreatID "123456"
		
	.EXAMPLE
		Get-TCSignatures -VictimID "123456"
	#>
	[CmdletBinding(DefaultParameterSetName='Default')]Param(
		[Parameter(Mandatory=$False,ParameterSetName='Default')]
		[Parameter(Mandatory=$False,ParameterSetName='AdversaryID')]
		[Parameter(Mandatory=$False,ParameterSetName='EmailID')]
		[Parameter(Mandatory=$False,ParameterSetName='IncidentID')]
		[Parameter(Mandatory=$False,ParameterSetName='SecurityLabel')]
		[Parameter(Mandatory=$False,ParameterSetName='SignatureID')]
		[Parameter(Mandatory=$False,ParameterSetName='TagName')]
		[Parameter(Mandatory=$False,ParameterSetName='ThreatID')]
		[Parameter(Mandatory=$False,ParameterSetName='VictimID')]
			[ValidateNotNullOrEmpty()][String]$Owner,
		[Parameter(Mandatory=$True,ParameterSetName='AdversaryID')]
			[ValidateNotNullOrEmpty()][String]$AdversaryID,
		[Parameter(Mandatory=$True,ParameterSetName='EmailID')]
			[ValidateNotNullOrEmpty()][String]$EmailID,
		[Parameter(Mandatory=$True,ParameterSetName='IncidentID')]
			[ValidateNotNullOrEmpty()][String]$IncidentID,
		[Parameter(Mandatory=$True,ParameterSetName='SecurityLabel')]
			[ValidateNotNullOrEmpty()][String]$SecurityLabel,
		[Parameter(Mandatory=$True,ParameterSetName='SignatureID')]
			[ValidateNotNullOrEmpty()][String]$SignatureID,
		[Parameter(Mandatory=$True,ParameterSetName='TagName')]
			[ValidateNotNullOrEmpty()][String]$TagName,
		[Parameter(Mandatory=$True,ParameterSetName='ThreatID')]
			[ValidateNotNullOrEmpty()][String]$ThreatID,
		[Parameter(Mandatory=$True,ParameterSetName='VictimID')]
			[ValidateNotNullOrEmpty()][String]$VictimID
	)
	
	# Construct the Child URL based on the Parameter Set that was chosen
	switch ($PSCmdlet.ParameterSetName) {
		"AdversaryID" {
			$APIChildURL = "/v2/groups/adversaries/" + $AdversaryID + "/groups/signatures"
		}
		
		"EmailID" {
			$APIChildURL = "/v2/groups/emails/" + $EmailID + "/groups/signatures"
		}
		
		"IncidentID" {
			$APIChildURL = "/v2/groups/incidents/" + $IncidentID + "/groups/signatures"
		}
		
		"SecurityLabel" {
			# Need to escape the URI in case there are any spaces or special characters
			$SecurityLabel = Get-EscapedURIString -String $SecurityLabel
			$APIChildURL = "/v2/securityLabels/" + $SecurityLabel + "/groups/signatures"
		}
		
		"SignatureID" {
			$APIChildURL = "/v2/groups/signatures/" + $SignatureID
		}
		
		"TagName" {
			# Need to escape the URI in case there are any spaces or special characters
			$TagName = Get-EscapedURIString -String $TagName
			$APIChildURL = "/v2/tags/" + $TagName + "/groups/signatures"		
		}		
		
		"ThreatID" {
			$APIChildURL = "/v2/groups/threats/" + $ThreatID + "/groups/signatures"
		}
		
		"VictimID" {
			$APIChildURL = "/v2/victims/" + $VictimID + "/groups/signatures"
		}
		
		Default {
			# Use this if nothing else is specified
			$APIChildURL ="/v2/groups/signatures"
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
		$Response.data.signature
	} else {
		Write-Error "API Request failed with the following error:`n $($Response.Status)"
	}
}

function Get-TCThreats {
	<#
	.SYNOPSIS
		Gets a list of threats from Threat Connect.  Default is all threats for the API Key's organization
		
	.PARAMETER Owner
		Optional Parameter to define a specific Community (or other "Owner") from which to retrieve threats.
		This switch can be used alongside the other switches.
	
	.PARAMETER AdversaryID
		Optional parameter used to list all threats linked to a specific Adversary ID.
		
	.PARAMETER EmailID
		Optional parameter used to list all threats linked to a specific Email ID.
		
	.PARAMETER IncidentID
		Optional parameter used to list all threats linked to a specific Incident ID.
		
	.PARAMETER SecurityLabel
		Optional parameter used to list all threats with a specific Security Label.
		
	.PARAMETER SignatureID
		Optional parameter used to list all threats linked to a specific Signature ID.
	
	.PARAMETER TagName
		Optional parameter used to list all threats with a specific Tag.
	
	.PARAMETER ThreatID
		Optional parameter used to specify a Threat ID for which to query.
	
	.PARAMETER VictimID
		Optional parameter used to list all threats linked to a specific Victim ID.

	.EXAMPLE
		Get-TCThreats
		
	.EXAMPLE
		Get-TCThreats -AdversaryID 123456
		
	.EXAMPLE
		Get-TCThreats -EmailID "123456"
		
	.EXAMPLE
		Get-TCThreats -IncidentID "123456"
	
	.EXAMPLE
		Get-TCThreats -SecurityLabel "Confidential"
		
	.EXAMPLE
		Get-TCThreats -SignatureID "123456"
		
	.EXAMPLE
		Get-TCThreats -TagName "BadStuff"
		
	.EXAMPLE
		Get-TCThreats -ThreatID "123456"
		
	.EXAMPLE
		Get-TCThreats -VictimID "123456"
	#>
	[CmdletBinding(DefaultParameterSetName='Default')]Param(
		[Parameter(Mandatory=$False,ParameterSetName='Default')]
		[Parameter(Mandatory=$False,ParameterSetName='AdversaryID')]
		[Parameter(Mandatory=$False,ParameterSetName='EmailID')]
		[Parameter(Mandatory=$False,ParameterSetName='IncidentID')]
		[Parameter(Mandatory=$False,ParameterSetName='SecurityLabel')]
		[Parameter(Mandatory=$False,ParameterSetName='SignatureID')]
		[Parameter(Mandatory=$False,ParameterSetName='TagName')]
		[Parameter(Mandatory=$False,ParameterSetName='ThreatID')]
		[Parameter(Mandatory=$False,ParameterSetName='VictimID')]
			[ValidateNotNullOrEmpty()][String]$Owner,
		[Parameter(Mandatory=$True,ParameterSetName='AdversaryID')]
			[ValidateNotNullOrEmpty()][String]$AdversaryID,
		[Parameter(Mandatory=$True,ParameterSetName='EmailID')]
			[ValidateNotNullOrEmpty()][String]$EmailID,
		[Parameter(Mandatory=$True,ParameterSetName='IncidentID')]
			[ValidateNotNullOrEmpty()][String]$IncidentID,
		[Parameter(Mandatory=$True,ParameterSetName='SecurityLabel')]
			[ValidateNotNullOrEmpty()][String]$SecurityLabel,
		[Parameter(Mandatory=$True,ParameterSetName='SignatureID')]
			[ValidateNotNullOrEmpty()][String]$SignatureID,
		[Parameter(Mandatory=$True,ParameterSetName='TagName')]
			[ValidateNotNullOrEmpty()][String]$TagName,
		[Parameter(Mandatory=$True,ParameterSetName='ThreatID')]
			[ValidateNotNullOrEmpty()][String]$ThreatID,
		[Parameter(Mandatory=$True,ParameterSetName='VictimID')]
			[ValidateNotNullOrEmpty()][String]$VictimID
	)
	
	# Construct the Child URL based on the Parameter Set that was chosen
	switch ($PSCmdlet.ParameterSetName) {
		"AdversaryID" {
			$APIChildURL = "/v2/groups/adversaries/" + $AdversaryID + "/groups/threats"
		}
		
		"EmailID" {
			$APIChildURL = "/v2/groups/emails/" + $EmailID + "/groups/threats"
		}
		
		"IncidentID" {
			$APIChildURL = "/v2/groups/incidents/" + $IncidentID + "/groups/threats"
		}
		
		"SecurityLabel" {
			# Need to escape the URI in case there are any spaces or special characters
			$SecurityLabel = Get-EscapedURIString -String $SecurityLabel
			$APIChildURL = "/v2/securityLabels/" + $SecurityLabel + "/groups/threats"
		}
		
		"SignatureID" {
			$APIChildURL = "/v2/groups/signatures/" + $SignatureID + "/groups/threats"
		}
		
		"TagName" {
			# Need to escape the URI in case there are any spaces or special characters
			$TagName = Get-EscapedURIString -String $TagName
			$APIChildURL = "/v2/tags/" + $TagName + "/groups/threats"		
		}
		
		"ThreatID" {
			$APIChildURL = "/v2/groups/threats/" + $ThreatID
		}
		
		"VictimID" {
			$APIChildURL = "/v2/victims/" + $VictimID + "/groups/threats"
		}
		
		Default {
			# Use this if nothing else is specified
			$APIChildURL ="/v2/groups/threats"
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
		$Response.data.threat
	} else {
		Write-Error "API Request failed with the following error:`n $($Response.Status)"
	}
}

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
	
	.EXAMPLE
		Get-TCAttributes -AdversaryID "123456"
	
	.EXAMPLE
		Get-TCAttributes -EmailID "123456"
	
	.EXAMPLE
		Get-TCAttributes -IncidentID "123456"
	
	.EXAMPLE
		Get-TCAttributes -SignatureID "123456"
	
	.EXAMPLE
		Get-TCAttributes -ThreatID "123456"
	#>
	[CmdletBinding()]Param(
		[Parameter(Mandatory=$True,ParameterSetName='AdversaryID')]
			[ValidateNotNullOrEmpty()][String]$AdversaryID,
		[Parameter(Mandatory=$True,ParameterSetName='EmailID')]
			[ValidateNotNullOrEmpty()][String]$EmailID,
		[Parameter(Mandatory=$True,ParameterSetName='IncidentID')]
			[ValidateNotNullOrEmpty()][String]$IncidentID,
		[Parameter(Mandatory=$True,ParameterSetName='SignatureID')]
			[ValidateNotNullOrEmpty()][String]$SignatureID,
		[Parameter(Mandatory=$True,ParameterSetName='ThreatID')]
			[ValidateNotNullOrEmpty()][String]$ThreatID
	)
	
	# Construct the Child URL based on the Parameter Set that was chosen
	switch ($PSCmdlet.ParameterSetName) {
		"AdversaryID" { 
			$APIChildURL = "/v2/groups/adversaries/" + $AdversaryID + "/attributes"
		}
		
		"EmailID" { 
			$APIChildURL = "/v2/groups/emails/" + $AdversaryID + "/attributes"
		}
		
		"IncidentID" { 
			$APIChildURL = "/v2/groups/incidents/" + $AdversaryID + "/attributes"
		}
		
		"SignatureID" { 
			$APIChildURL = "/v2/groups/signatures/" + $AdversaryID + "/attributes"
		}
		
		"ThreatID" { 
			$APIChildURL = "/v2/groups/threats/" + $AdversaryID + "/attributes"
		}
	}

	# Generate the appropriate Headers for the API Request
	$AuthorizationHeaders = Get-ThreatConnectHeaders -RequestMethod "GET" -URL $APIChildURL
	
	# Query the API
	$Response = Invoke-RestMethod -Method "GET" -Uri ($Script:APIBaseURL + $APIChildURL) -Headers $AuthorizationHeaders -ErrorAction SilentlyContinue
	
	# Check for Status=Success and print the results or the Error
	if ($Response.Status -eq "Success") {
		$Response.data.attribute
	} else {
		Write-Error "API Request failed with the following error:`n $($Response.Status)"
	}
}

function Get-TCSecurityLabels {
	<#
	.SYNOPSIS
		Gets a list of security labels from Threat Connect.  Default is all security labels for the API Key's organization
		
	.PARAMETER Owner
		Optional Parameter to define a specific Community (or other "Owner") from which to retrieve security labels.
		This switch can be used alongside the other switches.
	
	.PARAMETER AdversaryID
		Optional parameter used to list all security labels linked to a specific Adversary ID.
		
	.PARAMETER EmailID
		Optional parameter used to list all security labels linked to a specific Email ID.
		
	.PARAMETER IncidentID
		Optional parameter used to list all security labels linked to a specific Incident ID.
		
	.PARAMETER SignatureID
		Optional parameter used to list all security labels linked to a specific Signature ID.
	
	.PARAMETER ThreatID
		Optional parameter used to list all security labels linked to a specific Threat ID.

	.EXAMPLE
		Get-TCSecurityLabels
		
	.EXAMPLE
		Get-TCSecurityLabels -AdversaryID 123456
		
	.EXAMPLE
		Get-TCSecurityLabels -EmailID "123456"
		
	.EXAMPLE
		Get-TCSecurityLabels -IncidentID "123456"
	
	.EXAMPLE
		Get-TCSecurityLabels -SecurityLabel "Confidential"
		
	.EXAMPLE
		Get-TCSecurityLabels -SignatureID "123456"
		
	.EXAMPLE
		Get-TCSecurityLabels -ThreatID "123456"
		
	#>
	[CmdletBinding(DefaultParameterSetName='Default')]Param(
		[Parameter(Mandatory=$False,ParameterSetName='Default')]
		[Parameter(Mandatory=$False,ParameterSetName='SecurityLabel')]
			[ValidateNotNullOrEmpty()][String]$Owner,
		[Parameter(Mandatory=$True,ParameterSetName='AdversaryID')]
			[ValidateNotNullOrEmpty()][String]$AdversaryID,
		[Parameter(Mandatory=$True,ParameterSetName='EmailID')]
			[ValidateNotNullOrEmpty()][String]$EmailID,
		[Parameter(Mandatory=$True,ParameterSetName='IncidentID')]
			[ValidateNotNullOrEmpty()][String]$IncidentID,
		[Parameter(Mandatory=$True,ParameterSetName='SecurityLabel')]
			[ValidateNotNullOrEmpty()][String]$SecurityLabel,
		[Parameter(Mandatory=$True,ParameterSetName='SignatureID')]
			[ValidateNotNullOrEmpty()][String]$SignatureID,
		[Parameter(Mandatory=$True,ParameterSetName='ThreatID')]
			[ValidateNotNullOrEmpty()][String]$ThreatID
	)
	
	# Construct the Child URL based on the Parameter Set that was chosen
	switch ($PSCmdlet.ParameterSetName) {
		"AdversaryID" {
			$APIChildURL = "/v2/groups/adversaries/" + $AdversaryID + "/securityLabels"
		}
		
		"EmailID" {
			$APIChildURL = "/v2/groups/emails/" + $EmailID + "/securityLabels"
		}
		
		"IncidentID" {
			$APIChildURL = "/v2/groups/incidents/" + $IncidentID + "/securityLabels"
		}
		
		"SecurityLabel" {
			# Need to escape the URI in case there are any spaces or special characters
			$SecurityLabel = Get-EscapedURIString -String $SecurityLabel
			$APIChildURL = "/v2/securityLabels/" + $SecurityLabel
		}
		
		"SignatureID" {
			$APIChildURL = "/v2/groups/signatures/" + $SignatureID + "/securityLabels"
		}
		
		"ThreatID" {
			$APIChildURL = "/v2/groups/threats/" + $ThreatID + "/securityLabels"
		}
		
		Default {
			# Use this if nothing else is specified
			$APIChildURL ="/v2/securityLabels"
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
		$Response.data.securityLabel
	} else {
		Write-Error "API Request failed with the following error:`n $($Response.Status)"
	}
}

function Get-TCTags {
	<#
	.SYNOPSIS
		Gets a list of tags from Threat Connect.  Default is all tags for the API Key's organization
		
	.PARAMETER Owner
		Optional Parameter to define a specific Community (or other "Owner") from which to retrieve tags.
		This switch can be used alongside the other switches.
	
	.PARAMETER AdversaryID
		Optional parameter used to list all tags linked to a specific Adversary ID.
		
	.PARAMETER EmailID
		Optional parameter used to list all tags linked to a specific Email ID.
		
	.PARAMETER IncidentID
		Optional parameter used to list all tags linked to a specific Incident ID.
		
	.PARAMETER SignatureID
		Optional parameter used to list all tags linked to a specific Signature ID.
	
	.PARAMETER TagName
		Optional parameter used to specify a Tag Name for which to query.
	
	.PARAMETER ThreatID
		Optional parameter used to list all tags linked to a specific Threat ID.

	.EXAMPLE
		Get-TCTags
		
	.EXAMPLE
		Get-TCTags -AdversaryID 123456
		
	.EXAMPLE
		Get-TCTags -EmailID "123456"
		
	.EXAMPLE
		Get-TCTags -IncidentID "123456"
		
	.EXAMPLE
		Get-TCTags -SignatureID "123456"
		
	.EXAMPLE
		Get-TCTags -TagName "BadStuff"
		
	.EXAMPLE
		Get-TCTags -ThreatID "123456"
		
	#>
	[CmdletBinding(DefaultParameterSetName='Default')]Param(
		[Parameter(Mandatory=$False,ParameterSetName='Default')]
		[Parameter(Mandatory=$False,ParameterSetName='TagName')]
			[ValidateNotNullOrEmpty()][String]$Owner,
		[Parameter(Mandatory=$True,ParameterSetName='AdversaryID')]
			[ValidateNotNullOrEmpty()][String]$AdversaryID,
		[Parameter(Mandatory=$True,ParameterSetName='EmailID')]
			[ValidateNotNullOrEmpty()][String]$EmailID,
		[Parameter(Mandatory=$True,ParameterSetName='IncidentID')]
			[ValidateNotNullOrEmpty()][String]$IncidentID,
		[Parameter(Mandatory=$True,ParameterSetName='SignatureID')]
			[ValidateNotNullOrEmpty()][String]$SignatureID,
		[Parameter(Mandatory=$True,ParameterSetName='TagName')]
			[ValidateNotNullOrEmpty()][String]$TagName,
		[Parameter(Mandatory=$True,ParameterSetName='ThreatID')]
			[ValidateNotNullOrEmpty()][String]$ThreatID
	)
	
	# Construct the Child URL based on the Parameter Set that was chosen
	switch ($PSCmdlet.ParameterSetName) {
		"AdversaryID" {
			$APIChildURL = "/v2/groups/adversaries/" + $AdversaryID + "/tags"
		}
		
		"EmailID" {
			$APIChildURL = "/v2/groups/emails/" + $EmailID + "/tags"
		}
		
		"IncidentID" {
			$APIChildURL = "/v2/groups/incidents/" + $IncidentID + "/tags"
		}
		
		"SignatureID" {
			$APIChildURL = "/v2/groups/signatures/" + $SignatureID + "/tags"
		}
		
		"TagName" {
			# Need to escape the URI in case there are any spaces or special characters
			$TagName = Get-EscapedURIString -String $TagName
			$APIChildURL = "/v2/tags/" + $TagName
		}
		
		"ThreatID" {
			$APIChildURL = "/v2/groups/threats/" + $ThreatID + "/tags"
		}
		
		Default {
			# Use this if nothing else is specified
			$APIChildURL ="/v2/tags"
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
		$Response.data.tag
	} else {
		Write-Error "API Request failed with the following error:`n $($Response.Status)"
	}
}

function Get-TCVictims {
	<#
	.SYNOPSIS
		Gets a list of victims from Threat Connect.  Default is all victims for the API Key's organization
		
	.PARAMETER Owner
		Optional Parameter to define a specific Community (or other "Owner") from which to retrieve victims.
		This switch can be used alongside the other switches.
	
	.PARAMETER AdversaryID
		Optional parameter used to list all victims linked to a specific Adversary ID.
		
	.PARAMETER EmailID
		Optional parameter used to list all victims linked to a specific Email ID.
		
	.PARAMETER IncidentID
		Optional parameter used to list all victims linked to a specific Incident ID.
		
	.PARAMETER SignatureID
		Optional parameter used to list all victims linked to a specific Signature ID.
	
	.PARAMETER ThreatID
		Optional parameter used to list all victims linked to a specific Threat ID.
	
	.PARAMETER VictimID
		Optional parameter used to list a specific victim.

	.EXAMPLE
		Get-TCVictims
		
	.EXAMPLE
		Get-TCVictims -AdversaryID 123456
		
	.EXAMPLE
		Get-TCVictims -EmailID "123456"
		
	.EXAMPLE
		Get-TCVictims -IncidentID "123456"
		
	.EXAMPLE
		Get-TCVictims -SignatureID "123456"
		
	.EXAMPLE
		Get-TCVictims -ThreatID "123456"
		
	#>
	[CmdletBinding(DefaultParameterSetName='Default')]Param(
		[Parameter(Mandatory=$False,ParameterSetName='Default')]
			[ValidateNotNullOrEmpty()][String]$Owner,
		[Parameter(Mandatory=$True,ParameterSetName='AdversaryID')]
			[ValidateNotNullOrEmpty()][String]$AdversaryID,
		[Parameter(Mandatory=$True,ParameterSetName='EmailID')]
			[ValidateNotNullOrEmpty()][String]$EmailID,
		[Parameter(Mandatory=$True,ParameterSetName='IncidentID')]
			[ValidateNotNullOrEmpty()][String]$IncidentID,
		[Parameter(Mandatory=$True,ParameterSetName='SignatureID')]
			[ValidateNotNullOrEmpty()][String]$SignatureID,
		[Parameter(Mandatory=$True,ParameterSetName='ThreatID')]
			[ValidateNotNullOrEmpty()][String]$ThreatID,
		[Parameter(Mandatory=$True,ParameterSetName='VictimID')]
			[ValidateNotNullOrEmpty()][String]$VictimID
	)
	
	# Construct the Child URL based on the Parameter Set that was chosen
	switch ($PSCmdlet.ParameterSetName) {
		"AdversaryID" {
			$APIChildURL = "/v2/groups/adversaries/" + $AdversaryID + "/victims"
		}
		
		"EmailID" {
			$APIChildURL = "/v2/groups/emails/" + $EmailID + "/victims"
		}
		
		"IncidentID" {
			$APIChildURL = "/v2/groups/incidents/" + $IncidentID + "/victims"
		}
		
		"SignatureID" {
			$APIChildURL = "/v2/groups/signatures/" + $SignatureID + "/victims"
		}
		
		"ThreatID" {
			$APIChildURL = "/v2/groups/threats/" + $ThreatID + "/victims"
		}
		
		"VictimID" {
			$APIChildURL = "/v2/victims/" + $VictimID
		}
		
		Default {
			# Use this if nothing else is specified
			$APIChildURL ="/v2/victims"
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
		$Response.data.victim
	} else {
		Write-Error "API Request failed with the following error:`n $($Response.Status)"
	}
}


