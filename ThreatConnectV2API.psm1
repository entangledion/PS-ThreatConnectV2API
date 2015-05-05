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
		
	.PARAMETER IndicatorType
		Optional paramter used to list all owners linked to a specific Indicator.  IndicatorType could be Host, EmailAddress, File, Address, or URL.
		Must be used along with the Indicator parameter.
		
	.PARAMETER Indicator
		Optional paramter used to list all owners linked to a specific Indicator.
		Must be used along with the IndicatorType parameter.
	
	.EXAMPLE
		Get-TCOwners
		
	.EXAMPLE
		Get-TCOwners -IndicatorType Address -Indicator "127.0.0.1"
	
	.EXAMPLE
		Get-TCOwners -IndicatorType EmailAddress -Indicator "test@baddomain.com"
	
	.EXAMPLE
		Get-TCOwners -IndicatorType File -Indicator "d41d8cd98f00b204e9800998ecf8427e"
	
	.EXAMPLE
		Get-TCOwners -IndicatorType Host -Indicator "baddomain.com"
	
	.EXAMPLE
		Get-TCOwners -IndicatorType URL -Indicator "http://baddomain.com/phishies"
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
		This switch can be used alongside some of the other switches.
	
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
		
	.PARAMETER IndicatorType
		Optional paramter used to list all groups linked to a specific Indicator.  IndicatorType could be Host, EmailAddress, File, Address, or URL.
		Must be used along with the Indicator parameter.
		
	.PARAMETER Indicator
		Optional paramter used to list all groups linked to a specific Indicator.
		Must be used along with the IndicatorType parameter.

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
	
	.EXAMPLE
		Get-TCGroups -IndicatorType Address -Indicator "127.0.0.1"
	
	.EXAMPLE
		Get-TCGroups -IndicatorType EmailAddress -Indicator "test@baddomain.com"
	
	.EXAMPLE
		Get-TCGroups -IndicatorType File -Indicator "d41d8cd98f00b204e9800998ecf8427e"
	
	.EXAMPLE
		Get-TCGroups -IndicatorType Host -Indicator "baddomain.com"
	
	.EXAMPLE
		Get-TCGroups -IndicatorType URL -Indicator "http://baddomain.com/phishies"
	#>
	[CmdletBinding(DefaultParameterSetName='Default')]Param(
		[Parameter(Mandatory=$False,ParameterSetName='Default')]
		[Parameter(Mandatory=$False,ParameterSetName='Indicator')]
		[Parameter(Mandatory=$False,ParameterSetName='SecurityLabel')]
		[Parameter(Mandatory=$False,ParameterSetName='TagName')]
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
			$APIChildURL = "/v2/groups/adversaries/" + $AdversaryID + "/groups"
		}
		
		"EmailID" {
			$APIChildURL = "/v2/groups/emails/" + $EmailID + "/groups"
		}
		
		"IncidentID" {
			$APIChildURL = "/v2/groups/incidents/" + $IncidentID + "/groups"
		}
		
		"Indicator" {
			# Craft Indicator Child URL based on Indicator Type
			switch ($IndicatorType) {
				"Address" {
					$APIChildURL = "/v2/indicators/addresses/" + $Indicator + "/groups"
				}
				"EmailAddress" {
					$APIChildURL = "/v2/indicators/emailAddresses/" + $Indicator + "/groups"
				}
				"File" {
					$APIChildURL = "/v2/indicators/files/" + $Indicator + "/groups"
				}
				"Host" {
					$APIChildURL = "/v2/indicators/hosts/" + $Indicator + "/groups"
				}
				"URL" {
					# URLs need to be converted to a friendly format first
					$Indicator = Get-EscapedURIString -String $Indicator
					$APIChildURL = "/v2/indicators/urls/" + $Indicator + "/groups"
				}
			}
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
		This switch can be used alongside some of the other switches.
	
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
		Get-TCAdversaries -IndicatorType URL -Indicator "http://baddomain.com/phishies"
	#>
	[CmdletBinding(DefaultParameterSetName='Default')]Param(
		[Parameter(Mandatory=$False,ParameterSetName='Default')]
		[Parameter(Mandatory=$False,ParameterSetName='Indicator')]
		[Parameter(Mandatory=$False,ParameterSetName='SecurityLabel')]
		[Parameter(Mandatory=$False,ParameterSetName='TagName')]
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
		This switch can be used alongside some of the other switches.
	
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
	
	.PARAMETER IndicatorType
		Optional paramter used to list all emails linked to a specific Indicator.  IndicatorType could be Host, EmailAddress, File, Address, or URL.
		Must be used along with the Indicator parameter.
		
	.PARAMETER Indicator
		Optional paramter used to list all emails linked to a specific Indicator.
		Must be used along with the IndicatorType parameter.

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
	
	.EXAMPLE
		Get-TCEmails -IndicatorType Address -Indicator "127.0.0.1"
	
	.EXAMPLE
		Get-TCEmails -IndicatorType EmailAddress -Indicator "test@baddomain.com"
	
	.EXAMPLE
		Get-TCEmails -IndicatorType File -Indicator "d41d8cd98f00b204e9800998ecf8427e"
	
	.EXAMPLE
		Get-TCEmails -IndicatorType Host -Indicator "baddomain.com"
	
	.EXAMPLE
		Get-TCEmails -IndicatorType URL -Indicator "http://baddomain.com/phishies"
	#>
	[CmdletBinding(DefaultParameterSetName='Default')]Param(
		[Parameter(Mandatory=$False,ParameterSetName='Default')]
		[Parameter(Mandatory=$False,ParameterSetName='Indicator')]
		[Parameter(Mandatory=$False,ParameterSetName='SecurityLabel')]
		[Parameter(Mandatory=$False,ParameterSetName='TagName')]
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
			$APIChildURL = "/v2/groups/adversaries/" + $AdversaryID + "/groups/emails"
		}
		
		"EmailID" {
			$APIChildURL = "/v2/groups/emails/" + $EmailID
		}
		
		"IncidentID" {
			$APIChildURL = "/v2/groups/incidents/" + $IncidentID + "/groups/emails"
		}
		
		"Indicator" {
			# Craft Indicator Child URL based on Indicator Type
			switch ($IndicatorType) {
				"Address" {
					$APIChildURL = "/v2/indicators/addresses/" + $Indicator + "/groups/emails"
				}
				"EmailAddress" {
					$APIChildURL = "/v2/indicators/emailAddresses/" + $Indicator + "/groups/emails"
				}
				"File" {
					$APIChildURL = "/v2/indicators/files/" + $Indicator + "/groups/emails"
				}
				"Host" {
					$APIChildURL = "/v2/indicators/hosts/" + $Indicator + "/groups/emails"
				}
				"URL" {
					# URLs need to be converted to a friendly format first
					$Indicator = Get-EscapedURIString -String $Indicator
					$APIChildURL = "/v2/indicators/urls/" + $Indicator + "/groups/emails"
				}
			}
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
		This switch can be used alongside some of the other switches.
	
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
		
	.PARAMETER IndicatorType
		Optional paramter used to list all incidents linked to a specific Indicator.  IndicatorType could be Host, EmailAddress, File, Address, or URL.
		Must be used along with the Indicator parameter.
		
	.PARAMETER Indicator
		Optional paramter used to list all incidents linked to a specific Indicator.
		Must be used along with the IndicatorType parameter.

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
		
	.EXAMPLE
		Get-TCIncidents -IndicatorType Address -Indicator "127.0.0.1"
	
	.EXAMPLE
		Get-TCIncidents -IndicatorType EmailAddress -Indicator "test@baddomain.com"
	
	.EXAMPLE
		Get-TCIncidents -IndicatorType File -Indicator "d41d8cd98f00b204e9800998ecf8427e"
	
	.EXAMPLE
		Get-TCIncidents -IndicatorType Host -Indicator "baddomain.com"
	
	.EXAMPLE
		Get-TCIncidents -IndicatorType URL -Indicator "http://baddomain.com/phishies"
	#>
	[CmdletBinding(DefaultParameterSetName='Default')]Param(
		[Parameter(Mandatory=$False,ParameterSetName='Default')]
		[Parameter(Mandatory=$False,ParameterSetName='Indicator')]
		[Parameter(Mandatory=$False,ParameterSetName='SecurityLabel')]
		[Parameter(Mandatory=$False,ParameterSetName='TagName')]
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
			$APIChildURL = "/v2/groups/adversaries/" + $AdversaryID + "/groups/incidents"
		}
		
		"EmailID" {
			$APIChildURL = "/v2/groups/emails/" + $EmailID + "/groups/incidents"
		}
		
		"IncidentID" {
			$APIChildURL = "/v2/groups/incidents/" + $IncidentID
		}
		
		"Indicator" {
			# Craft Indicator Child URL based on Indicator Type
			switch ($IndicatorType) {
				"Address" {
					$APIChildURL = "/v2/indicators/addresses/" + $Indicator + "/groups/incidents"
				}
				"EmailAddress" {
					$APIChildURL = "/v2/indicators/emailAddresses/" + $Indicator + "/groups/incidents"
				}
				"File" {
					$APIChildURL = "/v2/indicators/files/" + $Indicator + "/groups/incidents"
				}
				"Host" {
					$APIChildURL = "/v2/indicators/hosts/" + $Indicator + "/groups/incidents"
				}
				"URL" {
					# URLs need to be converted to a friendly format first
					$Indicator = Get-EscapedURIString -String $Indicator
					$APIChildURL = "/v2/indicators/urls/" + $Indicator + "/groups/incidents"
				}
			}
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
		This switch can be used alongside some of the other switches.
	
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
	
	.PARAMETER Download
		Optional parameter used in conjunction with SignatureID parameter that specifies to download the signature's content.
	
	.PARAMETER TagName
		Optional parameter used to list all signatures with a specific Tag.
	
	.PARAMETER ThreatID
		Optional parameter used to list all signatures linked to a specific Threat ID.
	
	.PARAMETER VictimID
		Optional parameter used to list all signatures linked to a specific Victim ID.
	
	.PARAMETER IndicatorType
		Optional paramter used to list all signatures linked to a specific Indicator.  IndicatorType could be Host, EmailAddress, File, Address, or URL.
		Must be used along with the Indicator parameter.
		
	.PARAMETER Indicator
		Optional paramter used to list all signatures linked to a specific Indicator.
		Must be used along with the IndicatorType parameter.

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
		Get-TCSignatures -SignatureID "123456" -Download
		
	.EXAMPLE
		Get-TCSignatures -TagName "BadStuff"
		
	.EXAMPLE
		Get-TCSignatures -ThreatID "123456"
		
	.EXAMPLE
		Get-TCSignatures -VictimID "123456"
	
	.EXAMPLE
		Get-TCSignatures -IndicatorType Address -Indicator "127.0.0.1"
	
	.EXAMPLE
		Get-TCSignatures -IndicatorType EmailAddress -Indicator "test@baddomain.com"
	
	.EXAMPLE
		Get-TCSignatures -IndicatorType File -Indicator "d41d8cd98f00b204e9800998ecf8427e"
	
	.EXAMPLE
		Get-TCSignatures -IndicatorType Host -Indicator "baddomain.com"
	
	.EXAMPLE
		Get-TCSignatures -IndicatorType URL -Indicator "http://baddomain.com/phishies"
	#>
	[CmdletBinding(DefaultParameterSetName='Default')]Param(
		[Parameter(Mandatory=$False,ParameterSetName='Default')]
		[Parameter(Mandatory=$False,ParameterSetName='Indicator')]
		[Parameter(Mandatory=$False,ParameterSetName='SecurityLabel')]
		[Parameter(Mandatory=$False,ParameterSetName='TagName')]
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
		[Parameter(Mandatory=$True,ParameterSetName='SignatureDownload')]
			[ValidateNotNullOrEmpty()][String]$SignatureID,
		[Parameter(Mandatory=$True,ParameterSetName='SignatureDownload')]
			[ValidateNotNull()][Switch]$Download,
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
		
		"Indicator" {
			# Craft Indicator Child URL based on Indicator Type
			switch ($IndicatorType) {
				"Address" {
					$APIChildURL = "/v2/indicators/addresses/" + $Indicator + "/groups/signatures"
				}
				"EmailAddress" {
					$APIChildURL = "/v2/indicators/emailAddresses/" + $Indicator + "/groups/signatures"
				}
				"File" {
					$APIChildURL = "/v2/indicators/files/" + $Indicator + "/groups/signatures"
				}
				"Host" {
					$APIChildURL = "/v2/indicators/hosts/" + $Indicator + "/groups/signatures"
				}
				"URL" {
					# URLs need to be converted to a friendly format first
					$Indicator = Get-EscapedURIString -String $Indicator
					$APIChildURL = "/v2/indicators/urls/" + $Indicator + "/groups/signatures"
				}
			}
		}
		
		"SecurityLabel" {
			# Need to escape the URI in case there are any spaces or special characters
			$SecurityLabel = Get-EscapedURIString -String $SecurityLabel
			$APIChildURL = "/v2/securityLabels/" + $SecurityLabel + "/groups/signatures"
		}
		
		"SignatureDownload" {
			$APIChildURL = "/v2/groups/signatures/" + $SignatureID + "/download"
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
		This switch can be used alongside some of the other switches.
	
	.PARAMETER AdversaryID
		Optional parameter used to list all threats linked to a specific Adversary ID.
		
	.PARAMETER EmailID
		Optional parameter used to list all threats linked to a specific Email ID.
		
	.PARAMETER IncidentID
		Optional parameter used to list all threats linked to a specific Incident ID.
		
	.PARAMETER IndicatorType
		Optional paramter used to list all threats linked to a specific Indicator.  IndicatorType could be Host, EmailAddress, File, Address, or URL.
		Must be used along with the Indicator parameter.
		
	.PARAMETER Indicator
		Optional paramter used to list all threats linked to a specific Indicator.
		Must be used along with the IndicatorType parameter.
		
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
		
	.EXAMPLE
		Get-TCThreats -IndicatorType Address -Indicator "127.0.0.1"
	
	.EXAMPLE
		Get-TCThreats -IndicatorType EmailAddress -Indicator "test@baddomain.com"
	
	.EXAMPLE
		Get-TCThreats -IndicatorType File -Indicator "d41d8cd98f00b204e9800998ecf8427e"
	
	.EXAMPLE
		Get-TCThreats -IndicatorType Host -Indicator "baddomain.com"
	
	.EXAMPLE
		Get-TCThreats -IndicatorType URL -Indicator "http://baddomain.com/phishies"
	#>
	[CmdletBinding(DefaultParameterSetName='Default')]Param(
		[Parameter(Mandatory=$False,ParameterSetName='Default')]
		[Parameter(Mandatory=$False,ParameterSetName='Indicator')]
		[Parameter(Mandatory=$False,ParameterSetName='SecurityLabel')]
		[Parameter(Mandatory=$False,ParameterSetName='TagName')]
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
			$APIChildURL = "/v2/groups/adversaries/" + $AdversaryID + "/groups/threats"
		}
		
		"EmailID" {
			$APIChildURL = "/v2/groups/emails/" + $EmailID + "/groups/threats"
		}
		
		"IncidentID" {
			$APIChildURL = "/v2/groups/incidents/" + $IncidentID + "/groups/threats"
		}
		
		"Indicator" {
			# Craft Indicator Child URL based on Indicator Type
			switch ($IndicatorType) {
				"Address" {
					$APIChildURL = "/v2/indicators/addresses/" + $Indicator + "/groups/threats"
				}
				"EmailAddress" {
					$APIChildURL = "/v2/indicators/emailAddresses/" + $Indicator + "/groups/threats"
				}
				"File" {
					$APIChildURL = "/v2/indicators/files/" + $Indicator + "/groups/threats"
				}
				"Host" {
					$APIChildURL = "/v2/indicators/hosts/" + $Indicator + "/groups/threats"
				}
				"URL" {
					# URLs need to be converted to a friendly format first
					$Indicator = Get-EscapedURIString -String $Indicator
					$APIChildURL = "/v2/indicators/urls/" + $Indicator + "/groups/threats"
				}
			}
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
	
	.PARAMETER Owner
		Optional Parameter to define a specific Community (or other "Owner") from which to retrieve attributes.
		This switch can be used alongside some of the other switches.
		
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
		
	.EXAMPLE
		Get-TCAttributes -IndicatorType Address -Indicator "127.0.0.1"
	
	.EXAMPLE
		Get-TCAttributes -IndicatorType EmailAddress -Indicator "test@baddomain.com"
	
	.EXAMPLE
		Get-TCAttributes -IndicatorType File -Indicator "d41d8cd98f00b204e9800998ecf8427e"
	
	.EXAMPLE
		Get-TCAttributes -IndicatorType Host -Indicator "baddomain.com"
	
	.EXAMPLE
		Get-TCAttributes -IndicatorType URL -Indicator "http://baddomain.com/phishies"
	#>
	[CmdletBinding()]Param(
		[Parameter(Mandatory=$False,ParameterSetName='Indicator')]
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
			$APIChildURL = "/v2/groups/signatures/" + $AdversaryID + "/attributes"
		}
		
		"ThreatID" { 
			$APIChildURL = "/v2/groups/threats/" + $AdversaryID + "/attributes"
		}
	}
	
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
		This switch can be used alongside some of the other switches.
	
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
	
	.PARAMETER IndicatorType
		Optional paramter used to list all security labels linked to a specific Indicator.  IndicatorType could be Host, EmailAddress, File, Address, or URL.
		Must be used along with the Indicator parameter.
		
	.PARAMETER Indicator
		Optional paramter used to list all security labels linked to a specific Indicator.
		Must be used along with the IndicatorType parameter.

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
	
	.EXAMPLE
		Get-TCSecurityLabels -IndicatorType Address -Indicator "127.0.0.1"
	
	.EXAMPLE
		Get-TCSecurityLabels -IndicatorType EmailAddress -Indicator "test@baddomain.com"
	
	.EXAMPLE
		Get-TCSecurityLabels -IndicatorType File -Indicator "d41d8cd98f00b204e9800998ecf8427e"
	
	.EXAMPLE
		Get-TCSecurityLabels -IndicatorType Host -Indicator "baddomain.com"
	
	.EXAMPLE
		Get-TCSecurityLabels -IndicatorType URL -Indicator "http://baddomain.com/phishies"
		
	#>
	[CmdletBinding(DefaultParameterSetName='Default')]Param(
		[Parameter(Mandatory=$False,ParameterSetName='Default')]
		[Parameter(Mandatory=$False,ParameterSetName='Indicator')]
		[Parameter(Mandatory=$False,ParameterSetName='SecurityLabel')]
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
		
		"Indicator" {
			# Craft Indicator Child URL based on Indicator Type
			switch ($IndicatorType) {
				"Address" {
					$APIChildURL = "/v2/indicators/addresses/" + $Indicator + "/securityLabels"
				}
				"EmailAddress" {
					$APIChildURL = "/v2/indicators/emailAddresses/" + $Indicator + "/securityLabels"
				}
				"File" {
					$APIChildURL = "/v2/indicators/files/" + $Indicator + "/securityLabels"
				}
				"Host" {
					$APIChildURL = "/v2/indicators/hosts/" + $Indicator + "/securityLabels"
				}
				"URL" {
					# URLs need to be converted to a friendly format first
					$Indicator = Get-EscapedURIString -String $Indicator
					$APIChildURL = "/v2/indicators/urls/" + $Indicator + "/securityLabels"
				}
			}
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
		This switch can be used alongside some of the other switches.
	
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
		
	.PARAMETER IndicatorType
		Optional paramter used to list all tags linked to a specific Indicator.  IndicatorType could be Host, EmailAddress, File, Address, or URL.
		Must be used along with the Indicator parameter.
		
	.PARAMETER Indicator
		Optional paramter used to list all tags linked to a specific Indicator.
		Must be used along with the IndicatorType parameter.

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
		
	.EXAMPLE
		Get-TCTags -IndicatorType Address -Indicator "127.0.0.1"
	
	.EXAMPLE
		Get-TCTags -IndicatorType EmailAddress -Indicator "test@baddomain.com"
	
	.EXAMPLE
		Get-TCTags -IndicatorType File -Indicator "d41d8cd98f00b204e9800998ecf8427e"
	
	.EXAMPLE
		Get-TCTags -IndicatorType Host -Indicator "baddomain.com"
	
	.EXAMPLE
		Get-TCTags -IndicatorType URL -Indicator "http://baddomain.com/phishies"
		
	#>
	[CmdletBinding(DefaultParameterSetName='Default')]Param(
		[Parameter(Mandatory=$False,ParameterSetName='Default')]
		[Parameter(Mandatory=$False,ParameterSetName='Indicator')]
		[Parameter(Mandatory=$False,ParameterSetName='TagName')]
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
		
		"Indicator" {
			# Craft Indicator Child URL based on Indicator Type
			switch ($IndicatorType) {
				"Address" {
					$APIChildURL = "/v2/indicators/addresses/" + $Indicator + "/tags"
				}
				"EmailAddress" {
					$APIChildURL = "/v2/indicators/emailAddresses/" + $Indicator + "/tags"
				}
				"File" {
					$APIChildURL = "/v2/indicators/files/" + $Indicator + "/tags"
				}
				"Host" {
					$APIChildURL = "/v2/indicators/hosts/" + $Indicator + "/tags"
				}
				"URL" {
					# URLs need to be converted to a friendly format first
					$Indicator = Get-EscapedURIString -String $Indicator
					$APIChildURL = "/v2/indicators/urls/" + $Indicator + "/tags"
				}
			}
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
		This switch can be used alongside some of the other switches.
	
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
	
	.PARAMETER IndicatorType
		Optional paramter used to list all victims linked to a specific Indicator.  IndicatorType could be Host, EmailAddress, File, Address, or URL.
		Must be used along with the Indicator parameter.
		
	.PARAMETER Indicator
		Optional paramter used to list all victims linked to a specific Indicator.
		Must be used along with the IndicatorType parameter.

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
		
	.EXAMPLE
		Get-TCVictims -IndicatorType Address -Indicator "127.0.0.1"
	
	.EXAMPLE
		Get-TCVictims -IndicatorType EmailAddress -Indicator "test@baddomain.com"
	
	.EXAMPLE
		Get-TCVictims -IndicatorType File -Indicator "d41d8cd98f00b204e9800998ecf8427e"
	
	.EXAMPLE
		Get-TCVictims -IndicatorType Host -Indicator "baddomain.com"
	
	.EXAMPLE
		Get-TCVictims -IndicatorType URL -Indicator "http://baddomain.com/phishies"
		
	#>
	[CmdletBinding(DefaultParameterSetName='Default')]Param(
		[Parameter(Mandatory=$False,ParameterSetName='Default')]
		[Parameter(Mandatory=$False,ParameterSetName='Indicator')]
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
		
		"Indicator" {
			# Craft Indicator Child URL based on Indicator Type
			switch ($IndicatorType) {
				"Address" {
					$APIChildURL = "/v2/indicators/addresses/" + $Indicator + "/victims"
				}
				"EmailAddress" {
					$APIChildURL = "/v2/indicators/emailAddresses/" + $Indicator + "/victims"
				}
				"File" {
					$APIChildURL = "/v2/indicators/files/" + $Indicator + "/victims"
				}
				"Host" {
					$APIChildURL = "/v2/indicators/hosts/" + $Indicator + "/victims"
				}
				"URL" {
					# URLs need to be converted to a friendly format first
					$Indicator = Get-EscapedURIString -String $Indicator
					$APIChildURL = "/v2/indicators/urls/" + $Indicator + "/victims"
				}
			}
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

function Get-TCIndicators {
	<#
	.SYNOPSIS
		Gets a list of indicators from Threat Connect.  Default is all indicators for the API Key's organization
		
	.PARAMETER Owner
		Optional Parameter to define a specific Community (or other "Owner") from which to retrieve indicators.
		This switch can be used alongside some of the other switches.
	
	.PARAMETER AdversaryID
		Optional parameter used to list all indicators linked to a specific Adversary ID.
		
	.PARAMETER EmailID
		Optional parameter used to list all indicators linked to a specific Email ID.
		
	.PARAMETER IncidentID
		Optional parameter used to list all indicators linked to a specific Incident ID.
		
	.PARAMETER SecurityLabel
		Optional parameter used to list all indicators with a specific Security Label.
		
	.PARAMETER SignatureID
		Optional parameter used to list all indicators linked to a specific Signature ID.
	
	.PARAMETER TagName
		Optional parameter used to list all indicators with a specific Tag.
	
	.PARAMETER ThreatID
		Optional parameter used to list all indicators linked to a specific Threat ID.
	
	.PARAMETER VictimID
		Optional parameter used to list all indicators linked to a specific Victim ID.
		
	.PARAMETER IndicatorType
		Optional paramter used to list all indicators of a certain type.  IndicatorType could be Host, EmailAddress, File, Address, or URL.
		This parameter can be used alongside many of the other switches.
	
	.EXAMPLE
		Get-TCIndicators
		
	.EXAMPLE
		Get-TCIndicators -AdversaryID 123456
		
	.EXAMPLE
		Get-TCIndicators -EmailID "123456"
		
	.EXAMPLE
		Get-TCIndicators -IncidentID "123456"
	
	.EXAMPLE
		Get-TCIndicators -SecurityLabel "Confidential"
		
	.EXAMPLE
		Get-TCIndicators -SignatureID "123456"
		
	.EXAMPLE
		Get-TCIndicators -TagName "BadStuff"
		
	.EXAMPLE
		Get-TCIndicators -ThreatID "123456"
		
	.EXAMPLE
		Get-TCIndicators -VictimID "123456"
	#>
	[CmdletBinding(DefaultParameterSetName='Default')]Param(
		[Parameter(Mandatory=$False,ParameterSetName='Default')]
		[Parameter(Mandatory=$False,ParameterSetName='SecurityLabel')]
		[Parameter(Mandatory=$False,ParameterSetName='TagName')]
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
			$APIChildURL = "/v2/groups/adversaries/" + $AdversaryID + "/indicators"
		}
		
		"EmailID" {
			$APIChildURL = "/v2/groups/emails/" + $EmailID + "/indicators"
		}
		
		"IncidentID" {
			$APIChildURL = "/v2/groups/incidents/" + $IncidentID + "/indicators"
		}
		
		"SecurityLabel" {
			# Need to escape the URI in case there are any spaces or special characters
			$SecurityLabel = Get-EscapedURIString -String $SecurityLabel
			$APIChildURL = "/v2/securityLabels/" + $SecurityLabel + "/indicators"
		}
		
		"SignatureID" {
			$APIChildURL = "/v2/groups/signatures/" + $SignatureID + "/indicators"
		}
		
		"TagName" {
			# Need to escape the URI in case there are any spaces or special characters
			$TagName = Get-EscapedURIString -String $TagName
			$APIChildURL = "/v2/tags/" + $TagName + "/indicators"		
		}
		
		"ThreatID" {
			$APIChildURL = "/v2/groups/threats/" + $ThreatID + "/indicators"
		}
		
		"VictimID" {
			$APIChildURL = "/v2/victims/" + $VictimID + "/indicators"
		}
		
		Default {
			# Use this if nothing else is specified
			$APIChildURL ="/v2/indicators"
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
		$Response.data.indicator
	} else {
		Write-Error "API Request failed with the following error:`n $($Response.Status)"
	}
}

