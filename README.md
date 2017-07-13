# Cleanup-SnapShots
Given a vRops server or list of vCenters and proper credentials, script will inspect all vcenter for snapshots in a given time range.  If the snapshot is older than minimum age, it will report on it.  If it is older than the max age, it will delete it.  Once complete, the report will be emailed to the snapshot owners and other specified smtp addresses in the email config file.

# Copyright
Copyright 2017 Comcast Cable Communications Management, LLC

# License
Licensed under the Apache License, verison 2.0 (the "License"). See LICENSE file in the project root for full license information.

# Requirements
  - PowerCli - Tested with v6.5
  - vRops - Tested with v6.
  - vSphere/vCenter - tested with v5.5
  - PowerShell - Tested with v5.1
  - XML credenitals file created with desired credentials
	  - $credential = Get-Credential
	  - $credential | Export-Clixml vmbalance_cred.xml
  - Run As Admin
  
# Requirements:
	- PowerCli - Tested with v6.5
	- vSphere/vCenter - tested with v5.5
	- PowerShell - Tested with v5.1
	- XML credenitals file created with desired credentials
		- $credential = Get-Credential
		- $credential | Export-Clixml vmbalance_cred.xml
	- Run As Admin

# Optional:
	- vRops - Tested with v6.5

# Parameters
  - vCenterSource
	- Description:  Specify the vRops server or an input file containing the vCenters.
	- Required: TRUE
	- Type:  String
	- Default Value:  $null

  - CredentialPath
	- Description:  Looking for the path to the XML file with credenital for vRops and vCenter
	- Required:  TRUE
	- Type:  String
	- Default Value:  $null

  - LogFilePath
	- Description:  Specify a path for the log file, if not specified it will go to Logs in the directory script is executed from.
	- Required:  FALSE
	- Type:  String
	- Default Value:  $null
	
  - ReportFilePath
	- Description:  Specify a path for the log file, if not specified it will go to Logs in the directory script is executed from.
	- Required:  FALSE
	- Type:  String
	- Default Value:  $null

  - VCExclustionList
	 - Description:  Text file of vCenters that are to be excluded from process.
	 - Required:  FALSE
	 - Type:  String
	 - Default Value:  $null

  - VMExclusionList
	- Description:  Text file of vm names to be excluded from process.
	- Required:  FALSE
	- Type:  String
	- Default Value:  $null

  - ReportDaysOlder
	- Description:  Specify the age in days to report on snapshots that are older.
	- Required:  TRUE
	- Type:  Int
	- Default Value:  $null
	
  - DeleteDaysOlder
	- Description:  Specify the age in days to delete snapshots that are older.
	- Required:  FALSE
	- Type:  Int
	- Default Value:  $null
	
  - EmailConfigFile
	- Description:  Configuration file for information to be used in the email that gets sent out.
	- Required:  FALSE
	- Type:  String
	- Default Value:  $null
	
  - SlackURL
	- Description:  Specify the URL of the webhook app you setup in Slack if you would like to get notifications in a slack channel.
	- Required:  FALSE
	- Type:  String
	- Default Value:  $null

  - RemoveChildren
	- Description:  To be used with DeleteDaysOlder.  If switch is used it will delete ALL child snapshots of snapshots older than DeleteDaysOlder specified.
	- Required:  FALSE
	- Type:  Switch
	- Default Value:  $false

  - NoDelete
	- Description:  To run through entire script, but skip the delete part.
	- Required:  FALSE
	- Type:  Switch
	- Default Value:  $false

  - Interactive
	- Description:  To run script and write all log entries to the screen.
	- Required:  FALSE
	- Type:  Switch
	- Default Value:  $false

# Usage
- Example:
  - Testmode and Interactive:
  	- Cleanup-SnapShots.ps1 -vCenterSource vrops.server.com -CredentialPath snapshot_cred.xml -ReportDaysOlder 1 -DeleteDaysOlder 5 -RemoveChildren -VCExclusionList vcexclusionlist.txt -VMExclusionList vmexclusionlist.txt -EmailConfigFile emailconfig.txt -Interactive -NoDelete
  - Normal Mode:
  	- Cleanup-SnapShots.ps1 -vCenterSource vrops.server.com -CredentialPath snapshot_cred.xml -ReportDaysOlder 1 -DeleteDaysOlder 5 -RemoveChildren -VCExclusionList vcexclusionlist.txt -VMExclusionList vmexclusionlist.txt -EmailConfigFile emailconfig.txt

# Logging
A log file of all actions will be created in a Log directory in the same directory where the script is executed from.

# Alerting
Script will send error alerts and script complete/summary messages to the a webhook enabled slack channel if specified in the input parameters.

# Release Notes

