<#
.SYNOPSIS
Given a vRops server or list of vCenters and proper credentials, script will inspect all vcenter for snapshots in
a given time range.  If the snapshot is older than minimum age, it will report on it.  If it is older than the max
age, it will delete it.  Once complete, the report will be emailed to the snapshot owners and other specified
smtp addresses in the email config file.

.DESCRIPTION
Report on and delete old snapshots in vcenters.

.PARAMETER vCenterSource
Specify the vRops server or an input file containing the vCenters.

.PARAMETER CredentialPath
Looking for the path to the XML file with credenital for vRops and vCenter.

.PARAMETER ReportDaysOlder
Specify the age in days to report on snapshots that are older.

.PARAMETER DeleteDaysOlder
Specify the age in days to delete snapshots that are older.

.PARAMETER RemoveChildren
To be used with DeleteDaysOlder.  If switch is used it will delete ALL child snapshots of snapshots older than DeleteDaysOlder specified.

.PARAMETER LogFilePath
Specify a path for the log file, if not specified it will go to Logs in the directory script is executed from.

.PARAMETER ReportFilePath
Specify a path for the report file, if not specified it will go to Reports in the directory script is executed from.

.PARAMETER VCExclusionList
Text file of vCenters that are to be excluded from process.

.PARAMETER VMExclusionList
Text file of VM names to be excluded from process.

.PARAMETER EmailConfigFile
Configuration file for information to be used in the email that gets sent out.

.PARAMETER SlackURL
Specify the URL of the webhook app you setup in Slack if you would like to get notifications in a slack channel

.PARAMETER NoDelete
To run through entire script, but skip the delete snapshot function and only report that it would have been deleted.

.PARAMETER Interactive
To run script and write all log entries to the screen.

.EXAMPLE
Cleanup-SnapShots.ps1 -vCenterSource C:\Temp\SnapShotCleanup\vcs.txt -CredentialPath .\snapshot_cred.xml -ReportDaysOlder 3 -DeleteDaysOlder 14 -VMExclusionList .\vmexclusionlist.txt -EmailConfigFile .\emailconfig.txt -NoDelete -Interactive

.EXAMPLE
Cleanup-SnapShots.ps1 -vCenterSource vrops.yourdomain.com -CredentialPath .\snapshot_cred.xml -ReportDaysOlder 3 -DeleteDaysOlder 14

.NOTES
AUTHOR: Tim Kalligonis, Comcast
DATE  : 6/29/2017
Version: 1.0
=================================================================================
Copyright 2017 Comcast Cable Communications Management, LLC
=================================================================================
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
=================================================================================
Requirements:
	1.  PowerCli - Tested with v6.5
	3.  vSphere/vCenter - tested with v5.5
	4.  PowerShell - Tested with v5.1
	5.  XML credenitals file created with desired credentials
		ie.: 	$credential = Get-Credential
			$credential | Export-Clixml vmbalance_cred.xml
	6.  Run As Admin

Optional:
	1.  vRops - Tested with v6.5
=================================================================================	
Modifications:
Version X.X(increment by # of changes) - <Date MM/DD/YYYY> - <Name of Modifier> - <Description of changes>

#>
param(
	[Parameter(Mandatory=$true)][String] $vCenterSource = $null,
	[Parameter(Mandatory=$true)][String] $CredentialPath = $null,
	[Parameter(Mandatory=$true)][int] $ReportDaysOlder = $null,
	[Parameter(Mandatory=$false)][ValidateScript({$_ -gt $ReportDaysOlder})] [int] $DeleteDaysOlder = $null,
	[Parameter(Mandatory=$false)][switch]$RemoveChildren,
	[Parameter(Mandatory=$false)][String] $LogFilePath = $null,
	[Parameter(Mandatory=$false)][String] $ReportFilePath = $null,
	[Parameter(Mandatory=$false)][String] $VCExclusionList = $null,
	[Parameter(Mandatory=$false)][String] $VMExclusionList = $null,
	[Parameter(Mandatory=$false)][String] $EmailConfigFile = $null,
	[Parameter(Mandatory=$false)][String] $SlackURL = $null,
	[switch] $NoDelete,
	[switch] $Interactive
)

function global:Test-Administrator
{
	# =================================================================================
	# Function to check if PS is running as Admin
	# =================================================================================
	
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)  
}

function global:Create-LogFile
{
	# =================================================================================
	# Function to create a global log file for event logging
	# =================================================================================
	
	Param (
		[Parameter(Mandatory=$false)][String] $LogPath = $null
	)
	
	# Create a log file and put it in the same directory specified in the input file path.
	$timestamp = "{0:yyyyMMdd-hhmmssfff}" -f (get-date)
	$time = "{0:yyyy-MM-dd hh:mm:ss.fff}" -f (get-date)

	if ($LogPath){
		$LogFilePath = $LogPath.trimend('\')
	}
	else{
		$LogFilePath = Split-Path -Parent $PSCommandPath
	}
	
	if( -Not (Test-Path -Path "$LogFilePath\Logs\")){
		New-Item -ItemType directory -Path "$LogFilePath\Logs\" | Out-Null
	}
		
	$global:logfile = "$LogFilePath\Logs\SnapShotManagement-$timestamp.log"
	
	Get-Date | %{"[$_]`: Logfile Created" | Out-File $logfile -Append}
}

function global:Create-ReportFile
{
	# =================================================================================
	# Function to create a Report File for snapshots
	# =================================================================================
	
	Param (
		[Parameter(Mandatory=$false)][String] $ReportPath = $null
	)
	
	# Create a log file and put it in the same directory specified in the input file path.
	$timestamp = "{0:yyyyMMdd-hhmmssfff}" -f (get-date)
	$time = "{0:yyyy-MM-dd hh:mm:ss.fff}" -f (get-date)

	if ($ReportPath){
		$ReportFilePath = $ReportPath.trimend('\')
	}
	else{
		$ReportFilePath = Split-Path -Parent $PSCommandPath
	}
	
	if( -Not (Test-Path -Path "$ReportFilePath\Reports\")){
		New-Item -ItemType directory -Path "$ReportFilePath\Reports\" | Out-Null
	}
		
	$global:ReportFile = "$ReportFilePath\Reports\SnapShotManagement-$timestamp.csv"
}

function global:Post-Message
{
	# =================================================================================
	# Function to post messages to screen and/or log files
	# =================================================================================
	
	Param (
		[Parameter(Mandatory=$true)][String] $Message,
		[Parameter(Mandatory=$false)][String] $Color = "white",
		[Parameter(Mandatory=$false)][String] $WriteToLog = $null,
		[Parameter(ParameterSetName='Slack',Mandatory=$false)][String] $SlackWebHook = $null,
		[Parameter(ParameterSetName='Slack',Mandatory=$false)][String] $SlackCriticality = $null,
		[Parameter(Mandatory=$false)][Boolean] $Interactive = $false,
		[switch] $Quit
	)
	
  	# Write message to screen
	if ($Interactive){
		Write-Host $Message -ForegroundColor $Color
	}
	
	# Write message to logfile if true
	if ($WriteToLog){
		Get-Date | %{"[$_]`: $message" | Out-File $WriteToLog -Append}
	}
	
	# Write message to Slack if true
	if($SlackWebHook){ PostTo-Slack -webhook $SlackWebHook -notification $Message -criticality $SlackCriticality}
	
	# Break out of the script if true
	if ($quit){
		Post-Message -Message "Processing Complete - ERROR - Terminating Script" -Color red -WriteToLog $logfile -SlackWebHook $SlackURL -SlackCriticality "critical" -Interactive $Interactive
		Clear-Variable logfile -Scope Global
		break
	}
}

function global:PostTo-Slack
{
# Function to post messages to Steel Cloud Sink Slack channel
	Param (
		[Parameter(Mandatory=$true)][String] $webhook,
		[Parameter(Mandatory=$true)][String] $notification,
		[Parameter(Mandatory=$true)][String] $criticality
	)
	
	# Given the notification, post the message to the appropriate Slack Channel
	# Escape out characters that create problems when posting the notifications
	$notification = $notification -replace '[[+*?()\\]','\$&' 

	# Criticality can be one of the following values "Critical, Warning, OK"
	# If any other value is provided for criticality, it will default to Warning
	if (@('critical','warning','ok') -notcontains $criticality) { $criticality = 'warning' }

	# Displaying the notification as a block with appropriate coloring for criticality
	$color_choices = @{'critical' = '#ff0000'; 'warning' = '#ffa500'; 'ok' = '#00ff00'}
	$slackpost_color = $color_choices.get_item($criticality)

	# Collect the scriptname and host running it is for posting so that it can aid in troubleshooting
	$hostname = $env:computername
	$scriptname = $(($MyInvocation.ScriptName).Split("\"))[-1]
	$username = $env:username

	# Format the Slack message to post in the channel
	$slack_payload = '{ "attachments":[{"fallback":"' + $scriptname + ' (' + $hostname + '): Message from ' + $username + ' - ' + $notification + '","color":"' + $slackpost_color + '","fields":[{ "value":"' + $scriptname + ' (' + $hostname + '): Message from ' + $username + ' - ' + $notification + '" }]}] }'
		
	try {
		# Post to Slack
		$response = Invoke-WebRequest -UseBasicParsing -Uri $webhook -Method "POST" -Body $slack_payload -ErrorAction SilentlyContinue
		Post-Message -Message "`tPOST to Slack succeeded" -Color green -Interactive $Interactive
	}
	catch {
		Post-Message -Message "`tPOST to Slack failed with HTTP Response Code $($_.Exception.Response.StatusCode.Value__)" -Color red -Interactive $Interactive
	}
}

function global:Prepare-VMware
{
	# =================================================================================
	# Function loads the VMware module
	# =================================================================================
		
	$modulename = "vmware.vimautomation.core"
	Post-Message -Message "Preparing for vSphere connectivity - importing module $($modulename)" -WriteToLog $logfile -Interactive $Interactive
	
	if (Get-Module -ListAvailable -Name $modulename) {
		#Import necessary VMware snap-in
        try{
        	Import-Module $modulename -ErrorAction Stop
        }
        catch{
        	Post-Message -Message "  ERROR:  Unable to import module $modulename" -Color red -WriteToLog $logfile -SlackWebHook $SlackURL -SlackCriticality "critical" -Interactive $Interactive -Quit
		}
		
		#Remove the FailoverClusters module if it is loaded to prevent conflict with VMware cmdlets
		Remove-Module -Name FailoverClusters -ErrorAction SilentlyContinue
	
		# Set the PowerCli Configuration to ignore the warning about the cert
		Set-PowerCLIConfiguration -InvalidCertificateAction ignore -Confirm:$false | Out-Null
		
		# Set the PowerCli Configuration to Single Deafult VI Server Mode - otherwise script will fail on the hardware checks
		Set-PowerCLIConfiguration -DefaultVIServerMode single -Confirm:$false | Out-Null
	}
	else{
		# Module did not load
		# Log something and exit script
		Post-Message -Message "  ERROR:  Unable to import module $modulename" -Color red -WriteToLog $logfile -SlackWebHook $SlackURL -SlackCriticality "critical" -Interactive $Interactive -Quit
	}
}

function global:Prepare-VRops
{
	# =================================================================================
	# Function loads the VRops module
	# =================================================================================
	
	$modulename = "vmware.vimautomation.vrops"
	Post-Message -Message "Preparing for vRops connectivity - importing module $($modulename)" -WriteToLog $logfile -Interactive $Interactive
	#Load necessary VMware snap-in, but if the PowerCLI terminal is being used, need to continue gracefully.
	
	if (Get-Module -ListAvailable -Name $modulename) {
		#Import necessary VMware snap-in
        try{
        	Import-Module $modulename -ErrorAction Stop
        }
        catch{
        	Post-Message -Message "  ERROR:  Unable to import module $modulename" -Color red -WriteToLog $logfile -SlackWebHook $SlackURL -SlackCriticality "critical" -Interactive $Interactive -Quit
		}
	}
	else{
		# Module did not load
		# Log something and exit script
		Post-Message -Message "  ERROR:  Unable to import module $modulename" -Color red -WriteToLog $logfile -SlackWebHook $SlackURL -SlackCriticality "critical" -Interactive $Interactive -Quit
	}
}

function global:Connect-VRops
{
	Param (
		[Parameter(Mandatory=$true)][String] $vRopsServer,
		[Parameter(Mandatory=$true)][PSCredential] $Credential
		
	)
	
	Post-Message -Message "`tConnecting to vRops" -WriteToLog $logfile -Interactive $Interactive
	try{
		Connect-OMServer -Server $vRopsServer -Credential $Credential -ErrorAction Stop | Out-Null
	}
	catch {
		Post-Message -Message "`tERROR: Connect-VRops $($vRopsServer): $($error[0])" -Color red -WriteToLog $logfile -SlackWebHook $SlackURL -SlackCriticality "critical" -Interactive $Interactive -Quit
	} # catch
}

function global:Connect-VCenter
{
	# =================================================================================
	# Function to connect to vcenter, checks for existing session
	# =================================================================================

	Param (
		[Parameter(Mandatory=$true)][String] $vcenter,
		[Parameter(Mandatory=$true)][PSCredential] $Credential
	)
 
  	try {
		Post-Message -Message "`tConnecting to VCenter $vcenter" -Color white -Interactive $Interactive
		$vcsession = ($global:DefaultVIServers | Where-Object -FilterScript {$_.name -eq $vcenter})
		$sessionID = $vcsession.sessionId
		$sessionState = $vcsession.IsConnected
		
		# If there is an existing session for give vCenter, use it.
		if (($SessionID) -and ($SessionState)) { 
			#Post-Message -Message "`tFound an active existing session for $vcenter. Attempting to connect using sessionID" -Color green -WriteToLog $logfile -Interactive $Interactive
			Connect-VIServer $vcenter -Session $sessionID -ErrorAction Stop | Out-Null
			#Post-Message -Message "`tSUCCESS: Connection to $vcenter successful using sessionID" -Color green -WriteToLog $logfile -Interactive $Interactive
		} # if
		# Else create a new session
		else {
			#Post-Message -Message "`tCreating a new session for $vcenter" -Color green -WriteToLog $logfile -Interactive $Interactive
			Connect-VIServer $vcenter -Credential $Credential -ErrorAction Stop | Out-Null
			#Post-Message -Message "`tSUCCESS: Connection to $vcenter successful" -Color green -WriteToLog $logfile -Interactive $Interactive
		} # else
	} # try
	catch {
		Post-Message -Message "`tERROR: ConnectTo-VCenter $($vcenter): $($error[0])" -Color red -WriteToLog $logfile -SlackWebHook $SlackURL -SlackCriticality "critical" -Interactive $Interactive
		Post-Message -Message "`tSkipping to next item" -Color red -WriteToLog $logfile -Interactive $Interactive
		# Failed to connect to vCenter, move on to next one in the loop
		continue
	} # catch
}

function global:Get-vCenters
{
	# =================================================================================
	# Function to create an array of vcenters to process based on vrops url or file
	# path location input
	# =================================================================================

	Param (
		[Parameter(Mandatory=$true)][String] $vCenterSource,
		[Parameter(Mandatory=$true)][PSCredential] $Credential
	)
	
	Post-Message -Message "Collecting vCenters to process" -WriteToLog $logfile -Interactive $Interactive
	
	# Determine if input file or vRops FQDN is the vCenter source and get the info
	[System.Collections.ArrayList]$vCenters = @()
	try{
		Resolve-DnsName $vCenterSource -ErrorAction Stop | Out-Null
		#vRops is the source - prep and connect
		Prepare-VRops
		try{
			Connect-VRops -vRopsServer $vCenterSource -Credential $Credential -ErrorAction Stop
		
			$vRopsVCenters = Get-OMResource -ResourceKind "VMwareAdapter Instance"
		
			foreach($vRopsVC in $vRopsVCenters){
				if($vRopsVC.name.substring(0,3) -eq "vc_"){
					$vcenter = $vRopsVC.name.Substring(3,$vRopsVC.name.Length-3)
					if($vcenter.tolower() -notin $VCExclude){
						$vCenters += $vcenter
					}
					else{
						Post-Message -Message "`t$($vcenter) excluded - on exclusion list" -WriteToLog $logfile -Interactive $Interactive
					}
				}
			}
		}
		catch{
			Post-Message -Message "  ERROR:  Failed to connect to vRops $($vCenterSource)" -Color red -WriteToLog $logfile -SlackWebHook $SlackURL -SlackCriticality "critical" -Interactive $Interactive -Quit
		}	
	}
	catch{
		#must be a file input
		if(Test-Path $vCenterSource){
			#good path get the list of vcenters
						
			$filevCenters = Get-Content $vCenterSource
			foreach($fileVC in $filevCenters){
				if($fileVC.tolower() -notin $VCExclude){
					$vCenters += $fileVC
				}
				else{
					Post-Message -Message "  $($fileVC) excluded - on exclusion list" -WriteToLog $logfile -Interactive $Interactive
				}
			}
		}
		else{
			#not a valid path/input file, fail and quit
			Post-Message -Message "  ERROR:  Invalid vRops or File input path" -Color red -WriteToLog $logfile -SlackWebHook $SlackURL -SlackCriticality "critical" -Interactive $Interactive -Quit
		}
	}
	return $vCenters
}

function global:Find-User
{
   	# =================================================================================
	# Function will retrieve displayname and e-mail address from AD of snapshot creator
	# account based on his "NT-style" username (domain\login).
	# =================================================================================

	Param (
		[Parameter(Mandatory=$true)][String] $username
	)
	
	if ($username -ne $null){
      $login = (($username.split("\"))[1])
      $adsi_searcher = [adsisearcher]"(samaccountname=$login)"
      $userinfo = New-Object PSObject
      $userinfo | Add-Member -Name "email" -Value $adsi_searcher.FindOne().Properties.mail -MemberType NoteProperty
      $userinfo | Add-Member -Name "name" -Value $adsi_searcher.FindOne().Properties.displayname -MemberType NoteProperty
      return $userinfo 
   }
}

function global:Get-MailConfig
{
	# =================================================================================
	# Function to take mail config input file to collect data Send-MailMessage cmdlet
	# =================================================================================

	Param (
		[Parameter(Mandatory=$true)][Array] $MailConfigFile
	)
	# Required Parameters
	[string]$global:FromEmail = $null
	[string]$global:SmtpServer = $null
	[string]$global:Subject = $null
	[System.Collections.ArrayList]$global:To = @()
	
	#Optional Parameters
	[System.Collections.ArrayList]$global:Attachments = @()
	[System.Collections.ArrayList]$global:Bcc = @()
	[string]$global:Body = @()
	[System.Collections.ArrayList]$global:Cc = @()
	[string]$global:DeliveryNotification = "None"
	[string]$global:Encoding = "ASCII"
	[string]$global:Priority = "Normal"
	[int32]$global:Port = 25
	
	Post-Message -Message "Collecting Email Configuration Information" -WriteToLog $logfile -Interactive $Interactive
	
	$MailFile = Get-Content $MailConfigFile | ?{$_ -notlike '#*'}
	
	foreach($Line in $MailFile){
		$SplitLine = $Line -split '=',2
		if($SplitLine[1]){
			switch ($SplitLine[0].tolower()){
				"from" {
					if($SplitLine[1] -like "*@*.*"){
						$global:FromEmail = $SplitLine[1]
					}
					else{
						Post-Message -Message "  WARNING:  $($SplitLine[1]) is an invalid email address" -Color yellow -WriteToLog $logfile -SlackWebHook $SlackURL -SlackCriticality "warning" -Interactive $Interactive
					}	
				}
				
				"smtpserver" {
					if(Test-Connection $SplitLine[1] -quiet){
						$global:SmtpServer = $SplitLine[1]
					}
					else{
						Post-Message -Message "  WARNING:  $($SplitLine[1]) is an invalid SMTP Server" -Color yellow -WriteToLog $logfile -SlackWebHook $SlackURL -SlackCriticality "warning" -Interactive $Interactive
					}
				}
				
				"subject" {$global:Subject = $SplitLine[1]}
				
				"to" {
					if($SplitLine[1] -like "*@*.*"){
						$global:To.Add($SplitLine[1]) | Out-Null
					}
					else{
						Post-Message -Message "  WARNING:  $($SplitLine[1]) is an invalid email address" -Color yellow -WriteToLog $logfile -SlackWebHook $SlackURL -SlackCriticality "warning" -Interactive $Interactive
					}	
				}
				
				"attachments" {
					$global:Attachments.Add($SplitLine[1]) | Out-Null
				}
				
				"bcc" {
					if($SplitLine[1] -like "*@*.*"){
						$global:Bcc.Add($SplitLine[1]) | Out-Null
					}
					else{
						Post-Message -Message "  WARNING:  $($SplitLine[1]) is an invalid email address" -Color yellow -WriteToLog $logfile -SlackWebHook $SlackURL -SlackCriticality "warning" -Interactive $Interactive
					}
				}
				
				"body" {
					if($SplitLine[1] -eq "CRLF"){
						$global:Body:Body += "`r`n"
					}
					else{
						$global:Body += $SplitLine[1]
					}
				}
				
				"cc" {
					if($SplitLine[1] -like "*@*.*"){
						$global:Cc.Add($SplitLine[1]) | Out-Null
					}
					else{
						Post-Message -Message "  WARNING:  $($SplitLine[1]) is an invalid email address" -Color yellow -WriteToLog $logfile -SlackWebHook $SlackURL -SlackCriticality "warning" -Interactive $Interactive
					}	
				}
				
				"deliverynotificationoption" {$global:DeliveryNotification = $SplitLine[1]}
				
				"encoding" {$global:Encoding = $SplitLine[1]}
				
				"priority" {$global:Priority = $SplitLine[1]}
				
				"port" {$global:Port = $SplitLine[1]}

				default {
					#log an invalid parameter entered
					Post-Message -Message "  WARNING:  $($SplitLine[0]) is an invalid mail parameter" -Color yellow -WriteToLog $logfile -SlackWebHook $SlackURL -SlackCriticality "warning" -Interactive $Interactive
				}
			}
		}
	}
	if(($FromEmail) -and ($SmtpServer) -and ($Subject) -and ($To)){
		return $true
	}
	else{
		Post-Message -Message "  ERROR:  Invalid email configuration provided.  Email will not be sent." -Color red -WriteToLog $logfile -SlackWebHook $SlackURL -SlackCriticality "critical" -Interactive $Interactive
		return $false
	}
}

# ======================================================================================
# Script body
# ======================================================================================
# If any thing in this section fails, break from script, nothing else will work correctly.

# Variables
$AllSnapsInfo = @()
$SendMail = $false
$EventAge = 0
$now = Get-Date

Create-LogFile -LogPath $LogFilePath
Create-ReportFile -ReportPath $ReportFilePath
Post-Message -Message "$($MyInvocation.MyCommand.name) has Started" -WriteToLog $logfile -Interactive $Interactive -SlackWebHook $SlackURL -SlackCriticality "ok"

if (!(Test-Administrator)){
	# Log that its not running as admin and exit script
	Post-Message -Message "  ERROR:  $($PSCommandPath) not running as Admin on $($env:computername)" -Color red -WriteToLog $logfile -SlackWebHook $SlackURL -SlackCriticality "critical" -Interactive $Interactive -Quit
}

Post-Message -Message "Obtaining credentials for processing" -WriteToLog $logfile -Interactive $Interactive
$Credential = Import-Clixml -Path $CredentialPath
if (!($Credential.username) -or !($Credential.password)){
	# Log that creds for vcenter and vrops not available
	Post-Message -Message "  ERROR:  Missing credentials for vcenter" -Color red -WriteToLog $logfile -SlackWebHook $SlackURL -SlackCriticality "critical" -Interactive $Interactive -Quit
}

Post-Message -Message "Reviewing vCenter exclusion list" -WriteToLog $logfile -Interactive $Interactive
if($VCExclusionList){ $VCExclude = (Get-Content $VCExclusionList | ?{$_ -notlike '#*'}).tolower()}

Post-Message -Message "Reviewing VM exclusion list" -WriteToLog $logfile -Interactive $Interactive
if($VMExclusionList){ $VMExclude = (Get-Content $VMExclusionList | ?{$_ -notlike '#*'}).tolower()}

# Collect the mail information
if ($EmailConfigFile){
	$SendMail = Get-MailConfig -MailConfigFile $EmailConfigFile
}

$vCenters = Get-vCenters -vCenterSource $vCenterSource -Credential $Credential
Prepare-VMware

# If failure occurs from here, don't break from script.  Log and skip to next in the loop.

#Walk Through array of vCenters
Post-Message -Message "Looping through each vCenter" -WriteToLog $logfile -Interactive $Interactive
$snapSummary = "`r`nSummary of VM SnapShots`r`n"

foreach($vc in $vCenters){
	Connect-VCenter -Vcenter $vc -Credential $Credential
    
 	$EventAge = get-advancedsetting -Entity $vc -Server $vc -name "event.maxAge"
 	$SnapShots = get-view -ViewType VirtualMachine -Filter @{"snapshot" = ""} -Property Name | % {get-vm -id $_.MoRef | get-snapshot}
	
	if (($SnapShots | measure).count){
		Post-Message -Message "`tLooping through snapshots on $($vc)" -WriteToLog $logfile -Interactive $Interactive
		#for each of snapshots found - create helper object for the report.
		foreach ($SnapShot in $SnapShots){
			# Skip snapshot if it is on the exclusion list
			$notfound=$true
			Post-Message -Message "`tSnapshot for: $($SnapShot.VM.name)" -WriteToLog $logfile -Interactive $Interactive
			foreach($vmx in $VMExclude){
				if($SnapShot.VM.name.tolower() -like $vmx){
					$notfound=$false
					Post-Message -Message "`t`tExcluding $($SnapShot.VM.name) - on the vm exclusion list " -WriteToLog $logfile -Interactive $Interactive
				}
			}
			# not on exclusion list
			if ($notfound){
				$SnapAge = $now - $SnapShot.Created
				Post-Message -Message "`t`t$($SnapShot.name) - $("{0:N1}" -f $SnapAge.TotalDays) days old" -WriteToLog $logfile -Interactive $Interactive
				# if the snapshot over x (specified) days old
				if ($SnapAge.TotalDays -gt $ReportDaysOlder){
				
					$SnapShotInfo = New-Object PSObject
					$SnapShotInfo | Add-Member -Name "CleanupStatus" -Value "Reporting" -MemberType NoteProperty
					$SnapShotInfo | Add-Member -Name "vCenter" -Value $vc -MemberType NoteProperty
					$SnapShotInfo | Add-Member -Name "VMName" -Value $($SnapShot.VM).name -MemberType NoteProperty
					$SnapShotInfo | Add-Member -Name "SnapshotName" -Value $SnapShot.name -MemberType NoteProperty
					$VmInfo = Get-VM $SnapShot.VM.name
					$SnapShotInfo | Add-Member -Name "OSType" -Value $VmInfo.extensiondata.guest.GuestFullName -MemberType NoteProperty
					$SnapShotInfo | Add-Member -Name "SizeGB" -Value $("{0:N2}" -f ($SnapShot.SizeGB)) -MemberType NoteProperty
					$SnapShotInfo | Add-Member -Name "CreatedTime" -Value $($SnapShot.Created.ToString("yyyy-MM-dd@HH:mm:ss")) -MemberType NoteProperty
		
					$SearchStartTime = $SnapShot.Created.AddMinutes(-10)
					
					$SnapShotInfo | Add-Member -Name "AgeInDays" -Value $("{0:N2}" -f $SnapAge.TotalDays) -MemberType NoteProperty
					
					$snapSummary += "`t$($SnapShot.VM) - $($SnapShot.name) - $("{0:N1}" -f $SnapAge.TotalDays) days old`r`n"
					
					#search event database for snapshot creator, use time window from -10 minutes before snapshot creation timestamp up to 20 minutes past this timestamp.
					if ($SnapAge.TotalDays -lt $EventAge.value){
						$SearchFinishTime = $SearchStartTime.AddMinutes(20)
						$CreationEvents = Get-VIEvent -Entity $SnapShot.VM -Start $SearchStartTime -Finish $SearchFinishTime -Type Info | where-object {$_.FullFormattedMessage.contains("Create virtual machine snapshot")}
						try {
							$user = $CreationEvents[0].UserName
						} catch [System.Exception] {
							$user = $CreationEvents.UserName
						}
						$SnapShotInfo | Add-Member -Name "CreatorLogin" -Value $user -MemberType NoteProperty
						if($user){
							$UserInfo = Find-User($user)
						}
						$SnapShotInfo | Add-Member -Name "CreatorName" -Value $($UserInfo.name) -MemberType NoteProperty
						$SnapShotInfo | Add-Member -Name "CreatorEMail" -Value $($UserInfo.email) -MemberType NoteProperty
						
						if(($UserInfo.email) -and ($SendMail)){
							if($UserInfo.email -notin $global:To){
								$global:To += $UserInfo.email
							}
						}
					}
					else {
						$SnapShotInfo | Add-Member -Name "CreatorLogin" -Value "Snapshot older than $($EventAge.Value)" -MemberType NoteProperty
						$SnapShotInfo | Add-Member -Name "CreatorName" -Value "No Data Available" -MemberType NoteProperty
						$SnapShotInfo | Add-Member -Name "CreatorEMail" -Value "No Data Available" -MemberType NoteProperty
					}
					if ($DeleteDaysOlder){
						if ($SnapAge.TotalDays -gt $DeleteDaysOlder){
							Post-Message -Message "`t`t$($SnapShot.name) - Greater than specified delete age of $DeleteDaysOlder" -WriteToLog $logfile -Interactive $Interactive
							if ($NoDelete){
								$SnapShotInfo."CleanupStatus" = "Would be Deleted - Delete Action Disabled"
								Post-Message -Message "`t`t$($SnapShot.name) - NOT deleted - Delete Action Disabled" -WriteToLog $logfile -Interactive $Interactive
								$snapSummary += "`t$($SnapShot.VM) - $($SnapShot.name) - $("{0:N1}" -f $SnapAge.TotalDays) days old - Would be Deleted - Delete Action Disabled`r`n"
							}
							else{
								try{
									if($RemoveChildren){
										$SnapShot | Remove-Snapshot -RemoveChildren -Confirm:$false -ErrorAction SilentlyContinue
										Post-Message -Message "`t`t$($SnapShot.name) deleted and all child snapshots" -WriteToLog $logfile -Interactive $Interactive
										$snapSummary += "`t$($SnapShot.VM) - $($SnapShot.name) - $("{0:N1}" -f $SnapAge.TotalDays) days old - Deleted and Children Deleted`r`n"
										$SnapShotInfo."CleanupStatus" = "Deleted and Children Deleted"
									}
									else{
										$SnapShot | Remove-Snapshot -Confirm:$false -ErrorAction SilentlyContinue
										Post-Message -Message "`t`t$($SnapShot.name) deleted" -WriteToLog $logfile -Interactive $Interactive
										$snapSummary += "`t$($SnapShot.VM) - $($SnapShot.name) - $("{0:N1}" -f $SnapAge.TotalDays) days old - Deleted`r`n"
										$SnapShotInfo."CleanupStatus" = "Deleted"
									}
								}
								catch{
									Post-Message -Message "`t`tERROR: Unable to Delete snapshot for $($SnapShot.VM.name): $($error[0])" -Color red -WriteToLog $logfile -SlackWebHook $SlackURL -SlackCriticality "critical" -Interactive $Interactive
								}
							}
						}
					}
					$AllSnapsInfo += $SnapShotInfo
				} #if greater then 6
			} #if not on exclusion list
		} #for each snapshot
	} #if there are snapshots
} # foreach($vc in $vCenter)

$AllSnapsInfo | Sort-Object -Property vCenter | Export-Csv -Path $ReportFile -NoTypeInformation
$global:Attachments += $ReportFile

if($SendMail){
	[string]$SendMailCmd = @()
	$SendMailCmd += 'Send-MailMessage -SmtpServer $global:SmtpServer -From $global:FromEmail -To $global:To -Subject $global:Subject -DeliveryNotificationOption $global:DeliveryNotification -Encoding $global:Encoding -Port $global:Port -Priority $global:Priority -BodyAsHtml'
	if ($global:Attachments){$SendMailCmd += ' -Attachments $global:Attachments'}
	if ($global:Cc){$SendMailCmd += ' -Cc $global:Cc'}
	if ($global:Bcc){$SendMailCmd += ' -Bcc $global:Bcc'}
	if ($global:Body){$SendMailCmd += ' -Body $global:Body'}
	
	$MailError = (Invoke-Expression $SendMailCmd) 2>&1
	if($MailError){
		Post-Message -Message "ERROR: Problem sending email: $($MailError)" -WriteToLog $logfile -Interactive $Interactive -SlackWebHook $SlackURL -SlackCriticality "warning" -Color red
	}
	else{
		Post-Message -Message "Successfully sent email" -WriteToLog $logfile -Interactive $Interactive
	}	
}
$snapSummary += "Snapshot Management Complete"
Post-Message -Message "$($snapSummary)" -WriteToLog $logfile -Interactive $Interactive -SlackWebHook $SlackURL -SlackCriticality "ok"
