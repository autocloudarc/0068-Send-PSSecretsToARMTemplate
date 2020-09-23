#requires -version 5.1
#requires -RunAsAdministrator

using Namespace System.Net # for TLS1.2 update

<#
.SYNOPSIS
Demonstrates how to use to the secureObject JSON type when passing secrets from a PowerShell script.

.DESCRIPTION
This script will create a simple Azure resource group deployment to demonstrate how to use the JSON ARM template secureObject type when passing sensitive strings to an ARM template.
Ensure that you are running at least PowerShell 5.1 and running this script in the context of an administrator.

.PARAMETER PSModuleRepository
The module repository used to get required Az submodules, which is 'PSGallery' by default.

.PARAMETER demoSecureObject
Switch to select the secure object scenario.

.PARAMETER secObjTemplateFile
The ARM Template file to deploy from this PowerShell script for the secure object scenario.

.PARAMETER demoSecureString
Switch to select the secure string scenario.

.PARAMETER secStrTemplateFile
The ARM Template file to deploy from this PowerShell script for the secure string scenario.

.PARAMETER demoPlainTextString
Switch to select the plain-text string scenario.

.PARAMETER plnStrTemplateFile
The ARM Template file to deploy from this PowerShell script for the plain-text string scenario.

.EXAMPLE
.\Demo-PSSecretsToARMDeployment.ps1 -Verbose

.INPUTS
$adminUserName : User name for building VMs
$adminPassword : Password used along with username to build VMs
$region: Azure region
$rgpName: Resource Group Name

.OUTPUTS
The outputs generated from this script includes:
1. A transcript log file to provide the full details of script execution. It will use the name format: <ScriptName>-TRANSCRIPT-<Date-Time>.log
2. The output values of this deployment will also appear in the deployments blade of the resource group.

.NOTES
LEGAL DISCLAIMER:
This Sample Code is provided for the purpose of illustration only and is not intended to be used in a production environment. 
THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE. 
We grant You a nonexclusive, royalty-free right to use and modify the Sample Code and to reproduce and distribute the object code form of the Sample Code, provided that You agree:
(i) to not use Our name, logo, or trademarks to market Your software product in which the Sample Code is embedded;
(ii) to include a valid copyright notice on Your software product in which the Sample Code is embedded; and
(iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims or lawsuits, including attorneys' fees, that arise or result from the use or distribution of the Sample Code.
This posting is provided "AS IS" with no warranties, and confers no rights.

.LINK
1. https://docs.microsoft.com/en-us/azure/azure-resource-manager/templates/template-best-practices#parameters
2. https://gallery.technet.microsoft.com/scriptcenter/Get-StringHash-aa843f71

.COMPONENT
Azure Infrastructure, PowerShell, ARM, JSON

.ROLE
Automation Engineer
DevOps Engineer
Azure Engineer
Azure Administrator
Azure Architect

.FUNCTIONALITY
Demonstrates how to assemble and pass secrets securely using the secureObject JSON type
#>

[CmdletBinding()]
param
(
    [string]$PSModuleRepository = "PSGallery",
    [Parameter(Mandatory=$true)]
    [ValidateSet("secureObject","secureString","plainText")]
    [string]$scenario,
    [Parameter(ParameterSetName="SecureObject")]
    [string]$secObjTemplateFile = ".\demoSecureObject.json",
    [Parameter(ParameterSetName="SecureString")]
    [string]$secStrTemplateFile = ".\demoSecureString.json",
    [Parameter(ParameterSetName="PlainText")]
    [string]$plnStrTemplateFile = ".\demoPlainTextString.json"
) # end param

$adminUserName = "adm.infra.user"
#region TLS1.2
# Use TLS 1.2 to support Nuget provider
Write-Output "Configuring security protocol to use TLS 1.2 for Nuget support when installing modules." -Verbose
[ServicePointManager]::SecurityProtocol = [SecurityProtocolType]::Tls12
#endregion TLS1.2

#region MODULES
# Module repository setup and configuration
Set-PSRepository -Name $PSModuleRepository -InstallationPolicy Trusted -Verbose
Install-PackageProvider -Name Nuget -ForceBootstrap -Force

# Bootstrap dependent modules
$ARMDeployModule = "ARMDeploy"
if (Get-InstalledModule -Name $ARMDeployModule -ErrorAction SilentlyContinue)
{
    # If module exists, update it
    [string]$currentVersionADM = (Find-Module -Name $ARMDeployModule -Repository $PSModuleRepository).Version
    [string]$installedVersionADM = (Get-InstalledModule -Name $ARMDeployModule).Version
    If ($currentVersionADM -ne $installedVersionADM)
    {
            # Update modules if required
            Update-Module -Name $ARMDeployModule -Force -ErrorAction SilentlyContinue -Verbose
    } # end if
} # end if
# If the modules aren't already loaded, install and import it.
else
{
    Install-Module -Name $ARMDeployModule -Repository $PSModuleRepository -Force -Verbose
} #end If
Import-Module -Name $ARMDeployModule -Verbose
#endregion MODULES

#region functions
function New-ARMDeployTranscript
{
    [CmdletBinding()]
    [OutputType([string[]])]
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$LogDirectory,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$LogPrefix
    ) # end param

    # Get curent date and time
    $TimeStamp = (get-date -format u).Substring(0, 16)
    $TimeStamp = $TimeStamp.Replace(" ", "-")
    $TimeStamp = $TimeStamp.Replace(":", "")

    # Construct transcript file full path
    $TranscriptFile = "$LogPrefix-TRANSCRIPT" + "-" + $TimeStamp + ".log"
    $script:Transcript = Join-Path -Path $LogDirectory -ChildPath $TranscriptFile

    # Create log and transcript files
    New-Item -Path $Transcript -ItemType File -ErrorAction SilentlyContinue
} # end function
Function Get-StringHash
{
    # 1. http://jongurgul.com/blog/get-stringhash-get-filehash/
    # 2. https://gallery.technet.microsoft.com/scriptcenter/Get-StringHash-aa843f71
    param
    (
        [String]$StringToHash
    ) # end param
    $HashName = "SHA256"
    $StringBuilder = New-Object System.Text.StringBuilder
    [System.Security.Cryptography.HashAlgorithm]::Create($HashName).ComputeHash([System.Text.Encoding]::UTF8.GetBytes($StringToHash))| ForEach-Object {[Void]$StringBuilder.Append($_.ToString("x2"))}
    $StringBuilder.ToString()
} # end function

Function New-RandomString
{
 <#
.SYNOPSIS
Generates a random string of 12 characters based on specified criteria such as which character sets are required.

.DESCRIPTION
This function, New-RandomString.ps1, generates a fixed length string of 12 characters, consisting of a set of character types that you specify, such as uppercase, lowercase,
numbers and special characters. It is convenient to generate random strings multiple times from the same script, but with different character set combinations.
Some scenarios for which this function can be used includes; For passwords. In Azure, a minimum password length of 12 characters is required,
also Azure storage account names only accept lowercase and numeric characters, and Azure Site-To-Site VPN shared keys do not accept special characters.

.EXAMPLE
New-RandomString

.EXAMPLE
New-RandomString -IncludeUpper -IncludeLower -IncludeNumbers -IncludeSpecial

.PARAMETER -IncludeUpper
Include upper case letters. This parameter is an optional switch

.PARAMETER -IncludeLower
Include lower case letters. This parameter is an optional switch

.PARAMETER -IncludeNumbers
Include numeric characters. This parameter is an optional switch

.PARAMETER -IncludeSpecial
Include special characters. This parameter is an optional switch

.INPUTS
[int]
[boolean]

.OUTPUTS
[string]

.NOTES
NAME: New-RandomString

REQUIREMENTS:
-Version 5.1

AUTHOR: Preston K. Parsard

ATTRIBUTION:
NA

LASTEDIT: 20 SEP 2020

KEYWORDS: Random, String, Passwords, Complexity

LICENSE:
The MIT License (MIT)
Copyright (c) 2020 Preston K. Parsard

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

DISCLAIMER:
THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED,
INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.  We grant You a nonexclusive,
royalty-free right to use and modify the Sample Code and to reproduce and distribute the Sample Code, provided that You agree: (i) to not use Our name,
logo, or trademarks to market Your software product in which the Sample Code is embedded;
(ii) to include a valid copyright notice on Your software product in which the Sample Code is embedded; and (iii) to indemnify, hold harmless,
and defend Us and Our suppliers from and against any claims or lawsuits, including attorneys’ fees,
that arise or result from the use or distribution of the Sample Code.

.LINK
https://technet.microsoft.com/en-us/ms376608.aspx
#>

    [CmdletBinding(SupportsShouldProcess=$true,
  PositionalBinding=$false,
  HelpUri = 'https://gallery.technet.microsoft.com/scriptcenter',
  ConfirmImpact='Medium')]
 [OutputType([String])]
 Param
 (
  # Uppercase characters
  [switch] $IncludeUpper,

  # Lowercase characters
  [switch] $IncludeLower,

  # Numeric characters
  [switch] $IncludeNumbers,

  # Special characters
  [switch] $IncludeSpecial
 )

 # Lenth of random string
 [int]$StringLength = 12
 # Initialize array that will contain the custom combination of upper, lower, numeric and special complexity rules characters
 [string]$CharArray = @()
 # Initialize array of the default complexity rule set (uppercase, lowercase, numerical)
 [array]$RuleSets = @()
 # Initialize constructed string consisting of up to 12 characters, with characters from each of the 4 complexity rules
 [array]$StringArray = @()
 # The default number of samples taken from each of 3 complexity rules (Upper, Lower and Numeric) to construct the generated password string. SCR = String Complexity Rule.
 [int]$SampleCount = 0
 # Represents the combination of options selected: i.e. U = uppercase, L = lowercase, N = numeric and S = special. If all 4 options are selected, then the value of $Switches will be ULNS.
 [string]$Switches = $null

 # Alphabetic uppercase complexity rule
 $SCR1AlphaUpper = ([char[]]([char]65..[char]90))
 # Alphabetic lowercase complexity rule
 $SCR2AlphaLower = ([char[]]([char]97..[char]122))
 # Numeric complexity rule
 $SCR3Numeric = ([char[]]([char]48..[char]57))
 # Special characters complexity rule
 $SCR4Special = ([char[]]([char]33..[char]47)) + ([char[]]([char]58..[char]64)) + ([char[]]([char]92..[char]95)) + ([char[]]([char]123..[char]126))

 # Combine all complexity rules arrays into one consolidated array for all possible character values

 # Detect which switch parameters were used
 If ($IncludeUpper) { $Switches = "U" }
 If ($IncludeLower) { $Switches += "L" }
 If ($IncludeNumbers) { $Switches += "N" }
 If ($IncludeSpecial) { $Switches += "S" }

 If ($Switches.Length -gt 0)
 {
  # Calculate # of characters to sample per rule set
  [int]$SampleCount = $StringLength/($Switches.Length)
   Switch ($Switches)
   {
    # Alphabetic uppercase complexity rule
    {$_ -match 'U'}
    {
     Get-Random -InputObject $SCR1AlphaUpper -Count $SampleCount | ForEach-Object { $StringArrayU += $_ }
     $StringArray += $StringArrayU
    } #end -match

    # Alphabetic lowercase complexity rule
    {$_ -match 'L'}
    {
     Get-Random -InputObject $SCR2AlphaLower -Count $SampleCount | ForEach-Object { $StringArrayL += $_ }
    $StringArray += $StringArrayL
    } #end -match

    # Numeric complexity rule
    {$_ -match 'N'}
    {
     Get-Random -InputObject $SCR3Numeric -Count $SampleCount | ForEach-Object { $StringArrayN += $_ }
     $StringArray +=  $StringArrayN
    } #end -match

    # Special characters complexity rule
    {$_ -match 'S'}
    {
     Get-Random -InputObject $SCR4Special -Count $SampleCount | ForEach-Object { $StringArrayS += $_ }
     $StringArray +=  $StringArrayS
    } #end -match
   } #end Switch
 } #end If
 Else
 {
  # No options were specified
  [int]$SampleCount = 4
  [string]$CharArray = $SCR1AlphaUpper + $SCR2AlphaLower + $SCR3Numeric
  # Construct an array of 3 complexity rule sets
  [array]$RuleSets = ($SCR1AlphaUpper, $SCR2AlphaLower, $SCR3Numeric)
  # Generate a specified set of characters from each of the 4 complexity rule sets
  ForEach ($RuleSet in $RuleSets)
  {
   Get-Random -InputObject $RuleSet -Count $SampleCount | ForEach-Object { $StringArray += $_ }
  } #end ForEach
 } #end Else

 [string]$RandomStringWithSpaces = $StringArray
 $RandomString = $RandomStringWithSpaces.Replace(" ","")
 # Write-Host "`$Switches selected: $Switches"
 # Write-Host  "Randomly generated 12 character string: " $RandomString
 return $RandomString

} #end Function

#endregion functions

#region TRANSCRIPT
[string]$Transcript = $null
$scriptName = $MyInvocation.MyCommand.name
# Use script filename without exension as a log prefix
$LogPrefix = $scriptName.Split(".")[0]
$modulePath = "$env:systemdrive\Program Files\WindowsPowerShell\Modules"

$LogDirectory = Join-Path $modulePath -ChildPath $LogPrefix -Verbose
# Create log directory if not already present
If (-not(Test-Path -Path $LogDirectory -ErrorAction SilentlyContinue))
{
    New-Item -Path $LogDirectory -ItemType Directory -Verbose
} # end if

# funciton: Create log files for transcript
New-ARMDeployTranscript -LogDirectory $LogDirectory -LogPrefix $LogPrefix -Verbose

Start-Transcript -Path $Transcript -IncludeInvocationHeader -Verbose
#endregion TRANSCRIPT

#region Get required Az modules
$azurePreferredModule = @('Az.Accounts','Az.Resources')
Get-ARMDeployPSModule -ModulesToInstall $azurePreferredModule -PSRepository $PSModuleRepository -Verbose
#endregion Get required Az modules

#region HEADER
$label = "AUTOCLOUDARC PROJECT 0068: SEND SECRETS TO ARM TEMPLATES USING POWERSHELL"
$headerCharCount = 200
# function: Create new header
$header = New-ARMDeployHeader -label $label -charCount $headerCharCount -Verbose

Write-Output $header.SeparatorDouble  -Verbose
Write-Output $Header.Title  -Verbose
Write-Output $header.SeparatorSingle  -Verbose
#endregion HEADER

#region PATH
# Set script path
Write-Output "Changing path to script directory..." -Verbose
Set-Location -Path $PSScriptRoot -Verbose
Write-Output "Current directory has been changed to script root: $PSScriptRoot" -Verbose
#endregion PATH

#region Generate credentials
# https://pscustomobject.github.io/powershell/howto/PowerShell-Create-Credential-Object/

$pwPlainText = New-RandomString -IncludeUpper -IncludeLower -IncludeNumbers
$pwSecure = ConvertTo-SecureString -String $pwPlainText -AsPlainText -Force
$adminCred = [PSCredential]::New($adminUserName,$pwSecure)

$adminPassword = $adminCred.GetNetworkCredential().password
$hashedPw = Get-StringHash -StringToHash $adminPassword

Class CredClass
{
    [string]$userName = $adminUserName
    [string]$password = $adminPassword
    [string]$hash = $hashedPw
} # end class

$credObj = [CredClass]::new()

Write-Output "Credential object passed from the script: $scriptName to the ARM Template file: $templateDeploymentFile"
$credObj
#endregion Generate credentials

Write-Output "Please see the open dialogue box in your browser to authenticate to your Azure subscription..."

# Clear any possible cached credentials for other subscriptions
Clear-AzContext

# index 5.0: Authenticate to subscription
Connect-AzAccount -Environment AzureCloud

# https://docs.microsoft.com/en-us/azure/azure-government/documentation-government-get-started-connect-with-ps
# To connect to AzureUSGovernment, use:
# Connect-AzAccount -EnvironmentName AzureUSGovernment
Do
{
    # TASK-ITEM: List subscriptions
    (Get-AzSubscription).Name
	[string]$Subscription = Read-Host "Please enter your subscription name, i.e. [MySubscriptionName] "
	$Subscription = $Subscription.ToUpper()
} #end Do
Until ($Subscription -in (Get-AzSubscription).Name)
Select-AzSubscription -SubscriptionName $Subscription -Verbose

$rgList = (Get-AzResourceGroup).ResourceGroupName

$rgList

Write-Output "The list above shows the current resource groups in your subscription: $Subscription"
Write-Output ""
Do
{
	[string]$rgpName = Read-Host -Prompt "Please enter a new resource group name to use for this deployment"
    if ($rgpName -in $rgList)
    {
        Write-Output "Resource group $rgpName already exists in this subscription. Please enter a new resource group name."
    } # end if
} #end Do
Until ($rgpName -notin $rgList)

Write-Output "Resource group name specified was: $rgpName"

#region Select Azure Region
Do
{
    # The location refers to a geographic region of an Az data center
    $regions = Get-AzLocation | Select-Object -ExpandProperty Location
    Write-Output "The list of available regions are :"
    Write-Output ""
    Write-Output $regions
    Write-Output ""
    $enterRegionMessage = "Please enter the geographic location (Azure Data Center Region) for resources, i.e. [eastus2 | westus2]"
    [string]$Region = Read-Host $enterRegionMessage
    $region = $region.ToUpper()
    Write-Output "`$Region selected: $Region "
    Write-Output ""
} #end Do
Until ($region -in $regions)
#endregion

New-AzResourceGroup -Name $rgpName -Location $region -Force -Verbose

switch ($scenario)
{
    "secureObject"
    {
        $paramSecObj = @{}
        $paramSecObj.Add("secureCredentials",$credObj)
        $deployment = $_ + ((Get-Date).ToUniversalTime()).ToString('MMdd-HHmm')
        New-AzResourceGroupDeployment -Name $deployment `
        -ResourceGroupName $rgpName `
        -TemplateFile $secObjTemplateFile`
        -TemplateParameterObject $paramSecObj `
        -Force `
        -Verbose `
        -ErrorVariable ErrorMessages
        if ($ErrorMessages)
        {
            Write-Output '', 'Template deployment returned the following errors:', @(@($ErrorMessages) | ForEach-Object { $_.Exception.Message.TrimEnd("`r`n") })
        } # end if
    } # end condition
    "secureString"
    {
        $paramSecStr = @{}
        $paramSecStr.Add("adminUserName",$adminUserName)
        $paramSecStr.Add("pwSecure",$pwSecure)
        $deployment = $_ + ((Get-Date).ToUniversalTime()).ToString('MMdd-HHmm')
        New-AzResourceGroupDeployment -Name $deployment `
        -ResourceGroupName $rgpName `
        -TemplateFile $secStrTemplateFile `
        -TemplateParameterObject $paramSecStr `
        -Force `
        -Verbose `
        -ErrorVariable ErrorMessages
        if ($ErrorMessages)
        {
            Write-Output '', 'Template deployment returned the following errors:', @(@($ErrorMessages) | ForEach-Object { $_.Exception.Message.TrimEnd("`r`n") })
        } # end if
    } # end condition
    "plainText"
    {
        # TASK-ITEM:
    } # end condition
} # end switch

#region Terminate
# Resource group and log files cleanup messages
$labResourceGroupFilter = "rg??"
Write-Warning "The list of PoC resource groups are:"
Get-AzResourceGroup -Name $labResourceGroupFilter -Verbose
Write-Output ""
Write-Warning "To remove the resource groups, use the command below:"
Write-Warning 'Get-AzResourceGroup -Name <YourResourceGroupName> | ForEach-Object { Remove-AzResourceGroup -ResourceGroupName $_.ResourceGroupName -Verbose -Force }'

Write-Warning "Transcript logs are hosted in the directory: $LogDirectory to allow access for multiple users on this machine for diagnostic or auditing purposes."
Write-Warning "To examine, archive or remove old log files to recover storage space, run this command to open the log files location: Start-Process -FilePath $LogDirectory"
Write-Warning "You may change the value of the `$modulePath variable in this script, currently at: $modulePath to a common file server hosted share if you prefer, i.e. \\<server.domain.com>\<share>\<log-directory>"

Stop-Transcript -Verbose
#endregion Terminate

#region OPEN-TRANSCRIPT
# Create prompt and response objects for continuing script and opening logs.
$openTranscriptPrompt = "Would you like to open the transcript log now ? [YES/NO]"
Do
{
    $openTranscriptResponse = read-host $openTranscriptPrompt
    $openTranscriptResponse = $openTranscriptResponse.ToUpper()
} # end do
Until ($openTranscriptResponse -eq "Y" -OR $openTranscriptResponse -eq "YES" -OR $openTranscriptResponse -eq "N" -OR $openTranscriptResponse -eq "NO")

# Exit if user does not want to continue
If ($openTranscriptResponse -in 'Y', 'YES')
{
    Start-Process -FilePath notepad.exe $Transcript -Verbose
} #end condition
else
{
    # Terminate script
    Write-Output "End of Script!"
    $header.SeparatorDouble
} # end else
#endregion