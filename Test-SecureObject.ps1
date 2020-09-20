$rgpName = "rg10"
$adminUserName = "adm.infra.user"
$adminCred = Get-Credential -UserName $adminUserName -Message "Enter password for user: $adminUserName. Password must be complex, at least 12 characters including 3 of the following: lowercase, uppercase, numbers and special characters."
$adminPassword = $adminCred.GetNetworkCredential().password
# $adminPassword = $adminCred.password
# index 23: Create parameter hashtable for ARM templates
$secCred = @()
$secCred += $adminUserName
$secCred += $adminPassword
$secCredObj = @{"secureCredentials"=$secCred}

$secCredObj

Class CredClass
{
    [string]$userName = $adminUserName
    [string]$password = $adminPassword
} # end class

$credObj = [CredClass]::new()

$credObj

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
$subscriptionId = (Select-AzSubscription -SubscriptionName $Subscription).Subscription.id

$paramObj = @{}
$paramObj.Add("secureCredentials",$secCredObj)

$deployment = 'Test-SecureObject' + ((Get-Date).ToUniversalTime()).ToString('MMdd-HHmm')
New-AzResourceGroupDeployment -Name $deployment `
-ResourceGroupName $rgpName `
-TemplateFile .\testSecureObject.json `
-TemplateParameterObject $paramObj `
-Force `
-Verbose `
-ErrorVariable ErrorMessages
if ($ErrorMessages)
{
    Write-Output '', 'Template deployment returned the following errors:', @(@($ErrorMessages) | ForEach-Object { $_.Exception.Message.TrimEnd("`r`n") })
} # end if