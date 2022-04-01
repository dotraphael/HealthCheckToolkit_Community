<#
    .SYNOPSIS
        Collect Data from a ConfigMgr environment as part of the HealthCheck toolkit
        
	.DESCRIPTION
        Collect related data from a ConfigMgr environment to be used later on for healthcheck analysis
        
    .PARAMETER SaveToFolder
        Path where the collected files should be saved. if not passed, default 'C:\Temp\ConfigMgrHealthCheck' will be used

    .PARAMETER CreateZipFiles
        Create a zip file with all collected data into the user's desktop

	.PARAMETER AuthorizedSiteCodes
        List of ConfigMgr Site Codes. If multiple site codes, use comma (',') 
        
	.PARAMETER RulesOverrideFilePath
        Path for the ConfigMgrRulesOverride.xml file
        This file contain all the overrides for the rules that can be changed from the default values (i.e. Enabled True/False, Category, Classifications and Criticality)
        if there is no override to be done, a file with the following information should be used:
<?xml version="1.0" encoding="utf-8" ?>
<Rules>
    <Rule ID="0" Name="Default Rule" Category="1" Classification="ERROR" Criticality="High" Enabled="True" />
</Rules>

	.PARAMETER DefaultValuesOverrideFilePath
        Path for the ConfigMgrDefaultValues.xml file
        This file contain all the default values used by the tool and can be changed if required
        if there is no changes to the default values, a file with the following information should be used:
<?xml version="1.0" encoding="utf-8" ?>
<DefaultValues>
    <DefaultValue Name="DefaultValue" Type="int" value="1" />
</DefaultValues>

    .INPUTS
        None

    .OUTPUTS
        None

	.NOTES
        Author: Raphael Perez (raphael@perez.net.br)
        Website: http://www.endpointmanagers.com
        WebSite: https://github.com/dotraphael/HealthCheckToolkit_Community
        Twitter: @dotraphael

        DateCreated: 24/10/2013 (v0.1)
        Update: 05/11/2014 (v0.2)
        Update: 22/06/2015 (v0.3)
        Update: 04/02/2016 (v0.4)
        Update: 12/05/2017 (v0.5)
        Update: 03/08/2018 (v1.0)
        Update: 28/08/2018 (v1.1)
        Update: 10/09/2018 (v1.2)
        Update: 28/09/2018 (v1.3)
        Update: 14/12/2018 (v1.4)
        Update: 03/05/2019 (v1.5)
        Update: 01/10/2019 (v1.6)
        Update: 19/05/2020 (v1.7)
        Update: 26/02/2021 (v1.8)
        Update: 26/02/2021 (v1.9)
        Update: 17/02/2022 (v2.0)
        Update: 28/03/2022 (v2.1)
              - Removed need for HealthCheckClasses.dll
              - fixed issue when capturing Firewall policy list (rule 181,182)

        Test:
            CM2111 Primary site installed on a WS2016
            CM2107 Primary site installed on a WS2019

        Requirements: 
            ConfigMgr Console must be installed and connected to the ConfigMgr infrastructure to be able to run the tool
            ConfigMgr Primary Site environment. CAS is not supported
            Tool must be run as administrator and account must have full admin access to the ConfigMgr infrastructure

    .LINK
        http://www.endpointmanagers.com
        http://www.rflsystems.co.uk
        https://github.com/dotraphael/HealthCheckToolkit_Community

    .EXAMPLE
        Run the tool against sitecode 001 and use files ConfigMgrrulesoverride.xml and ConfigMgrdefaultvalues.xml located on the same folder as the script
        and will save all the data into the default location 'C:\Temp\ConfigMgrHealthCheck'

        .\CollectData.ps1 -AuthorizedSiteCodes '001' -RulesOverrideFilePath .\ConfigMgrRulesOverride.xml -DefaultValuesOverrideFilePath .\ConfigMgrDefaultValues.xml
    .EXAMPLE
        Run the tool against sitecode 001 and use files ConfigMgrrulesoverride.xml and ConfigMgrdefaultvalues.xml located on the same folder as the script
        and will save all the data into the location 'C:\Temp\ConfigMgrHealthCheckNewLocation' and will create a Zip File with all collected files into the user's desktop

        .\CollectData.ps1 -AuthorizedSiteCodes '001' -RulesOverrideFilePath .\ConfigMgrRulesOverride.xml -DefaultValuesOverrideFilePath .\ConfigMgrDefaultValues.xml -CreateZipFiles -SaveToFolder 'C:\Temp\ConfigMgrHealthCheckNewLocation'
#>
#region param
[CmdletBinding()]param (
    [parameter(Mandatory=$true)][string]$AuthorizedSiteCodes,
    [parameter(Mandatory=$true)][ValidateScript({If(Test-Path -LiteralPath $_){$true}else{Throw "Invalid Rules Override File Path given: $_"}})][string]$RulesOverrideFilePath,
    [parameter(Mandatory=$true)][ValidateScript({If(Test-Path -LiteralPath $_){$true}else{Throw "Invalid Default Values Override File Path given: $_"}})][string]$DefaultValuesOverrideFilePath,
    [switch]$CreateZipFiles,
    $SaveToFolder = 'C:\Temp\ConfigMgrHealthCheck'
)
#endregion

#region Starting Script, Verbose variables
$Global:ErrorCapture = @()
$Script:StartDateTime = get-date
$Script:RemoveVariable = $true
if ($Verbose) {
    $DebugPreference = 2
    $VerbosePreference = 2
    $WarningPreference = 2
}
$Error.Clear()
$ErrorActionPreference = "Continue"
#endregion

#region Import class DLL
Add-Type -Assembly System.IO.Compression.FileSystem | Out-Null
#endregion

#region Functions
#region Test-RFLAdministrator
Function Test-RFLAdministrator {
<#
    .SYSNOPSIS
        Check if the current user is member of the Local Administrators Group

    .DESCRIPTION
        Check if the current user is member of the Local Administrators Group

    .NOTES
        Name: Test-RFLAdministrator
        Author: Raphael Perez
        DateCreated: 28 November 2019 (v0.1)

    .EXAMPLE
        Test-RFLAdministrator
#>
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    (New-Object Security.Principal.WindowsPrincipal $currentUser).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}
#endregion

#region Clear-RFLLog
Function Clear-RFLLog {
<#
    .SYSNOPSIS
        Delete the log file if bigger than maximum size

    .DESCRIPTION
        Delete the log file if bigger than maximum size

    .NOTES
        Name: Clear-RFLLog
        Author: Raphael Perez
        DateCreated: 28 November 2019 (v0.1)

    .EXAMPLE
        Clear-RFLLog -maxSize 2mb
#>
param (
    [Parameter(Mandatory = $true)][string]$maxSize
)
    try  {
        if(Test-Path -Path $script:ScriptLogFilePath) {
            if ((Get-Item $script:ScriptLogFilePath).length -gt $maxSize) {
                Remove-Item -Path $script:ScriptLogFilePath
                Start-Sleep -Seconds 1
            }
        }
    }
    catch {
        Write-RFLLog -Message "Unable to delete log file." -LogLevel 3
    }    
}
#endregion

#region Get-ScriptDirectory
function Get-ScriptDirectory {
<#
    .SYSNOPSIS
        Get the directory of the script

    .DESCRIPTION
        Get the directory of the script

    .NOTES
        Name: ClearGet-ScriptDirectory
        Author: Raphael Perez
        DateCreated: 28 November 2019 (v0.1)

    .EXAMPLE
        Get-ScriptDirectory
#>
    Split-Path -Parent $PSCommandPath
}
#endregion

#region Set-RFLLogPath
Function Set-RFLLogPath {
<#
    .SYSNOPSIS
        Configures the full path to the log file depending

    .DESCRIPTION
        Configures the full path to the log file depending

    .NOTES
        Name: Set-RFLLogPath
        Author: Raphael Perez
        DateCreated: 28 November 2019 (v0.1)

    .EXAMPLE
        Set-RFLLogPath
#>
    if ([string]::IsNullOrEmpty($script:LogFilePath)) {
        $script:LogFilePath = $env:Temp
    }

    $script:ScriptLogFilePath = "$($script:LogFilePath)\$($Script:LogFileFileName)"
}
#endregion

#region Remove-RFLVariable
function Remove-RFLVariable {
    param (
        [Parameter(Mandatory=$true)][string]$VariableName
    )
    if ($Script:RemoveVariable -eq $true) {
        try {
            Remove-Variable -Name $VariableName -Force -Scope Script 
        } catch {
            $Global:ErrorCapture += $_
            Write-RFLLog -logtype "ERROR" -logmessage "Error Message: 'Unable to remove variable $($VariableName)'"
            Write-RFLLog -logtype "EXCEPTION" -logmessage "Error Message: '$($_.Error)'"
        }
    }
}
#endregion

#region Export-RFLXMLFile
function Export-RFLXMLFile {
    param (
        [Parameter(Mandatory=$true)][string]$VariableName,
        [switch]$ClearVariable = $false,
		[switch]$ForceExport = $false
    )
    $VarInfo = Get-Variable $VariableName -ErrorAction SilentlyContinue
    if ($null -eq $VarInfo) {
        Write-RFLLog -logtype "WARNING" -logmessage "Exporting $($VariableName) ignored as it is empty"
    } elseif (($null -eq $VarInfo.Value) -and ($ForceExport -eq $false)) {
        Write-RFLLog -logtype "WARNING" -logmessage "Exporting $($VariableName) ignored as it is empty"
    } elseif (($VarInfo.Value.Count -eq 0) -and ($ForceExport -eq $false)) {
        Write-RFLLog -logtype "WARNING" -logmessage "Exporting $($VariableName) ignored as it is empty"
    } else {
        Write-RFLLog -logtype "INFO" -logmessage "Exporting $($VarInfo.Name)"
        $VarInfo.Value | Export-Clixml -Path "$($SaveToFolder)\$($VarInfo.Name).xml"
        if ($ClearVariable) {
            Remove-RFLVariable -VariableName ($VarInfo.Name)
        }
    }
}
#endregion

#region Extract-RFLZipFiles
function Extract-RFLZipFiles {
    param (
        [string]$zipfilename,
        [string]$destinationdir
    )
    Write-RFLLog -logtype "Info" -logmessage "Extracting Zip File $($zipfilename) to $($destinationdir)"
    [System.IO.Compression.ZipFile]::ExtractToDirectory($zipfilename, $destinationdir)
}
#endregion

#region Write-RFLZipFiles
function Write-RFLZipFiles {
    param (
        [string]$zipfilename,
        [string]$sourcedir
    )
    Write-RFLLog -logtype "Info" -logmessage "Creating Zip File $($zipfilename)"
    $compressionLevel = [System.IO.Compression.CompressionLevel]::Optimal
    [System.IO.Compression.ZipFile]::CreateFromDirectory($sourcedir, $zipfilename, $compressionLevel, $false)
}
#endregion

#region Test-RFLUrl
function Test-RFLUrl {
    param (
        $ListOfServers,
        [Parameter(Mandatory=$true)][ValidateSet('mplist','mpcert','sitesigncert','appcatalogwebservice','appcatalogwebsite','wsussimpleauth','ssrsreporturi','ssrsreportserveruri')]
        [string]$ServerType,
        [int]$RuleID,
        [int]$CommentIDError,
        [int]$MessageIDError,
        [int]$CommentIDException,
        [bool]$UserCredentials
    )
    $RuleIDInfo = (Get-Variable "RuleID$($RuleID)" -ErrorAction SilentlyContinue).Value
    if ($null -ne $ListOfServers) {
        $ListOfServers | ForEach-Object {
            $item = $_
            $UseCertificate = $false
            $servername = $item.NetworkOSPath -replace '\\', ''
            if ($ServerType.ToLower() -eq 'mplist') {
                $MPPort = (($MPComponentList | Where-Object {$_.SiteCode -eq $item.SiteCode}).Props | Where-Object {$_.PropertyName -eq 'IISPortsList'}).Value1
                $MPProtocol = 'HTTP'
                if ($item.sslState -in (1,3)) {
                    $MPPort = (($MPComponentList | Where-Object {$_.SiteCode -eq $item.SiteCode}).Props | Where-Object {$_.PropertyName -eq 'IISSSLPortsList'}).Value1
                    $MPProtocol = 'HTTPS'
                    $UseCertificate = $true
                }
                $url = "$($MPProtocol)://$($servername):$($MPPort)/sms_mp/.sms_aut?mplist"
            } elseif ($servertype.tolower() -eq 'mpcert') {
                $MPPort = (($MPComponentList | Where-Object {$_.SiteCode -eq $item.SiteCode}).Props | Where-Object {$_.PropertyName -eq 'IISPortsList'}).Value1
                $MPProtocol = 'HTTP'
                if ($item.sslState -in (1,3)) {
                    $MPPort = (($MPComponentList | Where-Object {$_.SiteCode -eq $item.SiteCode}).Props | Where-Object {$_.PropertyName -eq 'IISSSLPortsList'}).Value1
                    $MPProtocol = 'HTTPS'
                    $UseCertificate = $true
                }
                $url = "$($MPProtocol)://$($servername):$($MPPort)/sms_mp/.sms_aut?mpcert"
            } elseif ($servertype.tolower() -eq 'sitesigncert') {
                $MPPort = (($MPComponentList | Where-Object {$_.SiteCode -eq $item.SiteCode}).Props | Where-Object {$_.PropertyName -eq 'IISPortsList'}).Value1
                $MPProtocol = 'HTTP'
                if ($item.sslState -in (1,3)) {
                    $MPPort = (($MPComponentList | Where-Object {$_.SiteCode -eq $item.SiteCode}).Props | Where-Object {$_.PropertyName -eq 'IISSSLPortsList'}).Value1
                    $MPProtocol = 'HTTPS'
                    $UseCertificate = $true
                }
                $url = "$($MPProtocol)://$($servername):$($MPPort)/sms_mp/.sms_aut?SITESIGNCERT"
            } elseif ($servertype.tolower() -eq 'appcatalogwebservice') {
                $HTTPPort = ($item.Props | Where-Object {$_.PropertyName -eq 'ServicePort' }).Value
                $ServiceName = ($item.Props | Where-Object {$_.PropertyName -eq 'ServiceName' }).Value1
                $HTTPProtocol = 'HTTP'
                if ($item.sslState -in (1,3)) {
                    $HTTPProtocol = 'HTTPS'
                }
                $url = "$($HTTPProtocol)://$($servername):$($HTTPPort)/$($ServiceName)/ApplicationOfferService.svc"
            } elseif ($servertype.tolower() -eq 'appcatalogwebsite') {
                $HTTPPort = ($item.Props | Where-Object {$_.PropertyName -eq 'PortalPort' }).Value
                $ServiceName = ($item.Props | Where-Object {$_.PropertyName -eq 'PortalPath' }).Value1
                if ([string]::IsNullOrEmpty($ServiceName)) {
                    $ServiceName = 'CMApplicationCatalog'
                }

                $HTTPProtocol = 'HTTP'
                if ($item.sslState -in (1,3)) {
                    $HTTPProtocol = 'HTTPS'
                    $HTTPPort = ($item.Props | Where-Object {$_.PropertyName -eq 'PortalSslPort' }).Value
                }
                $url = "$($HTTPProtocol)://$($servername):$($HTTPPort)/$($ServiceName)"
            } elseif ($servertype.tolower() -eq 'wsussimpleauth') {
                $HTTPPort = ($item.Props | Where-Object {$_.PropertyName -eq 'WSUSIISPort' }).Value
                $HTTPProtocol = 'HTTP'
                if ($item.sslState -in (1,3)) {
                    $HTTPProtocol = 'HTTPS'
                    $HTTPPort = ($item.Props | Where-Object {$_.PropertyName -eq 'WSUSIISSSLPort' }).Value
                }
                $url = "$($HTTPProtocol)://$($servername):$($HTTPPort)/SimpleAuthWebService/SimpleAuth.asmx"
            } elseif ($servertype.tolower() -eq 'ssrsreporturi') {
                $RootFolder = ($item.Props | Where-Object {$_.PropertyName -eq 'RootFolder' }).Value2
                $ReportsURI = ($item.Props | Where-Object {$_.PropertyName -eq 'ReportManagerUri' }).Value2
                $ReportServerURI = ($item.Props | Where-Object {$_.PropertyName -eq 'ReportServerUri' }).Value2
                $url = "$($ReportsURI)/$($RootFolder)"
            } elseif ($servertype.tolower() -eq 'ssrsreportserveruri') {
                $RootFolder = ($item.Props | Where-Object {$_.PropertyName -eq 'RootFolder' }).Value2
                $ReportsURI = ($item.Props | Where-Object {$_.PropertyName -eq 'ReportManagerUri' }).Value2
                $ReportServerURI = ($item.Props | Where-Object {$_.PropertyName -eq 'ReportServerUri' }).Value2
                $url = "$($ReportServerURI)/$($RootFolder)"
            } else {
                throw 'Invalid Server Type information'
            }

            if ($UseCertificate) {
                Write-RFLLog -logtype "Info" -logmessage "Certificate required. Trying to get a certificate information"
                $UserCertList = Get-ChildItem Cert:\CurrentUser\My 
                $CertToUse = $null
                foreach($cert in $UserCertList) {
                    $bFound = $false
                    $KeyUsageList = $cert.EnhancedKeyUsageList
                    foreach($KeyUsage in $KeyUsageList) {
                        if ($KeyUsage.FriendlyName -eq 'Client Authentication') {
                            $bFound = $true
                            break
		                }
	                }
	                if ($bFound) {
		                $CertToUse = $cert
		                break
	                }
                }
            }
            if ($null -eq $CertToUse) {
                Write-RFLLog -logtype "Info" -logmessage "No certificate with 'Client Authentication' found."
                $CertThumbprint = ''
            } else {
                Write-RFLLog -logtype "Info" -logmessage "Certificate with 'Client Authentication' found. Using certificate with Friendly Name:'$($certtouse.FriendlyName)', Subject: '$($certtoUse.Subject)' and thumbprint '$($CertToUse.Thumbprint)'"
                $CertThumbprint = $CertToUse.Thumbprint
            }

            Write-RFLLog -logtype "Info" -logmessage "Getting '$($servertype)' information for '$($servername)'"
            $Code = {
                Param (
                    [string]$url,
                    [string]$servername,
                    [bool]$UserCredentials,
                    [string]$CertThumbprint
                )
                try {
                    if ($UserCredentials) {
                        $WebRequest = Invoke-WebRequest -Uri $url -UseDefaultCredentials -UseBasicParsing
                    } elseif (-not ([string]::IsNullOrEmpty($CertThumbprint))) {
                        $WebRequest = Invoke-WebRequest -Uri $url -CertificateThumbprint $CertThumbprint
                    } else {
                        $WebRequest = Invoke-WebRequest -Uri $url -UseBasicParsing
                    }
                    New-Object -TypeName PSObject -Property @{'Success' = $true; 'ServerName' = $ServerName; 'StatusCode' = "$($WebRequest.StatusCode)"; 'URL' = $url;'Error'='' }
                } catch {
                    $Global:ErrorCapture += $_
                    New-Object -TypeName PSObject -Property @{'Success' = $false; 'ServerName' = $ServerName; 'StatusCode' = "$($WebRequest.StatusCode)"; 'URL' = $url;'Error'=$_ }
                }
            }
            $returnInfo = Execute-RFLRunSpace -code $Code -ParameterList @($url, $servername, $UserCredentials, $CertThumbprint)

            $returninfo | where-object {$_.Success -eq $true} | foreach-object {
                $Script:ServerHTTPAccessInformation += New-Object -TypeName PSObject -Property @{'CommentIDError' = $CommentIDError; 'MessageIDError' = $MessageIDError; 'RuleInfo' = $RuleID; 'ServerName' = $_.ServerName; 'StatusCode' = $_.StatusCode; 'URL' = $_.URL }
            }
            $returninfo | where-object {$_.Success -eq $false} | foreach-object {
                Write-RFLLog -logtype "EXCEPTION" -logmessage "Error Message: '$($_.Error)'"                
                $Script:ServerHTTPAccessInformation += New-Object -TypeName PSObject -Property @{'CommentIDError' = $CommentIDException; 'MessageIDError' = $MessageIDError; 'RuleInfo' = $RuleID; 'ServerName' = $_.ServerName; 'StatusCode' = 'Unable to connect'; 'URL' = $_.URL }
            }
        }
    }
}
#endregion

#region Get-RFLHealthCheckCategory
function Get-RFLHealthCheckCategory {
    param (
        [Parameter(Mandatory=$true)][int]$MessageID
    )

    $return = ($Script:HealthCheckCategoryData.Categories.Category | Where-Object {($_.id -eq $MessageID) -and ($_.module -eq 'ConfigMgr')}).Name
    if ($null -eq $return) {
        $Return = "Unknown Category with message ID $($MessageID)"
    }
    return $return
}
#endregion

#region Get-RFLHealthCheckIssue
function Get-RFLHealthCheckIssue {
    param (
        [Parameter(Mandatory=$true)][int]$MessageID,
        [Parameter(Mandatory=$false)][object[]]$MessageParameters
    )

    $return = ($Script:HealthCheckIssuesData.Issues.issue | Where-Object {($_.id -eq $MessageID) -and ($_.module -eq 'ConfigMgr')}).Name
    if ($null -eq $return) {
        $Return = "Unknown Issue with message ID $($MessageID)"
    } else {
        if (($MessageParameters.Count -gt 0) -and ($return.IndexOf('{0}') -ge 0)) {
            try {
                $return = $return -f $MessageParameters
            } catch {
                $Global:ErrorCapture += $_
                Write-RFLLog -LogType 'ERROR' -LogMessage "Message with Error: $MessageID"
                throw $_
            }
        }
    }
    #return "something $messageID - $return"
    return $return
}
#endregion

#region Get-RFLHealthCheckRecommendation
function Get-RFLHealthCheckRecommendation {
    param (
        [Parameter(Mandatory=$true)][int]$MessageID,
        [Parameter(Mandatory=$false)][object[]]$MessageParameters
    )

    $return = ($Script:HealthCheckRecommendationData.Recommendations.Recommendation | Where-Object {($_.id -eq $MessageID) -and ($_.module -eq 'ConfigMgr')}).Name
    if ($null -eq $return) {
        $Return = "Unknown Recommendation with message ID $($MessageID)"
    } else {
        if (($MessageParameters.Count -gt 0) -and ($return.IndexOf('{0}') -ge 0)) {
            try {
                $return = $return -f $MessageParameters
            } catch {
                $Global:ErrorCapture += $_
                Write-RFLLog -LogType 'ERROR' -LogMessage "Message with Error: $MessageID"
                throw $_
            }
        }
    }
    return $return
}
#endregion

#region Get-RFLCollectionNames
function Get-RFLCollectionNames {
    param (
        [Parameter(Mandatory=$true)]$CollectionList
    )
    (($CollectionList | select-Object Name -unique) | Foreach {"'$($_.Name.Trim())'"}) -join ' '
}
#endregion

#region Set-RFLHealthCheckDefaultValue
function Set-RFLHealthCheckDefaultValue {
    param (
        [Parameter(Mandatory=$true)][string]$ValueName,
        [Parameter(Mandatory=$true)]$ValueNonExist
    )
    $ValueDetails = $Script:HealthCheckDefaultValueData.DefaultValues.DefaultValue | Where-Object {$_.Name -eq $ValueName}
    if ($null -eq $ValueDetails) {
        New-Variable -Name $ValueName -Value $ValueNonExist -Force -Option AllScope -Scope Script
        #Write-RFLLog -LogType 'INFO' -LogMessage "$ValueName is now set to default value of $((Get-Variable $ValueName).Value)"
    } else {
        if ($ValueDetails -is [array]) {
            $ValueDetails = $ValueDetails[0]
        }

        if ($ValueDetails.Type.tolower() -eq 'array') {
            New-Variable -Name $ValueName -Value $ValueDetails.value.Split(',') -Force -Option AllScope -Scope Script
        } else {
            New-Variable -Name $ValueName -Value $ValueDetails.value -Force -Option AllScope -Scope Script
        }
        Write-RFLLog -LogType 'INFO' -LogMessage "$ValueName is now set to custom default value of $((Get-Variable $ValueName).Value)"
    }
}
#endregion

#region Set-RFLHealthCheckRulesOverride
function Set-RFLHealthCheckRulesOverride {
    param (
        [Parameter(Mandatory=$true)][int]$RuleID,
        [Parameter(Mandatory=$true)][string]$RuleName,
        [Parameter(Mandatory=$true)][int]$DefaultCategory,
        [Parameter(Mandatory=$true)][string]$Criticality,
        [Parameter(Mandatory=$true)][string]$DefaultClassification
    )
    $ValueDetails = $Script:HealthCheckRulesOverrideData.Rules.Rule | Where-Object {$_.ID -eq $RuleID}
    $VariableName = "RuleID$($RuleID)"
    $objRule = New-Object -TypeName PSObject -Property @{'ID' = $RuleID; 'Name' = $RuleName; 'Category' = $DefaultCategory; 'Classification' = $DefaultClassification;'Criticality'=$Criticality;'Enabled'=$true }
    #$objRule = new-object HealthCheckClasses.HealthCheck.CEClassRules($RuleID, $RuleName, $DefaultCategory, $DefaultClassification, $Criticality, $true)
    $ShowMsg = $false

    if ($null -ne $ValueDetails) {
        if ($ValueDetails -is [array]) {
            $ValueDetails = $ValueDetails[0]
        }
        $objRule.Category = $ValueDetails.Category
        $objRule.Classification = $ValueDetails.Classification
        $objRule.Criticality = $ValueDetails.Criticality
        $objRule.Enabled = [Convert]::ToBoolean($ValueDetails.Enabled)
        $ShowMsg = $true
    }
    New-Variable -Name $VariableName -Value $objRule -Force -Option AllScope -Scope Script
    if ($ShowMsg) {
        Write-RFLLog -LogType 'INFO' -LogMessage "Rule ID $($RuleID) information is set to custom values of Category: $((Get-Variable $VariableName).Value.Category), Classification: $((Get-Variable $VariableName).Value.Classification), Enabled: $((Get-Variable $VariableName).Value.Enabled)"
    }
}
#endregion

#region Write-RFLHealthCheckData
function Write-RFLHealthCheckData {
    PARAM (
        [Parameter(Mandatory=$true)][string]$Description,
        [Parameter(Mandatory=$false)][string]$Comment,
        [Parameter(Mandatory=$true)]$RuleIDInfo
    )
    $newRow = $Script:HealthCheckData.NewRow()
    $newRow.Category = Get-RFLHealthCheckCategory $RuleIDInfo.Category
    $newRow.Classification = $RuleIDInfo.Classification
    $newRow.Description = "$($Description)"
    $newRow.Comment = " $($Comment) "
    $newRow.RuleID = $RuleIDInfo.ID
    $newRow.Criticality = $RuleIDInfo.Criticality
    switch ($RuleIDInfo.Criticality.ToUpper()) {
        "HIGH" {
            $newRow.CriticalityID = 1
        }
        "MEDIUM" {
            $newRow.CriticalityID = 2
        }
        default {
            $newRow.CriticalityID = 3
        }
    }
    $Script:HealthCheckData.Rows.Add($newRow)
    Write-RFLLog -logtype "$($newRow.Classification)" -logmessage "$($newRow.Category) - $Description"
}
#endregion

#region Test-RFLHealthCheckCollectData
function Test-RFLHealthCheckCollectData {
    param (
        [Parameter(Mandatory=$true)][int[]]$Rules
    )

    $enabledRules = ""
    foreach($item in $Rules) {
        $RuleInfo = (Get-Variable "RuleID$($item)" -ErrorAction SilentlyContinue).Value
        if ($RuleInfo.Enabled -eq $true) {
            if (-not [string]::IsNullOrEmpty($enabledRules)) { $enabledRules += ', '}
            $enabledRules += $item
        }
    }

    if ([string]::IsNullOrEmpty($enabledRules)) {
        return $false
    } else {
        return $true
    }
}
#endregion

#region Write-RFLLog
function Write-RFLLog {
<#
    .SYSNOPSIS
        Write the log file if the global variable is set

    .DESCRIPTION
        Write the log file if the global variable is set

    .PARAMETER LogMessage
        Message to write to the log

    .PARAMETER LogType
        Log Level Information, Warning, Error or Exception

    .NOTES
        Name: Write-RFLLog
        Author: Raphael Perez
        DateCreated: 28 November 2019 (v0.1)
        Update: 23 February 2022 (v0.2)

    .EXAMPLE
        Write-RFLLog -LogMessage 'This is an information message' 

    .EXAMPLE
        Write-RFLLog -LogMessage 'This is a warning message' -LogType 'WARNING'

    .EXAMPLE
        Write-RFLLog -LogMessage 'This is an error message' -LogType 'ERROR'
#>

    PARAM (
        [Parameter(Mandatory=$false)]
        [ValidateSet('EXCEPTION', 'ERROR', 'WARNING', 'INFO')]
        [string]
        $LogType = 'INFO',

        [Parameter(Mandatory=$true)]
        [string]
        $LogMessage
    )
    $DateTime = Get-Date

    $MessageToWrite = "$($LogType.ToUpper()): $($DateTime.ToString('dd/MM/yyyy HH:mm:ss')) - $($LogMessage)"
    $MessageToWrite | Out-File -FilePath $script:ScriptLogFilePath -Append -NoClobber -Encoding default
    switch ($LogType.ToUpper()) {
        "EXCEPTION" {
            write-host $MessageToWrite -ForegroundColor Red -BackgroundColor White
            #send analytics info
        }
        "ERROR" {
            write-host $MessageToWrite -ForegroundColor Red
        }
        "WARNING" {
            Write-Host $MessageToWrite -ForegroundColor Yellow
        }
        default {
            write-Host $MessageToWrite
        }
    }
}
#endregion

#region Get-RFLAccountMembership
function Get-RFLAccountMembership {
    param (
        $AccountList,
        [string]$PropertyName,
        [bool]$isServiceAccount,
        [string]$AccountType
    )
    $Root = [ADSI]"LDAP://RootDSE"
    $oForestConfig = $Root.Get("configurationNamingContext")
    $oSearchRoot = [ADSI]("LDAP://CN=Partitions," + $oForestConfig)
    $AdSearcher = [adsisearcher]"(&(objectcategory=crossref)(netbiosname=*))"
    $AdSearcher.SearchRoot = $oSearchRoot
    $domains = $AdSearcher.FindAll()

    $AccountList | ForEach-Object {
        $itemAccount = $_
        #todo: need to get information about @ user
        if ($itemAccount.$PropertyName.Indexof('@') -lt 0) {
            Write-RFLLog -logtype "Info" -logmessage "Getting group membership for information for '$($itemAccount.$PropertyName)'"
            $ReturnInfo = @()
            try {
                $arrAccountInfo = $itemAccount.$PropertyName.Split('\')
                $domainNC = ($domains | Where-Object {$_.Properties.cn -eq $arrAccountInfo[0]}).Properties.ncname
                if ($null -eq $domainNC) {
                    $domainNC = ($domains | Where-Object {$_.Properties.dnsroot -eq $arrAccountInfo[0]}).Properties.ncname
                }
                $objSearcher = New-Object System.DirectoryServices.DirectorySearcher("LDAP://$($domainNC)")
                $objSearcher.PageSize = $Script:ADPageSize

                $objSearcher.SearchScope = "Subtree"
                $objSearcher.Filter = "(sAMAccountName=$($arrAccountInfo[1]))"
                $objSearchReturn = $objSearcher.FindOne()
                if ($null -eq $objSearchReturn) {
                    $ReturnInfo += New-Object -TypeName PSObject -Property @{'ReturnType' = 0; 'DomainNetbios' = $arrAccountInfo[0]; 'DomainDN' = $domainNC; 'AccountName' = $itemAccount.$PropertyName; 'isServiceAccount' = $false; 'AccountDN' = $itemAccount.$PropertyName; 'GroupDN' = ''; 'GroupName' = ''; 'ConnectionType' = ''; 'Error'='' }
                } else {
                    $objDN = $null
                    $objDN = $objSearchReturn.Properties.distinguishedname
                    if ($null -eq $objDN) {
                        $ReturnInfo += New-Object -TypeName PSObject -Property @{'ReturnType' = 0; 'DomainNetbios' = $arrAccountInfo[0]; 'DomainDN' = $domainNC; 'AccountName' = $itemAccount.$PropertyName; 'isServiceAccount' = $false; 'AccountDN' = $itemAccount.$PropertyName; 'GroupDN' = ''; 'GroupName' = ''; 'ConnectionType' = ''; 'Error'='' }
                    } else {
                        $groupName = $null
                        ([adsisearcher]"(distinguishedname=$($objDN[0]))").FindOne().Properties.memberof | foreach-object {
                            $groupName = $_
                        }
                        if ($null -eq $groupName) {
                            $ReturnInfo += New-Object -TypeName PSObject -Property @{'ReturnType' = 1; 'DomainNetbios' = $arrAccountInfo[0]; 'DomainDN' = $domainNC; 'AccountName' = $itemAccount.$PropertyName; 'isServiceAccount' = $false; 'AccountDN' = $itemAccount.$PropertyName; 'GroupDN' = ''; 'GroupName' = ''; 'ConnectionType' = ''; 'Error'='' }
                        } else {
                            $group = [adsi]"LDAP://$($groupName)"
                            $Group.Member | ForEach-Object {
                                $Searcher = [adsisearcher]"(distinguishedname=$_)"
                                $props = $searcher.FindOne().Properties
                                $ReturnInfo += New-Object -TypeName PSObject -Property @{'ReturnType' = 1; 'DomainNetbios' = $arrAccountInfo[0]; 'DomainDN' = $domainNC; 'AccountName' = $arrAccountInfo[1]; 'isServiceAccount' = $false; 'AccountDN' = $objDN; 'GroupDN' = $props.distinguishedname; 'GroupName' = $props.name; 'ConnectionType' = ''; 'Error'='' }
                            }
                        }
                    }
                }
            } catch {
                $Global:ErrorCapture += $_
                $ReturnInfo += New-Object -TypeName PSObject -Property @{'ReturnType' = 2; 'DomainNetbios' = ''; 'DomainDN' = ''; 'AccountName' = $itemAccount.$PropertyName; 'isServiceAccount' = $false; 'AccountDN' = $itemAccount.$PropertyName; 'GroupDN' = ''; 'GroupName' = ''; 'ConnectionType' = ''; 'Error'=$_ }
            }

            $returninfo | where-object {$_.ReturnType -eq 0} | foreach-object {
                $Script:AccountDoesNotExist += New-Object -TypeName PSObject -Property @{'AccountName' = $_.AccountName; 'isServiceAccount' = $isServiceAccount; 'AcccountType' = $AccountType; }
            }

            $returninfo | where-object {$_.ReturnType -eq 1} | ForEach-Object {
                $Script:GroupMembershipList += New-Object -TypeName PSObject -Property @{'DomainNetbios' = $_.DomainNetbios; 'DomainDN' = $_.DomainDN; 'AccountName' = $_.AccountName; 'isServiceAccount' = $_.isServiceAccount; 'AccountDN' = $_.AccountDN; 'GroupDN' = $_.GroupDN; 'GroupName' = $_.GroupName; 'AccountTYpe' = $_.AccountType; }
                #$Script:GroupMembershipList += new-object HealthCheckClasses.ConfigMgr.CEAccountMembership($_.DomainNetbios, $_.DomainDN, $_.AccountName, $_.isServiceAccount, $_.AccountDN, $_.GroupDN, $_.GroupName, $_.AccountType)
            } 

            $returninfo | where-object {$_.ReturnType -eq 2} | foreach-object {
                Write-RFLLog -logtype "EXCEPTION" -logmessage "Error Message: '$($_.Error)'"
                $Script:GroupMembershipErrorList += $_.AccountName
            }
        }
    }
}
#endregion

#region Execute-RFLRunSpace
function Execute-RFLRunSpace {
    param (
        [ScriptBlock]$code,
        [object[]]$ParameterList
    )
    $newPowerShell = [PowerShell]::Create().AddScript($code)
    $newPowerShell.AddParameters( $ParameterList ) | out-null
    $job = $newPowerShell.BeginInvoke()
    While (-Not $job.IsCompleted) {}
    $returnInfo = $newPowerShell.EndInvoke($job)
    $newPowerShell.Dispose()

    $returnInfo
}
#endregion

#endregion

#region Variables
$script:ScriptVersion = '2.1'
$script:LogFilePath = $env:Temp
$Script:LogFileFileName = 'CollectData.log'
$script:ScriptLogFilePath = "$($script:LogFilePath)\$($Script:LogFileFileName)"
#endregion

#region Main Script
try {
    Set-RFLLogPath
    Clear-RFLLog 25mb

    Write-RFLLog -logtype "Info" -logmessage "*** Starting ***"
    Write-RFLLog -logtype "Info" -logmessage "Script version $script:ScriptVersion"
    Write-RFLLog -logtype "Info" -logmessage "Running as $env:username $(if(Test-RFLAdministrator) {"[Administrator]"} Else {"[Not Administrator]"}) on $($env:computername)"
    $PSCmdlet.MyInvocation.BoundParameters.Keys | ForEach-Object { 
        Write-RFLLog -logtype "Info" -logmessage "Parameter '$($_)' is '$($PSCmdlet.MyInvocation.BoundParameters.Item($_))'"
    }

    #region Temporary Folder
    #$SaveToFolder = "$($env:TEMP)\$((Get-Date).Ticks)"
    #$SaveToFolder = 'C:\Temp\ConfigMgrHealthCheck'
    New-Item -Path $SaveToFolder -Type Directory -Force | out-null
    #endregion

    #region XML files
        
    #region Rules Override
    Write-RFLLog -logtype "Info" -logmessage "Rules Override Database"
    $Script:HealthCheckRulesOverrideData = [xml](get-content $RulesOverrideFilePath)
    #endregion

    #region Default Values
    Write-RFLLog -logtype "Info" -logmessage "Default Values Database"
    $Script:HealthCheckDefaultValueData = [xml](get-content $DefaultValuesOverrideFilePath)
    #endregion
    
    #endregion

    #region Set Default Variables
    Write-RFLLog -logtype "Info" -logmessage "Setting Default Check Variables"
    1..25 | foreach {
        Set-RFLHealthCheckDefaultValue -ValueName "Cat$($_)ERROR" -ValueNonExist 0
        Set-RFLHealthCheckDefaultValue -ValueName "Cat$($_)WARNING" -ValueNonExist 0
    }
    Set-RFLHealthCheckDefaultValue -ValueName 'MinimumConfigMgrBuildVersion' -ValueNonExist 9040 #2010 https://docs.microsoft.com/en-us/mem/configmgr/core/servers/manage/updates#version-details
    Set-RFLHealthCheckDefaultValue -ValueName 'LatestConfigMgrBuildVersion' -ValueNonExist 9068 #2111 list can be found https://buildnumbers.wordpress.com/sccm/
    Set-RFLHealthCheckDefaultValue -ValueName 'LatestWhatsNew' -ValueNonExist 'https://docs.microsoft.com/en-us/mem/configmgr/core/plan-design/changes/whats-new-in-version-2111'
    Set-RFLHealthCheckDefaultValue -ValueName 'W10MinBuild' -ValueNonExist 18363 #1909. https://support.microsoft.com/en-us/help/13853/windows-lifecycle-fact-sheet - build can be found https://docs.microsoft.com/en-gb/windows/release-health/release-information
    Set-RFLHealthCheckDefaultValue -ValueName 'MinimumSQLVersion' -ValueNonExist '12.0.6024.0' #2014 sp3 https://docs.microsoft.com/en-us/lifecycle/products/sql-server-2014, https://sqlserverbuilds.blogspot.com/ and https://docs.microsoft.com/en-us/mem/configmgr/core/plan-design/configs/support-for-sql-server-versions
    Set-RFLHealthCheckDefaultValue -ValueName 'MinADKVersion' -ValueNonExist '10.1.19041' #https://docs.microsoft.com/en-us/mem/configmgr/core/plan-design/configs/support-for-windows-10#windows-10-adk
    #ConfigMgr Build;W10ADK
    Set-RFLHealthCheckDefaultValue -ValueName 'ADKMatrix' -ValueNonExist @('9040;10.1.18362/10.1.19041', '9049;10.1.19041', '9058;10.1.19041/10.1.20348/10.1.22000', '9068;10.1.19041/10.1.20348/10.1.22000')
    Set-RFLHealthCheckDefaultValue -ValueName 'ClientSettingsListName' -ValueNonExist @('BackgroundIntelligentTransfer', 'ClientCache', 'ClientPolicy', 'Cloud', 'ComplianceSettings', 'ComputerAgent', 'ComputerRestart', 'EndpointProtection', 'HardwareInventory', 'MeteredNetwork', 'MobileDevice', 'NetworkAccessProtection', 'PowerManagement', 'RemoteTools', 'SoftwareDeployment', 'SoftwareInventory', 'SoftwareMetering', 'SoftwareUpdates', 'StateMessaging', 'UserAndDeviceAffinity', 'DeliveryOptimization', 'SoftwareCenter', 'WindowsAnalytics')
    Set-RFLHealthCheckDefaultValue -ValueName 'MinBootVersion' -ValueNonExist '10.0.18363'

    Set-RFLHealthCheckDefaultValue -ValueName 'ADPageSize' -ValueNonExist 2000
    Set-RFLHealthCheckDefaultValue -ValueName 'ExcludeServers' -ValueNonExist @()
    Set-RFLHealthCheckDefaultValue -ValueName 'ProcessListSamplesMinutes' -ValueNonExist 1
    Set-RFLHealthCheckDefaultValue -ValueName 'ProcessListSamplesWaitSeconds' -ValueNonExist 10
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxCollectionMembershipDirectRule' -ValueNonExist 500
    Set-RFLHealthCheckDefaultValue -ValueName 'MinimumSQLMemory' -ValueNonExist '8192'
    Set-RFLHealthCheckDefaultValue -ValueName 'MinConfigMgrModuleVersion' -ValueNonExist 5.1702
    Set-RFLHealthCheckDefaultValue -ValueName 'MinConfigMgrVersion' -ValueNonExist '1702'
    Set-RFLHealthCheckDefaultValue -ValueName 'MaximumNumberOfMPS' -ValueNonExist 15
    Set-RFLHealthCheckDefaultValue -ValueName 'RolesThatMustBeInstalledPrimary' -ValueNonExist @('SMS Management Point', 'SMS Distribution Point', 'SMS Fallback Status Point', 'SMS SRS Reporting Point', 'SMS Software Update Point', 'SMS Application Web Service', 'SMS Portal Web Site')
    Set-RFLHealthCheckDefaultValue -ValueName 'RulesThatMustBeInstalledSecondary' -ValueNonExist @('SMS Management Point', 'SMS Distribution Point', 'SMS Fallback Status Point', 'SMS Software Update Point')
    Set-RFLHealthCheckDefaultValue -ValueName 'HiddenPackages' -ValueNonExist @('Configuration Manager Client Package', 'Configuration Manager Client Piloting Package')
    Set-RFLHealthCheckDefaultValue -ValueName 'RolesThatMustNotBeInstalledPrimary' -ValueNonExist @()
    Set-RFLHealthCheckDefaultValue -ValueName 'RolesThatMustNotBeInstalledSecondary' -ValueNonExist @()
    Set-RFLHealthCheckDefaultValue -ValueName 'DDRMinScheduleInMinutes' -ValueNonExist 10080
    Set-RFLHealthCheckDefaultValue -ValueName 'DDRMaxScheduleInMinutes' -ValueNonExist 10080
    Set-RFLHealthCheckDefaultValue -ValueName 'ForestDiscoveryMinScheduleInMinutes' -ValueNonExist 10080
    Set-RFLHealthCheckDefaultValue -ValueName 'ForestDiscoveryMaxScheduleInMinutes' -ValueNonExist 10080
    Set-RFLHealthCheckDefaultValue -ValueName 'SecurityGroupDiscoveryMinScheduleInMinutes' -ValueNonExist 1440
    Set-RFLHealthCheckDefaultValue -ValueName 'SecurityGroupDiscoveryMaxScheduleInMinutes' -ValueNonExist 10080
    Set-RFLHealthCheckDefaultValue -ValueName 'SecurityGroupDiscoveryMinExpiredLogon' -ValueNonExist 60
    Set-RFLHealthCheckDefaultValue -ValueName 'SecurityGroupDiscoveryMaxExpiredLogon' -ValueNonExist 90
    Set-RFLHealthCheckDefaultValue -ValueName 'SecurityGroupDiscoveryMinPasswordSet' -ValueNonExist 60
    Set-RFLHealthCheckDefaultValue -ValueName 'SecurityGroupDiscoveryMaxPasswordSet' -ValueNonExist 90
    Set-RFLHealthCheckDefaultValue -ValueName 'SystemDiscoveryMinScheduleInMinutes' -ValueNonExist 1440
    Set-RFLHealthCheckDefaultValue -ValueName 'SystemDiscoveryMaxScheduleInMinutes' -ValueNonExist 10080
    Set-RFLHealthCheckDefaultValue -ValueName 'SystemDiscoveryMinExpiredLogon' -ValueNonExist 60
    Set-RFLHealthCheckDefaultValue -ValueName 'SystemDiscoveryMaxExpiredLogon' -ValueNonExist 90
    Set-RFLHealthCheckDefaultValue -ValueName 'SystemDiscoveryMinPasswordSet' -ValueNonExist 60
    Set-RFLHealthCheckDefaultValue -ValueName 'SystemDiscoveryMaxPasswordSet' -ValueNonExist 90
    Set-RFLHealthCheckDefaultValue -ValueName 'UserMinScheduleInMinutes' -ValueNonExist 1440
    Set-RFLHealthCheckDefaultValue -ValueName 'UserMaxScheduleInMinutes' -ValueNonExist 10080
    Set-RFLHealthCheckDefaultValue -ValueName 'MinCollectionMembershipEvaluation' -ValueNonExist 5
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxCollectionMembershipEvaluation' -ValueNonExist 60
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxCollectionIncrementalUpdateWarning' -ValueNonExist 125
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxCollectionIncrementalUpdateError' -ValueNonExist 200
    Set-RFLHealthCheckDefaultValue -ValueName 'MinClientStatusSettingsCleanUpInterval' -ValueNonExist 31
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxClientStatusSettingsCleanUpInterval' -ValueNonExist 90
    Set-RFLHealthCheckDefaultValue -ValueName 'MinClientStatusSettingsDDRInactiveInterval' -ValueNonExist 7
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxClientStatusSettingsDDRInactiveInterval' -ValueNonExist 21
    Set-RFLHealthCheckDefaultValue -ValueName 'MinClientStatusSettingsHWInactiveInterval' -ValueNonExist 7
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxClientStatusSettingsHWInactiveInterval' -ValueNonExist 21
    Set-RFLHealthCheckDefaultValue -ValueName 'MinClientStatusSettingsPolicyInactiveInterval' -ValueNonExist 7
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxClientStatusSettingsPolicyInactiveInterval' -ValueNonExist 21
    Set-RFLHealthCheckDefaultValue -ValueName 'MinClientStatusSettingsStatusInactiveInterval' -ValueNonExist 7
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxClientStatusSettingsStatusInactiveInterval' -ValueNonExist 21
    Set-RFLHealthCheckDefaultValue -ValueName 'MinClientStatusSettingsSWInactiveInterval' -ValueNonExist 7
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxClientStatusSettingsSWInactiveInterval' -ValueNonExist 21
    Set-RFLHealthCheckDefaultValue -ValueName 'MinCacheSize' -ValueNonExist 5120
    Set-RFLHealthCheckDefaultValue -ValueName 'MinPolicyRequestAssignmentTimeout' -ValueNonExist 60
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxPolicyRequestAssignmentTimeout' -ValueNonExist 60
    Set-RFLHealthCheckDefaultValue -ValueName 'MinRebootLogoffNotificationCountdownDuration' -ValueNonExist 30
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxRebootLogoffNotificationCountdownDuration' -ValueNonExist 720
    Set-RFLHealthCheckDefaultValue -ValueName 'MinRebootLogoffNotificationFinalWindow' -ValueNonExist 15
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxRebootLogoffNotificationFinalWindow' -ValueNonExist 90
    Set-RFLHealthCheckDefaultValue -ValueName 'MinHardwareInventoryScheduleMinutes' -ValueNonExist 1440
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxHardwareInventoryScheduleMinutes' -ValueNonExist 10080
    Set-RFLHealthCheckDefaultValue -ValueName 'MinSoftwareInventoryScheduleMinutes' -ValueNonExist 1440
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxSoftwareInventoryScheduleMinutes' -ValueNonExist 10080
    Set-RFLHealthCheckDefaultValue -ValueName 'MinSoftwareDeploymentEvaluationScheduleMinutes' -ValueNonExist 1440
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxSoftwareDeploymentEvaluationScheduleMinutes' -ValueNonExist 10080
    Set-RFLHealthCheckDefaultValue -ValueName 'MinSoftwareUpdateScanScheduleMinutes' -ValueNonExist 1440
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxSoftwareUpdateScanScheduleMinutes' -ValueNonExist 10080
    Set-RFLHealthCheckDefaultValue -ValueName 'MinSoftwareUpdateReScanScheduleMinutes' -ValueNonExist 1440
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxSoftwareUpdateReScanScheduleMinutes' -ValueNonExist 10080
    Set-RFLHealthCheckDefaultValue -ValueName 'MinFallbackDPBoundaryGroupRelationship' -ValueNonExist 60
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxFallbackDPBoundaryGroupRelationship' -ValueNonExist 240
    Set-RFLHealthCheckDefaultValue -ValueName 'MinFallbackMPBoundaryGroupRelationship' -ValueNonExist 60
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxFallbackMPBoundaryGroupRelationship' -ValueNonExist 240
    Set-RFLHealthCheckDefaultValue -ValueName 'MinFallbackSMPBoundaryGroupRelationship' -ValueNonExist 60
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxFallbackSMPBoundaryGroupRelationship' -ValueNonExist 240
    Set-RFLHealthCheckDefaultValue -ValueName 'MinFallbackSUPBoundaryGroupRelationship' -ValueNonExist 60
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxFallbackSUPBoundaryGroupRelationship' -ValueNonExist 240
    Set-RFLHealthCheckDefaultValue -ValueName 'DatabaseFreeSpaceMinWarningValueAlert' -ValueNonExist 2
    Set-RFLHealthCheckDefaultValue -ValueName 'DatabaseFreeSpaceMaxWarningValueAlert' -ValueNonExist 5
    Set-RFLHealthCheckDefaultValue -ValueName 'DatabaseFreeSpaceMinCriticalValueAlert' -ValueNonExist 2
    Set-RFLHealthCheckDefaultValue -ValueName 'DatabaseFreeSpaceMaxCriticalValueAlert' -ValueNonExist 3
    Set-RFLHealthCheckDefaultValue -ValueName 'AntiMalwareLimitCPUUsageMax' -ValueNonExist 50
    Set-RFLHealthCheckDefaultValue -ValueName 'AntiMalwareDeleteQuarantinedFilesMax' -ValueNonExist 120
    Set-RFLHealthCheckDefaultValue -ValueName 'AntiMalwareDeleteQuarantinedFilesMin' -ValueNonExist 30
    Set-RFLHealthCheckDefaultValue -ValueName 'AntiMalwarePolicySettingsListName' -ValueNonExist @('Advanced', 'DefaultActions', 'DefinitionUpdates', 'ExclusionSettings', 'MicrosoftActiveProtectionService', 'RealTimeProtection', 'ScanSettings', 'ScheduledScans', 'ThreatOverrides')
    Set-RFLHealthCheckDefaultValue -ValueName 'TotalOfSites' -ValueNonExist 1
    Set-RFLHealthCheckDefaultValue -ValueName 'RegExLDAPDiscovery' -ValueNonExist 'LDAP:\/\/DC=(.+[^,])'
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxUpdateInSUPGroupWarning' -ValueNonExist 750
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxUpdateInSUPGroupError' -ValueNonExist 1000
    Set-RFLHealthCheckDefaultValue -ValueName 'MinSUPSummarizationTime' -ValueNonExist 720
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxSUPSummarizationTime' -ValueNonExist 10080
    Set-RFLHealthCheckDefaultValue -ValueName 'ADRLastRunMaxTime' -ValueNonExist 30
    Set-RFLHealthCheckDefaultValue -ValueName 'MinSUPAlertTime' -ValueNonExist 4320
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxSUPAlertTime' -ValueNonExist 10080
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxADRSchedule' -ValueNonExist 43200
    Set-RFLHealthCheckDefaultValue -ValueName 'MinADRSchedule' -ValueNonExist 240
    Set-RFLHealthCheckDefaultValue -ValueName 'MinClientUpgradeDays' -ValueNonExist 3
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxClientUpgradeDays' -ValueNonExist 14
    Set-RFLHealthCheckDefaultValue -ValueName 'ForestDiscoveryMaxDiscoveryTime' -ValueNonExist 14
    Set-RFLHealthCheckDefaultValue -ValueName 'DatabaseReplicationMaxLagTime' -ValueNonExist 2
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxLinkDatabaseReplicationSchedule' -ValueNonExist 30
    Set-RFLHealthCheckDefaultValue -ValueName 'MinLinkDatabaseReplicationSchedule' -ValueNonExist 10
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxAppDeploymentSummarization1' -ValueNonExist 720
    Set-RFLHealthCheckDefaultValue -ValueName 'MinAppDeploymentSummarization1' -ValueNonExist 30
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxAppDeploymentSummarization2' -ValueNonExist 2880
    Set-RFLHealthCheckDefaultValue -ValueName 'MinAppDeploymentSummarization2' -ValueNonExist 720
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxAppDeploymentSummarization3' -ValueNonExist 20160
    Set-RFLHealthCheckDefaultValue -ValueName 'MinAppDeploymentSummarization3' -ValueNonExist 5040
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxAppStatisticsSummarization1' -ValueNonExist 720
    Set-RFLHealthCheckDefaultValue -ValueName 'MinAppStatisticsSummarization1' -ValueNonExist 30
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxAppStatisticsSummarization2' -ValueNonExist 2880
    Set-RFLHealthCheckDefaultValue -ValueName 'MinAppStatisticsSummarization2' -ValueNonExist 720
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxAppStatisticsSummarization3' -ValueNonExist 20160
    Set-RFLHealthCheckDefaultValue -ValueName 'MinAppStatisticsSummarization3' -ValueNonExist 5040
    Set-RFLHealthCheckDefaultValue -ValueName 'GroupsNotAllowed' -ValueNonExist @('Access Control Assistance Operators', 'Account Operators', 'Administrators', 'Backup Operators', 'Certificate Service DCOM Access', 'Cryptographic Operators', 'Distributed COM Users', 'Event Log Readers', 'Guests', 'Hyper-V Administrators', 'IIS_IUSRS', 'Incoming Forest Trust Builders', 'Network Configuration Operators', 'Performance Log Users', 'Performance Monitor Users', 'Pre-Windows 2000 Compatible Access', 'Print Operators', 'RDS Endpoint Servers', 'RDS Management Servers', 'RDS Remote Access Servers', 'Remote Desktop Users', 'Remote Management Users', 'Replicator', 'Server Operators', 'Storage Replica Administrators', 'System Managed Accounts Group', 'Terminal Server License Servers', 'Windows Authorization Access Group', 'Allowed RODC Password Replication Group', 'Cert Publishers', 'Cloneable Domain Controllers', 'DHCP Administrators', 'DHCP Users', 'DnsAdmins', 'DnsUpdateProxy', 'Domain Admins', 'Domain Computers', 'Domain Controllers', 'Domain Guests', 'Enterprise Admins', 'Enterprise Key Admins', 'Enterprise Read-only Domain Controllers', 'Group Policy Creator Owners', 'Key Admins', 'Protected Users', 'RAS and IAS Servers', 'Read-only Domain Controllers', 'Schema Admins')
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxFullAdminWarning' -ValueNonExist 3
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxFullAdminError' -ValueNonExist 5
    Set-RFLHealthCheckDefaultValue -ValueName 'WarningCPUAverageUsage' -ValueNonExist 50
    Set-RFLHealthCheckDefaultValue -ValueName 'ErrorCPUAverageUsage' -ValueNonExist 75
    Set-RFLHealthCheckDefaultValue -ValueName 'WarningPercentageFreeSpace' -ValueNonExist 20
    Set-RFLHealthCheckDefaultValue -ValueName 'ErrorPercentageFreeSpace' -ValueNonExist 10
    Set-RFLHealthCheckDefaultValue -ValueName 'InboxFolderCountWarning' -ValueNonExist 30
    Set-RFLHealthCheckDefaultValue -ValueName 'InboxFolderCountError' -ValueNonExist 50
    Set-RFLHealthCheckDefaultValue -ValueName 'ApplicationFailurePercentageWarning' -ValueNonExist 25
    Set-RFLHealthCheckDefaultValue -ValueName 'ApplicationFailurePercentageError' -ValueNonExist 50
    Set-RFLHealthCheckDefaultValue -ValueName 'ComponentStatusMessageDateOld' -ValueNonExist 7
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxDPContentValudationSchedule' -ValueNonExist 20160
    Set-RFLHealthCheckDefaultValue -ValueName 'MinDPContentValudationSchedule' -ValueNonExist 4320
    Set-RFLHealthCheckDefaultValue -ValueName 'IgnoreCloudDP' -ValueNonExist $false
    Set-RFLHealthCheckDefaultValue -ValueName 'AddMultipleComponentStatusMessage' -ValueNonExist $false
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxApprovalRequestDate' -ValueNonExist 7
    Set-RFLHealthCheckDefaultValue -ValueName 'MinMDTVersion' -ValueNonExist '6.3.8450.1000'
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxDistributionInProgressWarning' -ValueNonExist 3
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxDistributionInProgressError' -ValueNonExist 7
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxPingResponseTimeWarning' -ValueNonExist 50
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxPingResponseTimeError' -ValueNonExist 100
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxPingDropPercentWarning' -ValueNonExist 5
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxPingDropPercentError' -ValueNonExist 10
    Set-RFLHealthCheckDefaultValue -ValueName 'PingDelay' -ValueNonExist 2
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxPingCount' -ValueNonExist 30
    Set-RFLHealthCheckDefaultValue -ValueName 'MinScheduleInMinutes' -ValueNonExist 240
    Set-RFLHealthCheckDefaultValue -ValueName 'FreeDiskSpacePercentageWarning' -ValueNonExist 20
    Set-RFLHealthCheckDefaultValue -ValueName 'FreeDiskSpacePercentageError' -ValueNonExist 10
    Set-RFLHealthCheckDefaultValue -ValueName 'MinimumSiteServerRAMGB' -ValueNonExist 8
    Set-RFLHealthCheckDefaultValue -ValueName 'MinimumSiteServerCPUCore' -ValueNonExist 8
    Set-RFLHealthCheckDefaultValue -ValueName 'MinimumRemoteServerRAMGB' -ValueNonExist 8
    Set-RFLHealthCheckDefaultValue -ValueName 'MinimumRemoteServerCPUCore' -ValueNonExist 4
    Set-RFLHealthCheckDefaultValue -ValueName 'DeploymentErrorsWarning' -ValueNonExist 5
    Set-RFLHealthCheckDefaultValue -ValueName 'DeploymentErrorsError' -ValueNonExist 10
    Set-RFLHealthCheckDefaultValue -ValueName 'IISRoles' -ValueNonExist @('SMS Distribution Point','SMS Management Point','SMS Software Update Point','SMS Fallback Status Point','SMS Application Web Service','SMS Portal Web Site')
    Set-RFLHealthCheckDefaultValue -ValueName 'IISExecutionTimeOut' -ValueNonExist 7200
    Set-RFLHealthCheckDefaultValue -ValueName 'IISmaxRequestLength' -ValueNonExist 20480
    Set-RFLHealthCheckDefaultValue -ValueName 'IISLogOldItemsWarning' -ValueNonExist 30
    Set-RFLHealthCheckDefaultValue -ValueName 'IISLogOldItemsError' -ValueNonExist 60
    Set-RFLHealthCheckDefaultValue -ValueName 'IISMaxBandwidth' -ValueNonExist -1
    Set-RFLHealthCheckDefaultValue -ValueName 'IISConnectionTimeout' -ValueNonExist 300
    Set-RFLHealthCheckDefaultValue -ValueName 'IISMaxConnections' -ValueNonExist 0
    Set-RFLHealthCheckDefaultValue -ValueName 'IISWSUSAppPoolCPUResetInterval' -ValueNonExist 900
    Set-RFLHealthCheckDefaultValue -ValueName 'IISWSUSAppPoolPingingEnabled' -ValueNonExist $false
    Set-RFLHealthCheckDefaultValue -ValueName 'IISWSUSAppPoolAppPoolRecyclePrivateMemory' -ValueNonExist $false
    Set-RFLHealthCheckDefaultValue -ValueName 'IISWSUSAppPoolAppPoolQueueLength' -ValueNonExist 30000
    Set-RFLHealthCheckDefaultValue -ValueName 'IISWSUSAppPoolRapidFailProtection' -ValueNonExist $false
    Set-RFLHealthCheckDefaultValue -ValueName 'IISWSUSAppPoolPeriodicRestartTime' -ValueNonExist 0
    Set-RFLHealthCheckDefaultValue -ValueName 'IISWSUSAppPoolPeriodicRestartRequests' -ValueNonExist 0
    Set-RFLHealthCheckDefaultValue -ValueName 'DPFeatures' -ValueNonExist 'Internet Information Services,IIS-WebServerRole;World Wide Web Services,IIS-WebServer;Common HTTP Features, IIS-CommonHttpFeatures;Default Document,IIS-DefaultDocument;Directory Browsing,IIS-DirectoryBrowsing;HTTP Errors,IIS-HttpErrors;Static Content,IIS-StaticContent;HTTP Redirection,IIS-HttpRedirect;Health and Diagnostics,IIS-HealthAndDiagnostics;HTTP Logging,IIS-HttpLogging;Performance Features,IIS-Performance;Static Content Compression,IIS-HttpCompressionStatic;Security,IIS-Security;Request Filtering,IIS-RequestFiltering;Windows Authentication,IIS-WindowsAuthentication;Application Development Features,IIS-ApplicationDevelopment;ISAPI Extensions,IIS-ISAPIExtensions;Web Management Tools,IIS-WebServerManagementTools;IIS Management Console,IIS-ManagementConsole;IIS 6 Management Compatibility,IIS-IIS6ManagementCompatibility;IIS Metabase and IIS 6 configuration compatibility,IIS-Metabase;IIS 6 WMI Compatibility,IIS-WMICompatibility;IIS Management Scripts and Tools,IIS-ManagementScriptingTools;Remote Differential Compression API Support,MSRDC-Infrastructure'
    Set-RFLHealthCheckDefaultValue -ValueName 'MPFeatures' -ValueNonExist 'Internet Information Services,IIS-WebServerRole;World Wide Web Services,IIS-WebServer;Common HTTP Features,IIS-CommonHttpFeatures;Default Document,IIS-DefaultDocument;Directory Browsing,IIS-DirectoryBrowsing;HTTP Errors,IIS-HttpErrors;Static Content,IIS-StaticContent;HTTP Redirection,IIS-HttpRedirect;Health and Diagnostics,IIS-HealthAndDiagnostics;HTTP Logging,IIS-HttpLogging;Logging Tools,IIS-LoggingLibraries;Request Monitor,IIS-RequestMonitor;Tracing,IIS-HttpTracing;Performance Features,IIS-Performance;Static Content Compression,IIS-HttpCompressionStatic;Security,IIS-Security;Request Filtering,IIS-RequestFiltering;Windows Authentication,IIS-WindowsAuthentication;Application Development Features,IIS-ApplicationDevelopment;.NET Extensibility 3.5,IIS-NetFxExtensibility;.NET Extensibility 4.6,IIS-NetFxExtensibility45;ISAPI Extensions,IIS-ISAPIExtensions;ISAPI Filters,IIS-ISAPIFilter;ASP.NET 3.5,IIS-ASPNET;ASP.NET 4.6,IIS-ASPNET45;Web Management Tools,IIS-WebServerManagementTools;IIS Management Console,IIS-ManagementConsole;IIS 6 Management Compatibility,IIS-IIS6ManagementCompatibility;IIS Metabase and IIS 6 configuration compatibility,IIS-Metabase;IIS 6 WMI Compatibility,IIS-WMICompatibility;IIS Management Scripts and Tools,IIS-ManagementScriptingTools;IIS Management Service,IIS-ManagementService;Background Intelligent Transfer Service (BITS),BITS;Background Intelligent Transfer Service (BITS) Server Extensions for File Upload,BITSExtensions-Upload'
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxThreads' -ValueNonExist 30
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxCPULoad' -ValueNonExist 20
    Set-RFLHealthCheckDefaultValue -ValueName 'AutoGrowthDateOld' -ValueNonExist 7
    Set-RFLHealthCheckDefaultValue -ValueName 'MinSUPGroupSummarizationTime' -ValueNonExist 43200
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxSUPGroupSummarizationTime' -ValueNonExist 86400
    Set-RFLHealthCheckDefaultValue -ValueName 'MinSUSDBSize' -ValueNonExist 30
    Set-RFLHealthCheckDefaultValue -ValueName 'MinConfigMgrDBSize' -ValueNonExist 75
    Set-RFLHealthCheckDefaultValue -ValueName 'ConfigMgrDBMinClients' -ValueNonExist 25000
    Set-RFLHealthCheckDefaultValue -ValueName 'LimitedCollectionToIgnore' -ValueNonExist @('All Unknown Computers','All Mobile Devices','All Desktop and Server Clients','All Provisioning Devices')
    Set-RFLHealthCheckDefaultValue -ValueName 'MaxLimitCollection' -ValueNonExist 1
    Set-RFLHealthCheckDefaultValue -ValueName 'MinMaxMifSize' -ValueNonExist 25000000
    Set-RFLHealthCheckDefaultValue -ValueName 'AADApplicationExpireWarning' -ValueNonExist 30
    #endregion

    #region set Override Rules
    Set-RFLHealthCheckRulesOverride -RuleID 1 -RuleName 'Server Down' -DefaultCategory 1 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 2 -RuleName 'Minimum ConfigMgr Build Version' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 3 -RuleName 'Latest ConfigMgr Build Version' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 4 -RuleName 'Enforce Enhanced Hash Algorithm' -DefaultCategory 2 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 5 -RuleName 'Enforce Message Signing' -DefaultCategory 2 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 6 -RuleName 'Use Encryption' -DefaultCategory 2 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 7 -RuleName 'Site Alert' -DefaultCategory 2 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 8 -RuleName 'Database Free Space Warning (Higher)' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 9 -RuleName 'Database Free Space Warning (Lower)' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 10 -RuleName 'Database Free Space Error (Higher)' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 11 -RuleName 'Database Free Space Error (Lower)' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 12 -RuleName 'List Roles Installed' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 13 -RuleName 'List Roles Not Installed' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 14 -RuleName 'Test MP (MPList) URL' -DefaultCategory 1 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 15 -RuleName 'Test MP (MPCert) URL' -DefaultCategory 1 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 16 -RuleName 'Test MP (SiteSign Cert) URL' -DefaultCategory 1 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 17 -RuleName 'MP Count' -DefaultCategory 6 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 18 -RuleName 'Application Catalog Web Service URL' -DefaultCategory 1 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 19 -RuleName 'Application Catalog Web Site URL' -DefaultCategory 1 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 20 -RuleName 'SUP (SimpleAuth) URL' -DefaultCategory 1 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 21 -RuleName 'SUP (Registration) URL' -DefaultCategory 6 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 22 -RuleName 'Application Catalog Integration' -DefaultCategory 7 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 23 -RuleName 'SQL Server Reporting Services (Reports) URL' -DefaultCategory 1 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 24 -RuleName 'SQL Server Reporting Services (ReportServer) URL' -DefaultCategory 1 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 25 -RuleName 'Minimum SQL Server' -DefaultCategory 3 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 26 -RuleName 'Minimum SQL Memory' -DefaultCategory 3 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 27 -RuleName 'Maximum SQL Memory' -DefaultCategory 3 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 28 -RuleName 'SQL Compatibility Level' -DefaultCategory 3 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 29 -RuleName 'SQL Server Installation Folder' -DefaultCategory 3 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 30 -RuleName 'SQL Server Data Folder' -DefaultCategory 3 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 31 -RuleName 'SQL Server Log Folder' -DefaultCategory 3 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 32 -RuleName 'SQL Server Data Folder (Install)' -DefaultCategory 3 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 33 -RuleName 'SQL Server Log Folder (Install)' -DefaultCategory 3 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 34 -RuleName 'SQL Server Data Folder (Log)' -DefaultCategory 3 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 35 -RuleName 'Account Usage' -DefaultCategory 8 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 36 -RuleName 'Account Usage (Software Distribution)' -DefaultCategory 8 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 37 -RuleName 'Account Usage (Admin)' -DefaultCategory 8 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 38 -RuleName 'Client Status (Clean Up) (Higher)' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 39 -RuleName 'Client Status (Clean Up) (Lower)' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 40 -RuleName 'Client Status (Heartbeat) (Higher)' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 41 -RuleName 'Client Status (Heartbeat) (Lower)' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 42 -RuleName 'Client Status (Hardware) (Higher)' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 43 -RuleName 'Client Status (Hardware) (Lower)' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 44 -RuleName 'Client Status (Client Policy) (Higher)' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 45 -RuleName 'Client Status (Client Policy) (Lower)' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 46 -RuleName 'Client Status (Status Message) (Higher)' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 47 -RuleName 'Client Status (Status Message) (Lower)' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 48 -RuleName 'Client Status (Software) (Higher)' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 49 -RuleName 'Client Status (Software) (Lower)' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 50 -RuleName 'Enabled Heartbeat Discovery' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 51 -RuleName 'Heartbeat Discovery Schedule (Lower)' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 52 -RuleName 'Forest Discovery' -DefaultCategory 10 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 53 -RuleName 'Forest Discovery Schedule (Lower)' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 54 -RuleName 'Forest Discovery AD Boundary' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 55 -RuleName 'Forest Discovery Subnet Boundary' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 56 -RuleName 'Network Discovery' -DefaultCategory 10 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 57 -RuleName 'Security Group Discovery' -DefaultCategory 10 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 58 -RuleName 'Security Group Discovery Schedule (Higher)' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 59 -RuleName 'Security Group Discovery Schedule (Lower)' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 60 -RuleName 'Security Group Discovery Expired Logon' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 61 -RuleName 'Security Group Discovery Expired Logon Days (Higher)' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 62 -RuleName 'Security Group Discovery Expired Logon Days (Lower)' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 63 -RuleName 'Security Group Discovery Expired Password' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 64 -RuleName 'Security Group Discovery Expired Password Days (Higher)' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 65 -RuleName 'Security Group Discovery Expired Password Days (Lower)' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 66 -RuleName 'Security Group Discovery LDAP Count' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 67 -RuleName 'Security Group Discovery LDAP Root' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 68 -RuleName 'System Discovery' -DefaultCategory 10 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 69 -RuleName 'System Discovery Schedule (Higher)' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 70 -RuleName 'System Discovery Schedule (Lower)' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 71 -RuleName 'System Discovery Expired Logon' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 72 -RuleName 'System Discovery Expired Logon Days (Higher)' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 73 -RuleName 'System Discovery Expired Logon Days (Lower)' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 74 -RuleName 'System Discovery Expired Password' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 75 -RuleName 'System Discovery Expired Password Days (Higher)' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 76 -RuleName 'System Discovery Expired Password Days (Lower)' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 77 -RuleName 'System Discovery LDAP Count' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 78 -RuleName 'System Discovery LDAP Root' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 79 -RuleName 'User Discovery' -DefaultCategory 10 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 80 -RuleName 'User Discovery Schedule (Higher)' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 81 -RuleName 'User Discovery Schedule (Lower)' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 82 -RuleName 'User Discovery LDAP Count' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 83 -RuleName 'User Discovery LDAP Root' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 84 -RuleName 'DP Group Has Members' -DefaultCategory 12 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 85 -RuleName 'DP Group Content In Sync' -DefaultCategory 12 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 86 -RuleName 'Collection Membership Evaluation Schedule (Higher)' -DefaultCategory 11 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 87 -RuleName 'Collection Membership Evaluation Schedule (Lower)' -DefaultCategory 11 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 88 -RuleName 'Device Collection Membership Rules Count' -DefaultCategory 11 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 89 -RuleName 'Device Collection Membership Count' -DefaultCategory 11 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 90 -RuleName 'Device Collection Limited by' -DefaultCategory 11 -Criticality 'High' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 91 -RuleName 'Device Collection Incremental Warning' -DefaultCategory 11 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 92 -RuleName 'Device Collection Incremental Error' -DefaultCategory 11 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 93 -RuleName 'Device Collection Direct Membership Rule Count' -DefaultCategory 11 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 94 -RuleName 'User Collection Membership Rules Count' -DefaultCategory 11 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 95 -RuleName 'User Collection Membership Count' -DefaultCategory 11 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 96 -RuleName 'User Collection Limited By' -DefaultCategory 11 -Criticality 'High' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 97 -RuleName 'User Collection Incremental Warning' -DefaultCategory 11 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 98 -RuleName 'User Collection Incremental Error' -DefaultCategory 11 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 99 -RuleName 'User Collection Direct Membership Rule Count' -DefaultCategory 11 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 100 -RuleName 'Deployment Empty Collection' -DefaultCategory 21 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 101 -RuleName 'Deployment to Root Collection' -DefaultCategory 21 -Criticality 'High' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 102 -RuleName 'Active Alerts' -DefaultCategory 18 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 103 -RuleName 'Alert Subscription Count' -DefaultCategory 18 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 104 -RuleName 'Alert Subscription' -DefaultCategory 18 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 105 -RuleName 'Device List - Non Client' -DefaultCategory 24 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 106 -RuleName 'Device List - Active Status' -DefaultCategory 24 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 107 -RuleName 'Device List - Blocked' -DefaultCategory 24 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 108 -RuleName 'Device List - Approved' -DefaultCategory 24 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 109 -RuleName 'Device List - Obsolete' -DefaultCategory 24 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 110 -RuleName 'Device List - Windows XP' -DefaultCategory 24 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 111 -RuleName 'Device List - WIndows XP x64' -DefaultCategory 24 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 112 -RuleName 'Device List - WIndows Vista' -DefaultCategory 24 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 113 -RuleName 'Device List - Windows 7' -DefaultCategory 24 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 114 -RuleName 'Device List - Windows 2003' -DefaultCategory 24 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 115 -RuleName 'Device List - Windows 2008' -DefaultCategory 24 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 116 -RuleName 'Device List - Windows 2008 R2' -DefaultCategory 24 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 117 -RuleName 'Device List - Windows Server 2012' -DefaultCategory 24 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 118 -RuleName 'Client Version Lower Site Server' -DefaultCategory 24 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 119 -RuleName 'Endpoint Protection - Unmanaged' -DefaultCategory 24 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 120 -RuleName 'Endpoint Protection - To Be Installed' -DefaultCategory 24 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 121 -RuleName 'Endpoint Protection - Install with Error' -DefaultCategory 24 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 122 -RuleName 'Endpoint Protection - Pending Reboot' -DefaultCategory 24 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 123 -RuleName 'Endpoint Protection - Infection Status Error' -DefaultCategory 24 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 124 -RuleName 'Endpoint Protection - Infection Status Pending' -DefaultCategory 24 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 125 -RuleName 'Endpoint Protection - Infection Status Unknown' -DefaultCategory 24 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 126 -RuleName 'Endpoint Protection - Policy Status Error' -DefaultCategory 24 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 127 -RuleName 'Endpoint Protection - Product Status Service Not Started' -DefaultCategory 24 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 128 -RuleName 'Endpoint Protection - Product Status Pending Full Scan' -DefaultCategory 24 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 129 -RuleName 'Endpoint Protection - Product Status Pending reboot' -DefaultCategory 24 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 130 -RuleName 'Endpoint Protection - Product Status Pending manual steps' -DefaultCategory 24 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 131 -RuleName 'Endpoint Protection - Product Status AV Signature Out to Date' -DefaultCategory 24 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 132 -RuleName 'Endpoint Protection - Product Status AS Signature Out to Date' -DefaultCategory 24 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 133 -RuleName 'Endpoint Protection - Product Status Missing quick scan' -DefaultCategory 24 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 134 -RuleName 'Endpoint Protection - Product Status Missing full scan' -DefaultCategory 24 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 135 -RuleName 'Endpoint Protection - Product Status Cleaning in progress' -DefaultCategory 24 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 136 -RuleName 'Endpoint Protection - Product Status non-genuine windows' -DefaultCategory 24 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 137 -RuleName 'Endpoint Protection - Product Status expired' -DefaultCategory 24 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 138 -RuleName 'Endpoint Protection - Product Status offline scan required' -DefaultCategory 24 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 139 -RuleName 'Client Settings - Deployments' -DefaultCategory 9 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 140 -RuleName 'Client Settings - Use New Software Center' -DefaultCategory 9 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 141 -RuleName 'Client Settings - Client Cache Size' -DefaultCategory 9 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 142 -RuleName 'Client Settings - Policy Request Schedule (Higher)' -DefaultCategory 9 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 143 -RuleName 'Client Settings - Policy Request Schedule (Lower)' -DefaultCategory 9 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 144 -RuleName 'Client Settings - User Policy' -DefaultCategory 9 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 145 -RuleName 'Client Settings - Reboot Logoff Notification Countdown Duration (Higher)' -DefaultCategory 9 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 146 -RuleName 'Client Settings - Reboot Logoff Notification Countdown Duration (Lower)' -DefaultCategory 9 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 147 -RuleName 'Client Settings - Reboot Logoff Notification Final Countdown (Higher)' -DefaultCategory 9 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 148 -RuleName 'Client Settings - Reboot Logoff Notification Final Countdown (Lower)' -DefaultCategory 9 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 149 -RuleName 'Client Settings - Hardware Inventory' -DefaultCategory 9 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 150 -RuleName 'Client Settings - Hardware Inventory Schedule (Higher)' -DefaultCategory 9 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 151 -RuleName 'Client Settings - Hardware Inventory Schedule (Lower)' -DefaultCategory 9 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 152 -RuleName 'Client Settings - Software Inventory' -DefaultCategory 9 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 153 -RuleName 'Client Settings - Software Inventory Schedule (Higher)' -DefaultCategory 9 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 154 -RuleName 'Client Settings - Software Inventory Schedule (Lower)' -DefaultCategory 9 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 155 -RuleName 'Client Settings - Software Reevaluation (Higher)' -DefaultCategory 9 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 156 -RuleName 'Client Settings - Software Reevaluation (Lower)' -DefaultCategory 9 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 157 -RuleName 'Client Settings - Software Updates' -DefaultCategory 9 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 158 -RuleName 'Client Settings - Software Update Scan Schedule (Higher)' -DefaultCategory 9 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 159 -RuleName 'Client Settings - Software Update Scan Schedule (Lower)' -DefaultCategory 9 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 160 -RuleName 'Client Settings - Software Update Reevaluation Schedule (Higher)' -DefaultCategory 9 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 161 -RuleName 'Client Settings - Software Update Reevaluation Schedule (Lower)' -DefaultCategory 9 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 162 -RuleName 'Client Settings - Software Update Reevaluation and Scan Schedule' -DefaultCategory 9 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 163 -RuleName 'Client Settings - Endpoint Protection' -DefaultCategory 9 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 164 -RuleName 'Maintenance Task - Backup SMS Site Server' -DefaultCategory 4 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 165 -RuleName 'Maintenance Task - Rebuild Indexes' -DefaultCategory 4 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 166 -RuleName 'Boundary Group - Site System Count' -DefaultCategory 13 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 167 -RuleName 'Boundary Group - Boundary Count' -DefaultCategory 13 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 168 -RuleName 'Boundary Group - Fallback DP Relationship (Higher)' -DefaultCategory 13 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 169 -RuleName 'Boundary Group - Fallback DP Relationship (Lower)' -DefaultCategory 13 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 170 -RuleName 'Boundary Group - Fallback MP Relationship (Higher)' -DefaultCategory 13 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 171 -RuleName 'Boundary Group - Fallback MP Relationship (Lower)' -DefaultCategory 13 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 172 -RuleName 'Boundary Group - Fallback SMP Relationship (Higher)' -DefaultCategory 13 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 173 -RuleName 'Boundary Group - Fallback SMP Relationship (Lower)' -DefaultCategory 13 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 174 -RuleName 'Boundary Group - Fallback SUP Relationship (Higher)' -DefaultCategory 13 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 175 -RuleName 'Boundary Group - Fallback SUP Relationship (Lower)' -DefaultCategory 13 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 176 -RuleName 'Endpoint Protection - Malware Detected' -DefaultCategory 14 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 177 -RuleName 'Endpoint Protection - Antimalware Policy Deployment Count' -DefaultCategory 14 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 178 -RuleName 'Endpoint Protection - Antimalware Policy Limit CPU' -DefaultCategory 14 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 179 -RuleName 'Endpoint Protection - Antimalware Policy Delete Quarantined Files Schedule (Higher)' -DefaultCategory 14 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 180 -RuleName 'Endpoint Protection - Antimalware Policy Delete Quarantined Files Schedule (Lower)' -DefaultCategory 14 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 181 -RuleName 'Endpoint Protection - Firewall Policy Deployment Count' -DefaultCategory 14 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 182 -RuleName 'Endpoint Protection - Firewall Policy Settings' -DefaultCategory 14 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 183 -RuleName 'Software Metering - Auto Create Rules' -DefaultCategory 15 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 184 -RuleName 'Software Metering - Disabled Rules' -DefaultCategory 15 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 185 -RuleName 'Boot Images - F8' -DefaultCategory 16 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 186 -RuleName 'Boot Images - Default Boot Image Usage' -DefaultCategory 16 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 187 -RuleName 'Boot Images - Boot Image Usage' -DefaultCategory 16 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 188 -RuleName 'Boot Images - PXE Architecture Count' -DefaultCategory 16 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 189 -RuleName 'Boot Images - Default Boot Image Binary Delta Replication' -DefaultCategory 16 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 190 -RuleName 'Boot Images - Default Boot Image Drivers' -DefaultCategory 16 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 191 -RuleName 'Boot Images - Binary Delta Replication' -DefaultCategory 16 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 192 -RuleName 'Boot Images - ADK Version' -DefaultCategory 16 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 193 -RuleName 'Software Update - Summarization (Higher)' -DefaultCategory 17 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 194 -RuleName 'Software Update - Summarization (Lower)' -DefaultCategory 17 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 195 -RuleName 'Software Update - Superseded' -DefaultCategory 17 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 196 -RuleName 'Software Update - Expired' -DefaultCategory 17 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 197 -RuleName 'Software Update - Missing Content' -DefaultCategory 17 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 198 -RuleName 'Software Update - Content not Deployed' -DefaultCategory 17 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 199 -RuleName 'Software Update Group - Deployments' -DefaultCategory 17 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 200 -RuleName 'Software Update Group - Warning Count' -DefaultCategory 17 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 201 -RuleName 'Software Update Group - Error Count' -DefaultCategory 17 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 202 -RuleName 'Software Update Group - Member Count' -DefaultCategory 17 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 203 -RuleName 'Software Update Group - Expired Updates' -DefaultCategory 17 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 204 -RuleName 'Software Update Group - Superseded Updates' -DefaultCategory 17 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 205 -RuleName 'Software Update Group - Missing Content' -DefaultCategory 17 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 206 -RuleName 'Software Update Group - Content not Deployed' -DefaultCategory 17 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 207 -RuleName 'Software Update Deployment' -DefaultCategory 17 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 208 -RuleName 'Software Update Deployment - Root Collection' -DefaultCategory 17 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 209 -RuleName 'Software Update Deployment - State Message' -DefaultCategory 17 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 210 -RuleName 'Software Update - ADR Deployment' -DefaultCategory 17 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 211 -RuleName 'Software Update - ADR Last Run Error' -DefaultCategory 17 -Criticality 'High' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 212 -RuleName 'Software Update - ADR Last Run Date and Time' -DefaultCategory 17 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 213 -RuleName 'Software Update - ADR Deployment Count' -DefaultCategory 17 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 214 -RuleName 'Software Update - ADR Root Collection' -DefaultCategory 17 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 215 -RuleName 'Software Update - ADR Schedule (Higher)' -DefaultCategory 17 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 216 -RuleName 'Software Update - ADR Schedule (Lower)' -DefaultCategory 17 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 217 -RuleName 'Software Update - ADR No Schedule' -DefaultCategory 17 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 218 -RuleName 'Software Update - ADR State Message' -DefaultCategory 17 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 219 -RuleName 'Software Update - ADR Alert' -DefaultCategory 17 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 220 -RuleName 'Software Update - ADR Alert Schedule (Higher)' -DefaultCategory 17 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 221 -RuleName 'Software Update - ADR Alert Schedule (Lower)' -DefaultCategory 17 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 222 -RuleName 'Hierarchy Settings - Auto Upgrade Client' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 223 -RuleName 'Hierarchy Settings - Auto Upgrade Client Schedule (Higher)' -DefaultCategory 2 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 224 -RuleName 'Hierarchy Settings - Auto Upgrade Client Schedule (Lower)' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 225 -RuleName 'Hierarchy Settings - Email Notification' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 226 -RuleName 'Hierarchy Settings - Email Notification Account' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 227 -RuleName 'Hierarchy Settings - Email Notification Security' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 228 -RuleName 'Active Directory Forests - Publishing Enabled' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 229 -RuleName 'Active Directory Forests - Last Discovery Error (Discovery - Access Denied)' -DefaultCategory 10 -Criticality 'High' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 230 -RuleName 'Active Directory Forests - Last Discovery Error (Discovery - Failed)' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 231 -RuleName 'Active Directory Forests - Last Discovery Error (Publishing - Failed)' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 232 -RuleName 'Active Directory Forests - Last Discovery Error (Publishing - Unknown)' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 233 -RuleName 'Active Directory Forests - Last Discovery Schedule' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 234 -RuleName 'Database Replication Status (Failed)' -DefaultCategory 19 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 235 -RuleName 'Database Replication Status (Degraded)' -DefaultCategory 19 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 236 -RuleName 'Database Replication Status (Unknown)' -DefaultCategory 19 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 237 -RuleName 'Database Replication Status - Site1 To Site2 Global Sync' -DefaultCategory 19 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 238 -RuleName 'Database Replication Status - Site2 To Site1 Global Sync' -DefaultCategory 19 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 239 -RuleName 'Database Replication Status - Enforce Enhanced Hash Algorithm' -DefaultCategory 19 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 240 -RuleName 'Database Replication Status - Link Schedule (Higher)' -DefaultCategory 19 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 241 -RuleName 'Database Replication Status - Link Schedule (Lower)' -DefaultCategory 19 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 242 -RuleName 'Status Summarization - Application Deployment 1st Interval (Higher)' -DefaultCategory 5 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 243 -RuleName 'Status Summarization - Application Deployment 1st Interval (Lower)' -DefaultCategory 5 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 244 -RuleName 'Status Summarization - Application Deployment 2nd Interval (Higher)' -DefaultCategory 5 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 245 -RuleName 'Status Summarization - Application Deployment 2nd Interval (Lower)' -DefaultCategory 5 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 246 -RuleName 'Status Summarization - Application Deployment 3rd Interval (Higher)' -DefaultCategory 5 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 247 -RuleName 'Status Summarization - Application Deployment 3rd Interval (Lower)' -DefaultCategory 5 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 248 -RuleName 'Status Summarization - Application Statistics 1st Interval (Higher)' -DefaultCategory 5 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 249 -RuleName 'Status Summarization - Application Statistics 1st Interval (Lower)' -DefaultCategory 5 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 250 -RuleName 'Status Summarization - Application Statistics 2nd Interval (Higher)' -DefaultCategory 5 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 251 -RuleName 'Status Summarization - Application Statistics 2nd Interval (Lower)' -DefaultCategory 5 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 252 -RuleName 'Status Summarization - Application Statistics 3rd Interval (Higher)' -DefaultCategory 5 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 253 -RuleName 'Status Summarization - Application Statistics 3rd Interval (Lower)' -DefaultCategory 5 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 254 -RuleName 'Account - Admin (RBAC)' -DefaultCategory 8 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 255 -RuleName 'Account - Service Account' -DefaultCategory 8 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 256 -RuleName 'Account - Full Admin Warning' -DefaultCategory 8 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 257 -RuleName 'Account - Full Admin Error' -DefaultCategory 8 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 258 -RuleName 'Account - Group Membership' -DefaultCategory 8 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 259 -RuleName 'CPU Usage - Error' -DefaultCategory 1 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 260 -RuleName 'CPU Usage - Warning' -DefaultCategory 1 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 261 -RuleName 'Short file name creation' -DefaultCategory 1 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 262 -RuleName 'ConfigMgr Installation on Root Drive' -DefaultCategory 1 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 263 -RuleName 'Distribution Point - Drive Free Space Error' -DefaultCategory 12 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 264 -RuleName 'Distribution Point - Drive Free Space Warning' -DefaultCategory 12 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 265 -RuleName 'Distribution Point - Group Membership Count' -DefaultCategory 12 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 266 -RuleName 'Distribution Point - Boundary Group Count' -DefaultCategory 12 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 267 -RuleName 'Distribution Point - Multicast' -DefaultCategory 12 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 268 -RuleName 'Distribution Point - PXE Password' -DefaultCategory 12 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 269 -RuleName 'Distribution Point - Responding to PXE' -DefaultCategory 12 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 270 -RuleName 'Distribution Point - PXE Unknown Machines' -DefaultCategory 12 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 271 -RuleName 'Distribution Point - Content Evaluation' -DefaultCategory 12 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 272 -RuleName 'Distribution Point - Content Evaluation Schedule (Higher)' -DefaultCategory 12 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 273 -RuleName 'Distribution Point - Content Evaluation Schedule (Lower)' -DefaultCategory 12 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 274 -RuleName 'Distribution Point - Content Evaluation Priority' -DefaultCategory 12 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 275 -RuleName 'Distribution Status - Default Boot Image' -DefaultCategory 20 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 276 -RuleName 'Distribution Status - Targeted Count' -DefaultCategory 20 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 277 -RuleName 'Distribution Status - Errors' -DefaultCategory 20 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 278 -RuleName 'Application - Hidden' -DefaultCategory 22 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 279 -RuleName 'Application - Devices with Failure (Error)' -DefaultCategory 22 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 280 -RuleName 'Application - Devices with Failure (Warning)' -DefaultCategory 22 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 281 -RuleName 'Application - Users with Failure (Error)' -DefaultCategory 22 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 282 -RuleName 'Application - Users with Failure (Warning)' -DefaultCategory 22 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 283 -RuleName 'Application - not used' -DefaultCategory 22 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 284 -RuleName 'Application - used by not deployed TS' -DefaultCategory 22 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 285 -RuleName 'NO_SMS_ON_DRIVE.SMS on SQL Drive' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 286 -RuleName 'Application - DT Folder does not exist' -DefaultCategory 22 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 287 -RuleName 'Application - DT allow User Interaction' -DefaultCategory 22 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 288 -RuleName 'Distribution Point Content - Not on DP Group' -DefaultCategory 22 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 289 -RuleName 'Distribution Point Content - Not on All DPs' -DefaultCategory 22 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 290 -RuleName 'Packages - Source Path does not exist' -DefaultCategory 23 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 291 -RuleName 'Packages - Source Path Local' -DefaultCategory 23 -Criticality 'High' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 292 -RuleName 'Packages - Deployment Count not used by TS' -DefaultCategory 23 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 293 -RuleName 'Packages - Deployment Count used by not deployed TS' -DefaultCategory 23 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 294 -RuleName 'Operating System - Source File Exist' -DefaultCategory 16 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 295 -RuleName 'Operating System - Used by TS' -DefaultCategory 16 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 296 -RuleName 'Operating System Installer - Source Exist' -DefaultCategory 16 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 297 -RuleName 'Operating System Installer - Used by TS' -DefaultCategory 16 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 298 -RuleName 'Task Sequence - Enabled' -DefaultCategory 16 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 299 -RuleName 'Task Sequence - Deployment Count' -DefaultCategory 16 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 300 -RuleName 'Task Sequence - Reboot to WinPE' -DefaultCategory 16 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 301 -RuleName 'Task Sequence - Boot Image' -DefaultCategory 16 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 302 -RuleName 'Task Sequence - Content Distributed' -DefaultCategory 16 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 303 -RuleName 'Task Sequence - Content Distributed with Error' -DefaultCategory 16 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 304 -RuleName 'Inbox - Count (Error)' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 305 -RuleName 'Inbox - Count (Warning)' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 306 -RuleName 'Driver Package' -DefaultCategory 16 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 307 -RuleName 'Component Status - Summarization' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 308 -RuleName 'Component Message' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 309 -RuleName 'Heartbeat Discovery Schedule (Higher)' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 310 -RuleName 'Forest Discovery Schedule (Higher)' -DefaultCategory 10 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 311 -RuleName 'SQL Server 2016 SP1' -DefaultCategory 3 -Criticality 'High' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 312 -RuleName 'WSUS Windows Internal Database' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 313 -RuleName 'NO_SMS_ON_DRIVE.SMS on SystemDrive' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 314 -RuleName 'Multiple Software Update Point (WSUS) using same SQL Server' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 315 -RuleName 'Pending Approval Request' -DefaultCategory 2 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 316 -RuleName 'Hierarchy Settings - Auto Upgrade Client Excluded specified clients from update' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 317 -RuleName 'Hierarchy Settings - Auto Upgrade Client Exclude Servers' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 318 -RuleName 'Hierarchy Settings - Auto Upgrade Client Automatically distribute client installation package' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 319 -RuleName 'Software Update - Windows 10 Express Updates' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 320 -RuleName 'Software Update - WSUS Cleanup' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 321 -RuleName 'Software Update - Synchronisation Alert' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 322 -RuleName 'Site Hierarchy - Conflicting Client Record' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 323 -RuleName 'Site Hierarchy - Client Approval Method - Manual' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 324 -RuleName 'Site Hierarchy - Client Approval Method - Automatically all' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 325 -RuleName 'Site Hierarchy - Script authors require approver' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 326 -RuleName 'Site Hierarchy - Clients prefer to use management point specified in boundary group' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 327 -RuleName 'ADK Version' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 328 -RuleName 'MDT Version' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 329 -RuleName 'ConfigMgr Services on ConfigMgr Servers' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 330 -RuleName 'Collection (Total) Incremental Warning' -DefaultCategory 11 -Criticality 'High' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 331 -RuleName 'Collection (Total) Incremental Error' -DefaultCategory 11 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 332 -RuleName 'Distribution Status - InProgress Warning' -DefaultCategory 20 -Criticality 'High' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 333 -RuleName 'Distribution Status - InProgress Error' -DefaultCategory 20 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 334 -RuleName 'Ping Response Time Warning' -DefaultCategory 1 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 335 -RuleName 'Ping Response Time Error' -DefaultCategory 1 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 336 -RuleName 'Ping Drop Percentace Warning' -DefaultCategory 1 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 337 -RuleName 'Ping Drop Percentace Error' -DefaultCategory 1 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 338 -RuleName 'Application - Number of DT' -DefaultCategory 22 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 339 -RuleName 'Intune Subscription' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 340 -RuleName 'IP Subnet Boundary' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 341 -RuleName 'Device Collection Schedule Too Often' -DefaultCategory 11 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 342 -RuleName 'User Collection Schedule Too Often' -DefaultCategory 11 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 343 -RuleName 'Boundary without GroupCount' -DefaultCategory 13 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 344 -RuleName 'Free Disk Space - Warning' -DefaultCategory 1 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 345 -RuleName 'Free Disk Space - Error' -DefaultCategory 1 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 346 -RuleName 'Total Site Server RAM Memory' -DefaultCategory 1 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 347 -RuleName 'Total Site Server CPU' -DefaultCategory 1 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 348 -RuleName 'Total Remote Server RAM Memory' -DefaultCategory 1 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 349 -RuleName 'Total Remote Server CPU' -DefaultCategory 1 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 350 -RuleName 'Empty Folder' -DefaultCategory 2 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 351 -RuleName 'Deployment Errors - Warning' -DefaultCategory 21 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 352 -RuleName 'Deployment Errors - Error' -DefaultCategory 21 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 353 -RuleName 'Task Sequence advertise to Unknown Computers for only ConfigMgr Clients' -DefaultCategory 21 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 354 -RuleName 'Baseline - not deployed' -DefaultCategory 21 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 355 -RuleName 'Baseline - disabled' -DefaultCategory 25 -Criticality 'Low' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 356 -RuleName 'Baseline - hidden' -DefaultCategory 25 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 357 -RuleName 'Baseline - failures warning' -DefaultCategory 25 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 358 -RuleName 'Baseline - failures error' -DefaultCategory 25 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 359 -RuleName 'Baseline - non-compliance warning' -DefaultCategory 25 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 360 -RuleName 'Baseline - non-compliance error' -DefaultCategory 25 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 361 -RuleName 'Baseline - evaluation Schedule Too Often' -DefaultCategory 21 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 362 -RuleName 'Account - Group Membership - Unable to collect' -DefaultCategory 8 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 363 -RuleName 'Component Message - Errors' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 364 -RuleName 'IIS - httpRuntime executionTimeout' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 365 -RuleName 'IIS - httpRuntime maxRequestLength' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 366 -RuleName 'IIS - Log Folder - Location' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 367 -RuleName 'IIS - Log Folder - Old Items Warning' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 368 -RuleName 'IIS - Log Folder - Old Items Error' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 369 -RuleName 'IIS - WSUS Administration - MaxBandwidth' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 370 -RuleName 'IIS - WSUS Administration - ConnectionTimeout' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 371 -RuleName 'IIS - WSUS Administration - MaxConnections' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 372 -RuleName 'IIS - WSUS Administration - AppPool - CPU Reset Interval' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 373 -RuleName 'IIS - WSUS Administration - AppPool - Pinging Enabled' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 374 -RuleName 'IIS - WSUS Administration - AppPool - Recycle Private Memory' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 375 -RuleName 'IIS - WSUS Administration - AppPool - Pool Queue Length' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 376 -RuleName 'IIS - WSUS Administration - AppPool - Rapid Fail Protection' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 377 -RuleName 'IIS - WSUS Administration - AppPool - Periodic Restart Time' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 378 -RuleName 'IIS - WSUS Administration - AppPool - Periodic Restart Requests' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 379 -RuleName 'Packages - Binary Delta Replication' -DefaultCategory 23 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 380 -RuleName 'Packages - Copy to a Package Share' -DefaultCategory 23 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 381 -RuleName 'Ping - Unable to ping computer' -DefaultCategory 1 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 382 -RuleName 'Boot Images - Copy to a Package Share' -DefaultCategory 16 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 383 -RuleName 'Hirarchy Updates' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 384 -RuleName 'Device Collection - invalid Schedule' -DefaultCategory 11 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 385 -RuleName 'User Collection - invalid Schedule' -DefaultCategory 11 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 386 -RuleName 'Windows Features - DP' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 387 -RuleName 'Windows Features - MP' -DefaultCategory 2 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 388 -RuleName 'Software Update - Packages - Binary Delta Replication' -DefaultCategory 17 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 389 -RuleName 'Software Update - Packages - Copy to a Package Share' -DefaultCategory 17 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 390 -RuleName 'SQL Server Jobs Disabled' -DefaultCategory 3 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 391 -RuleName 'SQL Server Jobs Enabled but not scheduled' -DefaultCategory 3 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 392 -RuleName 'SQL Server Jobs Last run status' -DefaultCategory 3 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 393 -RuleName 'SQL Server DB CPU Waits' -DefaultCategory 3 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 394 -RuleName 'SQL Server DB Information - Number of DB Files' -DefaultCategory 3 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 395 -RuleName 'SQL Server DB Information - Number of Log Files' -DefaultCategory 3 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 396 -RuleName 'SQL Server DB Information - File Count' -DefaultCategory 3 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 397 -RuleName 'SQL Server DB Information - File Growth Size' -DefaultCategory 3 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 398 -RuleName 'SQL Server DB Growth' -DefaultCategory 3 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 399 -RuleName 'Software Update Group Summary Task Schedule (Higher)' -DefaultCategory 17 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 400 -RuleName 'Software Update Group Summary Task Schedule (Lower)' -DefaultCategory 17 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 401 -RuleName 'Management Insights - Action Needed' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 402 -RuleName 'Site Feature - Release and off' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 403 -RuleName 'Client Settings - Enable user policy on clients' -DefaultCategory 9 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 404 -RuleName 'Device List - Windows 10' -DefaultCategory 24 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 405 -RuleName 'ADK Support for ConfigMgr' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 406 -RuleName 'SQL Server Service Account' -DefaultCategory 3 -Criticality 'Medium' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 407 -RuleName 'Maximum Allowable Inventory file size' -DefaultCategory 2 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 408 -RuleName 'Azure Active Directory Tenants - Application Secret Key Expirity (WARNING)' -DefaultCategory 1 -Criticality 'Medium' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 409 -RuleName 'Azure Active Directory Tenants - Application Secret Key Expirity (ERROR)' -DefaultCategory 1 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 410 -RuleName 'Cloud Management Gateway - Certificate Revocation List' -DefaultCategory 1 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 411 -RuleName 'Cloud Management Gateway - VM Size' -DefaultCategory 1 -Criticality 'Low' -DefaultClassification 'WARNING'
    Set-RFLHealthCheckRulesOverride -RuleID 412 -RuleName 'Cloud Management Gateway - Deployment Model' -DefaultCategory 1 -Criticality 'High' -DefaultClassification 'ERROR'
    Set-RFLHealthCheckRulesOverride -RuleID 413 -RuleName 'HTTPS or Enhanced HTTP enabled' -DefaultCategory 1 -Criticality 'High' -DefaultClassification 'ERROR'
    #endregion

    #region Script default variables

    $xmlList = @('SiteList', 'SiteRoleList', 'SiteRoleListWOCDP', 'SiteComponentList', 'SiteComponentManagerList', 'SMSPolProvComponentList', 'AlertList', 'MPComponentList', 'MPList', 
        'AppCatalogWebServiceList', 'AppCatalogWebSiteList', 'SUPList', 'SRSList', 'SQLList', 'SQLServerPrimarySiteList', 'SQLConfigurationList', 'SQLServerInformationList', 
        'ServiceAccountList', 'AdminAccountList', 'SQLServiceAccountList', 'GroupMembershipList', 'GroupMembershipErrorList', 'AccountDoesNotExist', 'ClientStatusSettings', 
        'DiscoveryMethodList', 'DPGroupList', 'CollectionMembershipEvaluation', 'DeviceCollectionList', 'CollectionDeviceFilterCount', 'UserCollectionList', 'CollectionUserFilterCount', 
        'DeploymentList', 'AlertSubscriptionList', 'DeviceList', 'EndpointProtectionList', 'ClientSettingsList', 'ClientSettingsSettingsList', 'MaintenanceTaskList', 'BoundaryGroupList', 
        'BoundaryGroupRelationshipList', 'DPList', 'SMPList', 'MalwareDetectedList', 'MalwarePolicyList', 'MalwarePolicySettingsList', 'MalwarePolicyList', 'SwMeteringSettingsList', 
        'SwMeteringRuleList', 'BootList', 'TaskSequenceList', 'TaskSequenceReferenceList', 'SoftwareUpdateSummarizationList', 'SoftwareUpdateList', 'SoftwareUpdateDeploymentList', 
        'SoftwareUpdateGroupList', 'SoftwareUpdateGroupDeploymentList', 'SoftwareUpdateADRList', 'SoftwareUpdateADRDeploymetList', 'AutoUpgradeConfigs', 'AutoUpgradeConfigsError', 
        'EmailNotificationList', 'ADForestlist', 'ADForestDiscoveryStatusList', 'DatabaseReplicationStatusList', 'DatabaseReplicationScheduleList', 'SiteSummarizationList', 
        'ProcessAverageTimeList', 'ProcessAverageTimeList', 'ServerRegistryInformation', 'DistributionPointList', 'DistributionPointInformationList', 'BoundarySiteSystemsList', 
        'DistributionPointDriveInfo', 'DistributionStatusList', 'ApplicationList', 'DeploymentTypeList', 'PathDTInformationList', 'DPContentList', 'DPGroupContentList', 'PackageList', 
        'PathPkgInformationList', 'OperatingSystemImageList', 'PathOSImgInformationList', 'OperatingSystemInstallerList', 'PathOSInstallerInformationList', 'TaskSequenceRebootOptions', 
        'inboxList', 'DriverPackageList', 'ComponentSummarizerList', 'ComponentStatusMessageList', 'ComponentStatusMessageListError', 'ComponentStatusMessageCompletedList', 'SUPWIDList', 
        'ServerNOSMSONDriveInformation', 'SUPSQL', 'ApprovalRequestList', 'SUPComponentSyncManager', 'SUPComponent', 'SiteDefinition', 'SoftwareVersionList', 'ServiceList', 'PingList', 
        'IntuneSubscription', 'Boundary', 'LogicalDiskInfoList', 'ComputerInformationList', 'FolderInformationList', 'AdvertisementList', 'BaselineList', 'BaselineDeploymentList', 'IISList', 
        'IISClientWebService', 'IISWebServerSetting', 'IISLogs', 'IisWebVirtualDirSetting', 'IIsApplicationPoolSetting', 'CMUpdates', 'OptionalFeaturesList', 'SoftwareUpdateDeploymentPackage', 
        'SQLJobs', 'SQLDBWaits', 'SQLDBInfo', 'SQLDBGrowth', 'sitesummarytask', 'ManagementInsights', 'SiteFeature', 'ServerDown', 'ServerHTTPAccessInformation', 'AADTenant', 'AADApplication',
        'CloudManagementGateway'
    )

    $xmlList | ForEach-Object {
        $item = $_
        New-Variable -Name "$item" -Value @() -Force -Option AllScope -Scope Script
    }
    #endregion

    #region HealthCheck Table
    Write-RFLLog -logtype "Info" -logmessage "Default Reporting Table"
    $Script:HealthCheckData = New-Object system.Data.DataTable "HealthCheck"
    $newCol = New-Object system.Data.DataColumn "Category",([string])
    $Script:HealthCheckData.Columns.Add($newCol)
    $newCol = New-Object system.Data.DataColumn "Classification",([string])
    $Script:HealthCheckData.Columns.Add($newCol)
    $newCol = New-Object system.Data.DataColumn "Description",([string])
    $Script:HealthCheckData.Columns.Add($newCol)
    $newCol = New-Object system.Data.DataColumn "Comment",([string])
    $Script:HealthCheckData.Columns.Add($newCol)
    $newCol = New-Object system.Data.DataColumn "RuleID",([int])
    $Script:HealthCheckData.Columns.Add($newCol)
    $newCol = New-Object system.Data.DataColumn "Criticality",([string])
    $Script:HealthCheckData.Columns.Add($newCol)
    $newCol = New-Object system.Data.DataColumn "CriticalityID",([int])
    $Script:HealthCheckData.Columns.Add($newCol)
    #endregion

    #region check SMS Provider Info
    Write-RFLLog -logtype "Info" -logmessage "Trying to identify SMS Provider Server Name."
    $SMSProviderServer = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Wow6432Node\Microsoft\ConfigMgr10\AdminUI\Connection" -ErrorAction SilentlyContinue).Server
    if ([string]::IsNullOrEmpty($SMSProviderServer)) {
        Write-RFLLog -logtype "Error" -logmessage "Unable to identify SMS Provider Server Name. Confirm the ConfigMgr Console is installed and has been opened at least once."
        return
    } else {
        Write-RFLLog -logtype "Info" -logmessage "SMS Provider Server is '$($SMSProviderServer)'"
    }
    #endregion

    #region check if running from Site Server
    Write-RFLLog -logtype "Info" -logmessage "Trying to if SCCM is installed."
    $CMInstallDir = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\SMS\Identification" -ErrorAction SilentlyContinue).'Installation Directory'
    if ([string]::IsNullOrEmpty($CMInstallDir)) {
        Write-RFLLog -logtype "Error" -logmessage "Unable to identify if the ConfigMgr is installed on this server."
        return
    } else {
        Write-RFLLog -logtype "Info" -logmessage "ConfigMgr installation path is '$($CMInstallDir)'"
    }
    #endregion

    #region HealthCheck
    try {
        Write-RFLLog -logtype "Info" -logmessage "Trying to locate ConfigMgr Console."
        #region Import PowerShell Modules
        $CurrentDriveLetter = (get-location).Drive.Name
        $ModulePath = $env:SMS_ADMIN_UI_PATH
        if ($null -eq $ModulePath) {
	        $ModulePath = (Get-ItemProperty -Path "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Environment").SMS_ADMIN_UI_PATH
        }
        if ($null -eq $ModulePath) {
            Write-RFLLog -logtype "Error" -logmessage "ConfigMgr Console is not installed or SMS_ADMIN_UI_PATH variable does not exist"
            return
        }

        #region Start PInvoke Code
        #based on code from https://smsagent.wordpress.com/2015/07/22/retrieving-configmgr-status-messages-with-powershell/
        $sigFormatMessage = @'
[DllImport("kernel32.dll")]
public static extern uint FormatMessage(uint flags, IntPtr source, uint messageId, uint langId, StringBuilder buffer, uint size, string[] arguments);
'@

        $sigGetModuleHandle = @'
[DllImport("kernel32.dll")]
public static extern IntPtr GetModuleHandle(string lpModuleName);
'@

        $sigLoadLibrary = @'
[DllImport("kernel32.dll")]
public static extern IntPtr LoadLibrary(string lpFileName);
'@

        $Win32FormatMessage = Add-Type -MemberDefinition $sigFormatMessage -name "Win32FormatMessage" -namespace Win32Functions -PassThru -Using System.Text
        $Win32GetModuleHandle = Add-Type -MemberDefinition $sigGetModuleHandle -name "Win32GetModuleHandle" -namespace Win32Functions -PassThru -Using System.Text
        $Win32LoadLibrary = Add-Type -MemberDefinition $sigLoadLibrary -name "Win32LoadLibrary" -namespace Win32Functions -PassThru -Using System.Text
        #endregion

        #region import ConfigMgr DLL's
        Write-RFLLog -logtype "Info" -logmessage "Importing ConfigMgr Console DLL 'srvmsgs.dll'"
        $ptrSrvFoo = $Win32LoadLibrary::LoadLibrary("$($CMInstallDir)\bin\X64\system32\smsmsgs\srvmsgs.dll")
        $ptrSrvModule = $Win32GetModuleHandle::GetModuleHandle("$($CMInstallDir)\bin\X64\system32\smsmsgs\srvmsgs.dll")

        Write-RFLLog -logtype "Info" -logmessage "Importing ConfigMgr Console DLL 'provmsgs.dll'"
        $ptrPrvFoo = $Win32LoadLibrary::LoadLibrary("$($CMInstallDir)\bin\X64\system32\smsmsgs\provmsgs.dll")
        $ptrPrvModule = $Win32GetModuleHandle::GetModuleHandle("$($CMInstallDir)\bin\X64\system32\smsmsgs\provmsgs.dll")

        Write-RFLLog -logtype "Info" -logmessage "Importing ConfigMgr Console DLL 'climsgs.dll'"
        $ptrCliFoo = $Win32LoadLibrary::LoadLibrary("$($CMInstallDir)\bin\X64\system32\smsmsgs\climsgs.dll")
        $ptrCliModule = $Win32GetModuleHandle::GetModuleHandle("$($CMInstallDir)\bin\X64\system32\smsmsgs\climsgs.dll")

        $sizeOfBuffer = [int]16384
        $stringArrayInput = {"%1","%2","%3","%4","%5", "%6", "%7", "%8", "%9"}
        $flags = 0x00000800 -bor 0x00000200
        $stringOutput = New-Object System.Text.StringBuilder $sizeOfBuffer
        #endregion

        #region Import ConfigMgr Certificate for powershell
        Write-RFLLog -logtype "Info" -logmessage "SMS_ADMIN_UI_PATH found. Location set to '$($ModulePath)'"
        $ModulePath = $ModulePath.Replace("bin\i386","bin\ConfigurationManager.psd1")

        Write-RFLLog -logtype "Info" -logmessage "Checking ConfigMgr Certificate"
        $Certificate = Get-AuthenticodeSignature -FilePath "$ModulePath" -ErrorAction SilentlyContinue
        $CertStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("TrustedPublisher")
        try {
            $CertStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::MaxAllowed)
            $Certexist = $null -ne ($CertStore.Certificates | Where-Object {$_.thumbprint -eq $Certificate.SignerCertificate.Thumbprint})

            if ($Certexist -eq $false) {
                $CertStore.Add($Certificate.SignerCertificate)
                Write-RFLLog -logtype "Info" -logmessage "Certificate successfully checked"
            }
        } catch {
            $Global:ErrorCapture += $_
            Write-RFLLog -logtype "EXCEPTION" -logmessage "Unable to import ConfigMgr Certificate into certificate Store"
            Write-RFLLog -logtype "EXCEPTION" -logmessage "Error Message: '$($_)'"
            return
        } finally {
            $CertStore.Close()
        }
        #endregion

        Write-RFLLog -logtype "Info" -logmessage "Importing ConfigMgr DLLs"
        import-module $ModulePath -force
        $PSDriveCount = (get-psdrive -PSProvider CMSite -erroraction SilentlyContinue | Measure-Object).Count
        if ($PSDriveCount -lt 1) {
            $PSDriveCreated = $false
            Write-RFLLog -logtype "Info" -logmessage "Connecting ConfigMgr"
            foreach($item in $AuthorizedSiteCodes.Split(',')) {
                try {
                    new-psdrive -Name $item -PSProvider "AdminUI.PS.Provider\CMSite" -Root $SMSProviderServer | Out-Null
                    Write-RFLLog -logtype "Info" -logmessage "Connected to ConfigMgr Site Code '$($item)' on server '$($SMSProviderServer)'"
                    $PSDriveCreated = $true
                    break
                } catch {
                    $Global:ErrorCapture += $_
                    Write-RFLLog -logtype "Error" -logmessage "Unable to connect to ConfigMgr Site Code '$($item)' on server '$($SMSProviderServer)'"
                }
            }
            if ($PSDriveCreated -eq $false) {
                Write-RFLLog -logtype "Error" -logmessage "Unable to import ConfigMgr DLLs"
                return
            }
        } elseif ($PSDriveCount -gt 1) {
            Write-RFLLog -logtype "Error" -logmessage "Multiple ConfigMgr Site Code found"
            return
        }

        $ModuleConfigMgr = Get-Module -Name ConfigurationManager
        $ModuleConfigMgrVersionBuild = $ModuleConfigMgr.Version.Minor
        if ($ModuleConfigMgr.Version -lt $script:MinConfigMgrModuleVersion) {
            if ($ModuleConfigMgrVersionBuild -lt $script:MinConfigMgrVersion) {
                Write-RFLLog -logtype "WARNING" -logmessage "ConfigMgr Console ('$($ModuleConfigMgr.Version)') is below minimum supported version ('$($script:MinConfigMgrVersion)')"
            }
        }

        $PSDriveName = "$((get-psdrive -PSProvider CMSite -erroraction SilentlyContinue).Name)"

        if ($PSDriveName -notin $AuthorizedSiteCodes.Split(',')) {
            Write-RFLLog -logtype "ERROR" -logmessage "Connected Site Code '$($PSDriveName)' is not in the list of Registered Site Codes ($($AuthorizedSiteCodes))"
            return
        }

        Set-Location -Path "$($PSDriveName):"
        $CMPSSuppressFastNotUsedCheck = $true

        Write-RFLLog -logtype "Info" -logmessage "DLLs Imported Successfully"
        #endregion

        #region Collecting Data
        Write-RFLLog -logtype "Info" -logmessage "Collecting ConfigMgr Data"
        $Script:StartCollectingDateTime = get-date

        #region Site Information
        Write-RFLLog -logtype "Info" -logmessage "Getting 'Site' List Information"
                $FileToImport = "$($SaveToFolder)\SiteList.xml"
        if (Test-Path -LiteralPath $FileToImport) {
            Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
            New-Variable -Name "SiteList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
        } else {
            $SiteList += Get-CMSite
            Export-RFLXMLFile -VariableName 'SiteList'
        }

        #getting the main ConfigMgr Site (Primary Site) - There is no CAS here
        $MainSiteCode = ($SiteList | Where-Object {$_.Type -eq 2}).SiteCode

        #check if there is cas, if yes, stop
        if (($SiteList | Where-Object {$_.Type -eq 4} | Measure-Object).Count -gt 0) {
            Write-RFLLog -logtype "Error" -logmessage "HealthCheck Toolkit is not supported to run in a CAS environment"
            return
        }
        #endregion

        #region Site Role List
        Write-RFLLog -logtype "Info" -logmessage "Getting 'Site Role' List Information"
        $FileToImport = "$($SaveToFolder)\SiteRoleList.xml"
        if (Test-Path -LiteralPath $FileToImport) {
            Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
            New-Variable -Name "SiteRoleList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
        } else {
            $SiteList | Select-Object SiteCode | Get-Unique -AsString | ForEach-Object {
                Write-RFLLog -logtype "Info" -logmessage "Getting Site Role List Information for Site '$($_.SiteCode)'"

                Get-CMSiteRole -SiteCode $_.SiteCode | ForEach-Object {
                    $item = $_ 
                    $Servername = ($item.NetworkOSPath.Replace('\\',''))
                    if ($script:ExcludeServers -notcontains $Servername) {
                        $SiteRoleList += $item
                    }
                }
            }
            Export-RFLXMLFile -VariableName 'SiteRoleList'
        }
        #endregion

        #region Site Role List without CloudDP
        Write-RFLLog -logtype "Info" -logmessage "Getting 'Site Role' List Information"
        $FileToImport = "$($SaveToFolder)\SiteRoleListWOCDP.xml"
        if (Test-Path -LiteralPath $FileToImport) {
            Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
            New-Variable -Name "SiteRoleListWOCDP" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
        } else {
            $SiteRoleList | ForEach-Object {
                $item = $_
                $RemoteComputer = ($item.NetworkOSPath.Replace('\\',''))
                $CloudDP = $false

                if ($item.NALType -ne 'Windows Azure') {
                    $CloudDPInfo = $item | Where-Object {($_.NetworkOSPath -eq $item.NetworkOSPath) -and ($_.RoleName -eq 'SMS Distribution Point')}
                    if ($null -ne $CloudDPInfo) {
                        if ($CloudDPInfo.Props | Where-Object {($_.PropertyName -eq 'IsCloud') -and ($_.Value -eq 1)}) {
                            $CloudDP = $true
                        }
                    }

                    if ($CloudDP -eq $false) {
                        $SiteRoleListWOCDP += $item
                    }
                }
            }
            Export-RFLXMLFile -VariableName 'SiteRoleListWOCDP'
        }
        #endregion

        #region Site Component List
        $FileToImport = "$($SaveToFolder)\SiteComponentList.xml"
        if (Test-Path -LiteralPath $FileToImport) {
            Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
            New-Variable -Name "SiteComponentList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
        } else {            
            $SiteList | Select-Object SiteCode | Get-Unique -AsString | ForEach-Object {
                Write-RFLLog -logtype "Info" -logmessage "Getting Site Component List Information for Site '$($_.SiteCode)'"
                $SiteComponentList += Get-CMSiteComponent -SiteCode $_.SiteCode
                Export-RFLXMLFile -VariableName 'SiteComponentList'
            }
        }
        #endregion
        
        #region Rules

        #region sub-Rules
        $arrRuleID = @(4,5,239)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            $FileToImport = "$($SaveToFolder)\SiteComponentManagerList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "SiteComponentManagerList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $SiteComponentManagerList += $SiteComponentList | where-object {$_.ComponentName -eq 'SMS_SITE_COMPONENT_MANAGER'}
                Export-RFLXMLFile -VariableName 'SiteComponentManagerList' -ClearVariable
            }
        }
        #endregion
        
        #region sub-Rules
        $arrRuleID = @(6)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            $FileToImport = "$($SaveToFolder)\SMSPolProvComponentList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "SMSPolProvComponentList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $SMSPolProvComponentList += $SiteComponentList | where-object {$_.ComponentName -eq 'SMS_POLICY_PROVIDER'}
                Export-RFLXMLFile -VariableName 'SMSPolProvComponentList' -ClearVariable
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(7,8,9,10,11,102,104,321)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\AlertList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "AlertList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $AlertList += Get-CMAlert
                Export-RFLXMLFile -VariableName 'AlertList' -ClearVariable
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(14,15,16)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            $FileToImport = "$($SaveToFolder)\MPComponentList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "MPComponentList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $MPComponentList += $SiteComponentList | where-object {$_.ComponentName -eq 'SMS_MP_CONTROL_MANAGER'}
                Export-RFLXMLFile -VariableName 'MPComponentList'
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(14,15,16,17,170,171)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            $FileToImport = "$($SaveToFolder)\MPList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "MPList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $MPList += $SiteRoleList | Where-Object {$_.RoleName -eq 'SMS Management Point'}
                Export-RFLXMLFile -VariableName 'MPList'
            }
        }
        #endregion

        #region sub-Rules 
        $arrRuleID = @(14)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            Test-RFLUrl -ListOfServers $MPlist -ServerType 'mplist' -RuleID 14 -CommentIDError 5004 -MessageIDError 3128 -CommentIDException 5004
        }
        #endregion

        #region sub-Rules 
        $arrRuleID = @(15)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            Test-RFLUrl -ListOfServers $MPlist -ServerType 'mpcert' -RuleID 15 -CommentIDError 5004 -MessageIDError 3128 -CommentIDException 5004
        }
        #endregion

        #region sub-Rules 
        $arrRuleID = @(16)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            Test-RFLUrl -ListOfServers $MPlist -ServerType 'sitesigncert' -RuleID 16 -CommentIDError 5004 -MessageIDError 3128 -CommentIDException 5004
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(18,22)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\AppCatalogWebServiceList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "AppCatalogWebServiceList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $AppCatalogWebServiceList +=  $SiteRoleList | Where-Object {$_.RoleName -eq 'SMS Application Web Service'}
                Export-RFLXMLFile -VariableName 'AppCatalogWebServiceList'
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(18)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            Test-RFLUrl -ListOfServers $AppCatalogWebServiceList -ServerType 'appcatalogwebservice' -RuleID 18 -CommentIDError 5004 -MessageIDError 3128 -CommentIDException 5004
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(19,22)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\AppCatalogWebSiteList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "AppCatalogWebSiteList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $AppCatalogWebSiteList +=  $SiteRoleList | Where-Object {$_.RoleName -eq 'SMS Portal Web Site'}
                Export-RFLXMLFile -VariableName 'AppCatalogWebSiteList'
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(19)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            Test-RFLUrl -ListOfServers $AppCatalogWebSiteList -UserCredentials $true -ServerType 'appcatalogwebsite' -RuleID 19 -CommentIDError 5004 -MessageIDError 3128 -CommentIDException 5004
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(20,21,157,158,159,160,161,162,174,175,312,314)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\SUPList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "SUPList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $SUPList +=  $SiteRoleList | Where-Object {$_.RoleName -eq 'SMS Software Update Point'}
                Export-RFLXMLFile -VariableName 'SUPList'
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(20)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            Test-RFLUrl -ListOfServers $SUPList -ServerType 'wsussimpleauth' -RuleID 20 -CommentIDError 5004 -MessageIDError 3128 -CommentIDException 5004
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(21)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $SUPList | ForEach-Object {
                $HTTPPort = ($_.Props | Where-Object {$_.PropertyName -eq 'WSUSIISPort' }).Value
                $HTTPProtocol = 'HTTP'
                if ($_.sslState -in (1,3)) {
                    $HTTPProtocol = 'HTTPS'
                    $HTTPPort = ($_.Props | Where-Object {$_.PropertyName -eq 'WSUSIISSSLPort' }).Value
                }
                $servername = $_.NetworkOSPath -replace '\\', ''
                $url = "$($HTTPProtocol)://$($servername):$($HTTPPort)/SimpleAuthWebService/SimpleAuth.asmx"
                Write-RFLLog -logtype "Info" -logmessage "Checking URL '$($url)', Service Method 'GetAuthorizationCookie'"
                $code = {
                    Param (
                        $url,
                        $servername
                    )
                    try {
                        $SUPProxy = New-WebServiceProxy -Uri $url -UseDefaultCredential
                        $SUPProxy.GetAuthorizationCookie('ConfigMgrHealthCheckID', $null, 'CreatedByConfigMgrHealthCheck') | out-null
                        New-Object -TypeName PSObject -Property @{'CommentIDError' = 5004; 'MessageIDError' = 3128; 'RuleInfo' = 21; 'ServerName' = $ServerName; 'StatusCode' = 200; 'URL' = $url }
                    } catch {
                        $Global:ErrorCapture += $_
                        New-Object -TypeName PSObject -Property @{'CommentIDError' = 5004; 'MessageIDError' = 3128; 'RuleInfo' = 21; 'ServerName' = $ServerName; 'StatusCode' = "Unable to connect"; 'URL' = $url }
                    }
                }
                $Script:ServerHTTPAccessInformation += Execute-RFLRunSpace -code $Code -ParameterList @($url, $servername)                
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(23,24)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\SRSList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "SRSList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $SRSList +=  $SiteRoleList | Where-Object {$_.RoleName -eq 'SMS SRS Reporting Point'}
                Export-RFLXMLFile -VariableName 'SRSList'
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(23)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            Test-RFLUrl -ListOfServers $SRSList -UserCredentials $true -ServerType 'ssrsreporturi' -RuleID 23 -CommentIDError 5004 -MessageIDError 3128 -CommentIDException 5004
        }
        #endregion

        #region sub-Rules 
        $arrRuleID = @(24)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            Test-RFLUrl -ListOfServers $SRSList -UserCredentials $true -ServerType 'ssrsreportserveruri' -RuleID 24 -CommentIDError 5004 -MessageIDError 3128 -CommentIDException 5004
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(25,26,27,28,311)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            $FileToImport = "$($SaveToFolder)\SQLList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "SQLList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $SQLList += $SiteRoleList | Where-Object {$_.RoleName -eq 'SMS SQL Server'}
                Export-RFLXMLFile -VariableName 'SQLList' -ClearVariable
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(25,26,27,28,29,30,31,32,33,34,285,311,390,391,392,393,394,395,396,397,406)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\SQLServerPrimarySiteList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "SQLServerPrimarySiteList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {                
                $SiteList | Where-Object {$_.Type -eq 2} | Select-Object SiteCode | Get-Unique -AsString | ForEach-Object {
                    $item = $_
                    $SQLServerPrimarySiteList += $SiteRoleList | Where-Object {($_.SiteCode -eq $item.SiteCode) -and ($_.RoleName -eq 'SMS SQL Server')}
                }
                Export-RFLXMLFile -VariableName 'SQLServerPrimarySiteList'
            }
        }
        #endregion

        #region sub-Rules 
        $arrRuleID = @(25,26,27,28,311)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\SQLConfigurationList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "SQLConfigurationList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $SQLServerPrimarySiteList | ForEach-Object { 
                    $item = $_
                    $arrPropList = $item.PropLists[0].values.split(',').Trim()
                    $ServerName = $item.NetworkOSPath.Replace('\\','')
                    $DbName = $arrPropList[2]

                    if ($arrPropList[2].IndexOf('\') -ge 0) {
                        $ServerName += "\{0}" -f $arrPropList[2].split('\')[0]
                        $DbName = $arrPropList[2].split('\')[1]
                    }

                    Write-RFLLog -logtype "Info" -logmessage "Getting SQL Server '$($ServerName)' Information"
                    $code = {
                        Param (
                            $servername,
                            $databasename
                        )
                        $ReturnInfo = @()
                        #connect to SQL
                        $SQLOpen = $false
                        $conn = New-Object System.Data.SqlClient.SqlConnection
                        try {
                            $conn.ConnectionString = "Data Source=$($servername);Initial Catalog=$($databasename);trusted_connection = true;"
                            $conn.Open()
                            $SQLOpen = $true
                        } catch {
                            $Global:ErrorCapture += $_
                            $ReturnInfo += New-Object -TypeName PSObject -Property @{'Success' = $false; 'ServerName' = $arrPropList; 'Version' = ''; 'MinMemory' = 0; 'MaxMemory' = 0; 'CompLevel' = 0; 'Database' = ''; 'ConnectionType' = 'SQL Server (SQL TCP)' ; 'Error'= $_}
                        }

                        if ($SQLOpen -eq $true) {
                            try {
                                $SqlCommand = $Conn.CreateCommand()
                                $SqlCommand.CommandTimeOut = 0
                                $SqlCommand.CommandText = "SELECT SERVERPROPERTY ('productversion'),SERVERPROPERTY ('productlevel'), SERVERPROPERTY ('edition')"
                                $DataAdapter = new-object System.Data.SqlClient.SqlDataAdapter $SqlCommand
                                $dataset = new-object System.Data.Dataset
                                $DataAdapter.Fill($dataset) | Out-Null
                            } catch {
                                $Global:ErrorCapture += $_
                                $ReturnInfo += New-Object -TypeName PSObject -Property @{'Success' = $false; 'ServerName' = $servername; 'Version' = ''; 'MinMemory' = 0; 'MaxMemory' = 0; 'CompLevel' = 0; 'Database' = ''; 'ConnectionType' = 'SQL Server (SERVERPROPERTY) (SQL TCP)' ; 'Error'= $_}
                            }

                            try {
                                $SqlCommand2 = $Conn.CreateCommand()
                                $SqlCommand2.CommandTimeOut = 0

                                $SqlCommand2.CommandText = "select (select value FROM sys.configurations WHERE name = 'max server memory (MB)') as committed_kb, (select value FROM sys.configurations WHERE name = 'min server memory (MB)') as committed_target_kb"
                                $DataAdapter2 = new-object System.Data.SqlClient.SqlDataAdapter $SqlCommand2
                                $dataset2 = new-object System.Data.Dataset
                                $DataAdapter2.Fill($dataset2) | Out-Null
                            } catch {
                                $Global:ErrorCapture += $_
                                $ReturnInfo += New-Object -TypeName PSObject -Property @{'Success' = $false; 'ServerName' = $servername; 'Version' = ''; 'MinMemory' = 0; 'MaxMemory' = 0; 'CompLevel' = 0; 'Database' = ''; 'ConnectionType' = 'SQL Server (DM_OS_SYS_INFO) (SQL TCP)' ; 'Error'= $_}
                            }

                            try {
                                $SqlCommand3 = $Conn.CreateCommand()
                                $SqlCommand3.CommandTimeOut = 0
                                $SqlCommand3.CommandText = "SELECT compatibility_level FROM sys.databases WHERE name = '$($databasename)'"
                                $DataAdapter3 = new-object System.Data.SqlClient.SqlDataAdapter $SqlCommand3
                                $dataset3 = new-object System.Data.Dataset
                                $DataAdapter3.Fill($dataset3) | Out-Null

                                $ReturnInfo += New-Object -TypeName PSObject -Property @{'Success' = $true; 'ServerName' = $servername; 'Version' = $dataset.Tables[0].Column1; 'MinMemory' = $dataset2.Tables[0].committed_kb; 'MaxMemory' = $dataset2.Tables[0].committed_target_kb; 'CompLevel' = $dataset3.Tables[0].compatibility_level; 'Database' = $databasename; 'ConnectionType' = ''; 'Error'='' }
                            } catch {
                                $Global:ErrorCapture += $_
                                $ReturnInfo += New-Object -TypeName PSObject -Property @{'Success' = $false; 'ServerName' = $servername; 'Version' = ''; 'MinMemory' = 0; 'MaxMemory' = 0; 'CompLevel' = 0; 'Database' = ''; 'ConnectionType' = 'SQL Server (COMPATIBILITY_LEVEL) (SQL TCP)' ; 'Error'= $_}
                            } finally {
                                $conn.Close()
                            }
                        }
                        $ReturnInfo
                    }
                    $returninfo = Execute-RFLRunSpace -code $Code -ParameterList @($ServerName, $DbName)

                    $returninfo | where-object {$_.Success -eq $true} | foreach-object {
                        $SQLConfigurationList += New-Object -TypeName PSObject -Property @{'ServerName' = $_.ServerName; 'Version' = $_.Version; 'MinMemory' = $_.MinMemory; 'MaxMemory' = $_.MaxMemory; 'CompLevel' = $_.CompLevel; 'Database' = $_.Database }
                    }

                    $returninfo | where-object {$_.Success -eq $false} | foreach-object {
                        Write-RFLLog -logtype "EXCEPTION" -logmessage "Error Message: '$($_.Error)'"
                        $Script:ServerDown += New-Object -TypeName PSObject -Property @{'ServerName' =$_.ServerName; 'ConnectionType' = $_.ConnectionType }
                    }
                }
                Export-RFLXMLFile -VariableName 'SQLConfigurationList' -ClearVariable
            }
        }
        #endregion

        #region sub-Rules 
        $arrRuleID = @(29,30,31,32,33,34,285)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\SQLServerInformationList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "SQLServerInformationList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $SQLServerPrimarySiteList | ForEach-Object {
                    $item = $_

                    $SQLServerName = $item.PropLists.values.Split(',')[1].Trim()
                    Write-RFLLog -logtype "Info" -logmessage "Getting SQL Server Instance Info '$($SQLServerName)' Information"
                    $code = {
                        Param (
                            $SQLServerName,
                            $SiteCode
                        )
                        $ReturnInfo = @()
                        try {
                            $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $SQLServerName)
                            $RegKey= $Reg.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion")
                            $ProgramFiles = $RegKey.GetValue("ProgramFilesDir")

                            $RegKey= $Reg.OpenSubKey("SOFTWARE\Microsoft\Microsoft SQL Server")
                            $InstanceName = $RegKey.GetValue("InstalledInstances")
                            $InstanceData = @()
                        
                            if ($InstanceName -is [Array]) {
                                $InstanceData = $InstanceName
                            } else {
                                $InstanceData += $InstanceName
                            }

                            $InstanceData | ForEach-Object {
                                $InstanceItem = $_

                                $RegKey= $Reg.OpenSubKey("SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL")
                                $InstanceID = $RegKey.GetValue($InstanceItem)

                                $RegKey= $Reg.OpenSubKey("SOFTWARE\Microsoft\Microsoft SQL Server\$($InstanceID)\Setup")
                                $SQLProgramDir = $RegKey.GetValue("SqlProgramDir")
                                $SQLData = $RegKey.GetValue("SQLDataRoot")


                                $RegKey= $Reg.OpenSubKey("SOFTWARE\Microsoft\Microsoft SQL Server\$($InstanceID)\MSSQLServer")
                                $SQLLogs = $RegKey.GetValue("DefaultLog")

                                if ($null -ne $SQLLogs) {
                                    $SQLLogsRoot = $SQLLogs.Split('\')[0].Replace(':','$')
                                }
                                $SQLDataRoot = $SQLData.Split('\')[0].Replace(':','$')
                                
                                if (Test-Path -LiteralPath "filesystem::\\$($SQLServerName)\$($SQLDataRoot)\NO_SMS_ON_DRIVE.SMS" -ErrorAction SilentlyContinue) {
                                    $bPathExistDataRoot = $true
                                } else {
                                    $bPathExistDataRoot = $false
                                }

                                if ($null -ne $SQLLogs) {
                                    if (Test-Path -LiteralPath "filesystem::\\$($SQLServerName)\$($SQLLogsRoot)\NO_SMS_ON_DRIVE.SMS" -ErrorAction SilentlyContinue) {
                                        $bPathExistLogRoot = $true
                                    } else {
                                        $bPathExistLogRoot = $false
                                    }
                                }

                                $ReturnInfo += New-Object -TypeName PSObject -Property @{'Success' = $true; 'SiteCode' = $SiteCode; 'ServerName' = $SQLServerName; 'ProgramFiles' = $ProgramFiles; 'InstallationFolder' = $SQLProgramDir; 'DataFolder' = $SQLData; 'LogFolder' = $SQLLogs; 'NOSMSONData' = $bPathExistDataRoot; 'NOSMSONLog' = $bPathExistLogRoot; 'ConnectionType' = ''; 'Error'='' }
                            }                        
                        } catch {
                            $Global:ErrorCapture += $_
                            $ReturnInfo += New-Object -TypeName PSObject -Property @{'Success' = $false; 'SiteCode' = $SiteCode; 'ServerName' = $SQLServerName; 'ProgramFiles' = ''; 'InstallationFolder' = ''; 'DataFolder' = ''; 'LogFolder' = ''; 'NOSMSONData' = ''; 'NOSMSONLog' = ''; 'ConnectionType' = 'SQL Server Remote Registry (RRP/RPC)'; 'Error'=$_ }
                        }
                        $ReturnInfo
                    }
                    $returninfo = Execute-RFLRunSpace -code $Code -ParameterList @($SQLServerName, $item.SiteCode)

                    $returninfo | where-object {$_.Success -eq $true} | foreach-object {
                        $SQLServerInformationList += New-Object -TypeName PSObject -Property @{'SiteCode' = $_.SiteCode; 'ServerName' = $_.ServerName; 'ProgramFiles' = $_.ProgramFiles; 'InstallationFolder' = $_.InstallationFolder; 'DataFolder' = $_.DataFolder; 'LogFolder' = $_.LogFolder; 'NOSMSONData' = $_.NOSMSONData; 'NOSMSONLog' = $_.NOSMSONLog }
                    }

                    $returninfo | where-object {$_.Success -eq $false} | foreach-object {
                        Write-RFLLog -logtype "EXCEPTION" -logmessage "Error Message: '$($_.Error)'"
                        $Script:ServerDown += New-Object -TypeName PSObject -Property @{'ServerName' =$_.ServerName; 'ConnectionType' = $_.ConnectionType }
                    }
                }
                Export-RFLXMLFile -VariableName 'SQLServerInformationList' -ClearVariable
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(35,36,37,258)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\ServiceAccountList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "ServiceAccountList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $ServiceAccountList += Get-CMAccount
                Export-RFLXMLFile -VariableName 'ServiceAccountList'
            }
        }
        #endregion
             
        #region sub-Rules
        $arrRuleID = @(37,256,257,258)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\AdminAccountList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "AdminAccountList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $AdminAccountList += Get-CMAdministrativeUser
                Export-RFLXMLFile -VariableName 'AdminAccountList'
            }
        }
        #endregion

        #region sub-Rules 
        $arrRuleID = @(258,406)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\SQLServiceAccountList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "SQLServiceAccountList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $SQLServiceAccountList = @()
                $SQLServerPrimarySiteList | ForEach-Object { 
                    $item = $_

                    $arrPropList = $item.PropLists[0].values.split(',').Trim()
                    $ServerName = $item.NetworkOSPath.Replace('\\','')
                    if ($arrPropList[2].IndexOf('\') -ge 0) {
                        $Instance = $arrPropList[2].split('\')[0]
                    }

                    Write-RFLLog -logtype "Info" -logmessage "Getting SQL Server '$($ServerName)' Information"
                    $code = {
                        Param (
                            $servername,
                            $Instance
                        )
                        $ReturnInfo = @()

                        try {
                            $Namespace = (Get-WmiObject -computer $servername -Namespace 'root\Microsoft\SqlServer' -class '__NAMESPACE' | Where-Object { $_.name -match 'ComputerManagement' }).Name
                            $services = Get-WmiObject -computer $servername -Namespace "root\Microsoft\SqlServer\$($Namespace)" -Class 'SqlService'

                            $services | ForEach-Object {
                                $item = $_
                                if ($item.ServiceName.Indexof('$') -ge 0) {
                                    $instanceID = $item.ServiceName.Substring($item.ServiceName.Indexof('$')+1)
                                }
                                $ReturnInfo += New-Object -TypeName PSObject -Property @{'Success' = $true; 'ServerName' = $ServerName; 'Instance' = $Instance; 'ConnectionType' = 'SQL Server (Service Account)' ; 'Error'= ''; 'AcceptPause' = $_.AcceptPause; 'AcceptsStop' = $_.AcceptsStop; 'BinaryPath' = $_.BinaryPath; 'Description' = $_.Description; 'DisplayName' = $_.DisplayName; 'ErrorControl' = $_.ErrorControl; 'ExitCode' = $_.ExitCode; 'HostName' = $_.HostName; 'ProcessId' = $_.ProcessId; 'ServiceName' = $_.ServiceName; 'SQLServiceType' = $_.SQLServiceType; 'StartMode' = $_.StartMode; 'StartName' = $_.StartName; 'State' = $_.State; 'InstanceID' = $instanceID; }
                            }
                        } catch {
                            $Global:ErrorCapture += $_
                            $ReturnInfo += New-Object -TypeName PSObject -Property @{'Success' = $False; 'ServerName' = $ServerName; 'Instance' = $Instance; 'ConnectionType' = 'SQL Server (Service Account)' ; 'Error'= $_; 'AcceptPause' = ''; 'AcceptsStop' = ''; 'BinaryPath' = ''; 'Description' = ''; 'DisplayName' = ''; 'ErrorControl' = ''; 'ExitCode' = ''; 'HostName' = ''; 'ProcessId' = ''; 'ServiceName' = ''; 'SQLServiceType' = ''; 'StartMode' = ''; 'StartName' = ''; 'State' = ''; 'InstanceID' = ''; }
                        }

                        $ReturnInfo
                    }
                    $returninfo = Execute-RFLRunSpace -code $Code -ParameterList @($ServerName, $Instance)

                    $SQLServiceAccountList += $returninfo | where-object {$_.Success -eq $true}

                    $returninfo | where-object {$_.Success -eq $false} | foreach-object {
                        Write-RFLLog -logtype "EXCEPTION" -logmessage "Error Message: '$($_.Error)'"
                        $Script:ServerDown += New-Object -TypeName PSObject -Property @{'ServerName' =$_.ServerName; 'ConnectionType' = $_.ConnectionType }
                    }
                }
                Export-RFLXMLFile -VariableName 'SQLServiceAccountList'
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(35,36,37,256,257,258)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\GroupMembershipList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "GroupMembershipList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script

                if (Test-Path -LiteralPath "$($SaveToFolder)\GroupMembershipErrorList.xml") {
                    New-Variable -Name "GroupMembershipErrorList" -Value (Import-Clixml -Path "$($SaveToFolder)\GroupMembershipErrorList.xml") -Force -Option AllScope -Scope Script
                }

                if (Test-Path -LiteralPath "$($SaveToFolder)\AccountDoesNotExist.xml") {
                    New-Variable -Name "AccountDoesNotExist" -Value (Import-Clixml -Path "$($SaveToFolder)\AccountDoesNotExist.xml") -Force -Option AllScope -Scope Script
                }
            } else {
                if ($ServiceAccountList.Count -ne 0) {
                    Get-RFLAccountMembership -AccountList $ServiceAccountList -PropertyName 'UserName' -isServiceAccount $true -AccountType 'Service Account'
                }
                if ($AdminAccountList.Count -ne 0) {
                    Get-RFLAccountMembership -AccountList $AdminAccountList -PropertyName 'LogonName' -isServiceAccount $false -AccountType 'Admin Account'
                }

                if ($SQLServiceAccountList.Count -ne 0) {
                    $SQLServiceAccountList = $SQLServiceAccountList | Where-Object { ($_.ServiceName -ne 'SQLBrowser') -and ($_.StartName -notin @('LocalSystem', 'NT AUTHORITY\LOCALSERVICE')) -and (($_.Instance -eq $_.InstanceID) -or ([string]::IsNullOrEmpty($_.Instance))) }
                }
                    
                if ($SQLServiceAccountList.Count -ne 0) {
                    Get-RFLAccountMembership -AccountList $SQLServiceAccountList -PropertyName 'StartName' -isServiceAccount $true -AccountType 'SQL Server Service Account'
                }

                Export-RFLXMLFile -VariableName 'GroupMembershipList' -ClearVariable
                Export-RFLXMLFile -VariableName 'GroupMembershipErrorList' -ClearVariable 
                Export-RFLXMLFile -VariableName 'AccountDoesNotExist' -ClearVariable
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(38,39,40,41,42,43,44,45,46,47,48,49)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\ClientStatusSettings.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "ClientStatusSettings" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $ClientStatusSettings += Get-CMClientStatusSetting
                Export-RFLXMLFile -VariableName 'ClientStatusSettings' -ClearVariable
            }
        }
        #endregion
        
        #region sub-Rules
        $arrRuleID = @(50,51,52,53,54,55,56,57,58,59,60,61,62,63,64,65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,81,82,83,309,310)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\DiscoveryMethodList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "DiscoveryMethodList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $DiscoveryMethodList += Get-CMDiscoveryMethod
                Export-RFLXMLFile -VariableName 'DiscoveryMethodList' -ClearVariable
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(84,85,289)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\DPGroupList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "DPGroupList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $DPGroupList += Get-CMDistributionPointGroup
                Export-RFLXMLFile -VariableName 'DPGroupList' -ClearVariable
            }
        }
        #endregion
        
        #region sub-Rules
        $arrRuleID = @(86,87)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\CollectionMembershipEvaluation.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "CollectionMembershipEvaluation" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $CollectionMembershipEvaluation += Get-CMCollectionMembershipEvaluationComponent
                Export-RFLXMLFile -VariableName 'CollectionMembershipEvaluation' -ClearVariable
            }
        }
        #endregion
        
        #region sub-Rules
        $arrRuleID = @(88,89,90,91,92,93,330,331,341,361,384)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\DeviceCollectionList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "DeviceCollectionList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $DeviceCollectionList += Get-CMDeviceCollection
                Export-RFLXMLFile -VariableName 'DeviceCollectionList'
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(93) 
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\CollectionDeviceFilterCount.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "CollectionDeviceFilterCount" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                if ($ModuleConfigMgrVersionBuild -lt 1702) { #using if for the ConfigMgr version because lower than 1702 does not have the cmdlet
                    $CollectionDeviceFilterCount = ($DeviceCollectionList | ForEach-Object {
                        $item = $_
                        #cade
                        $MembershipRules = (Get-WmiObject -computer $SMSProviderServer -Namespace "root\sms\site_$($MainSiteCode)" -Query "SELECT * FROM SMS_Collection WHERE Name = '$($item.Name)'")
                        $MembershipRules.Get()

                        if (($MembershipRules.CollectionRules | Where-Object {$_.__CLASS -eq 'SMS_CollectionRuleDirect'} | Measure-Object).Count -gt $script:MaxCollectionMembershipDirectRule) { $_ }
                    } | Measure-Object).Count
                } else {
                    $CollectionDeviceFilterCount += ($DeviceCollectionList | ForEach-Object {if ((Get-CMCollectionDirectMembershipRule -CollectionName $_.Name | Measure-Object).Count -gt $script:MaxCollectionMembershipDirectRule) { $_ } } | Measure-Object).Count
                }
                Export-RFLXMLFile -VariableName 'CollectionDeviceFilterCount' -ClearVariable
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(94,95,96,97,98,99,100,330,331,342,361,385)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\UserCollectionList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "UserCollectionList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $UserCollectionList += Get-CMUserCollection
                Export-RFLXMLFile -VariableName 'UserCollectionList'
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(99) 
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\CollectionUserFilterCount.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "CollectionUserFilterCount" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                if ($ModuleConfigMgrVersionBuild -lt 1702) { #using if for the ConfigMgr version because lower than 1702 does not have the cmdlet
                    $CollectionUserFilterCount = ($UserCollectionList | ForEach-Object {
                        $item = $_
                        $MembershipRules = (Get-WmiObject -computer $SMSProviderServer -Namespace "root\sms\site_$($MainSiteCode)" -Query "SELECT * FROM SMS_Collection WHERE Name = '$($item.Name)'")
                        $MembershipRules.Get()

                        if (($MembershipRules.CollectionRules | Where-Object {$_.__CLASS -eq 'SMS_CollectionRuleDirect'} | Measure-Object).Count -gt $script:MaxCollectionMembershipDirectRule) { $_ }
                    } | Measure-Object).Count
                } else {
                    $CollectionUserFilterCount += ($UserCollectionList | ForEach-Object {if ((Get-CMCollectionDirectMembershipRule -CollectionName $_.Name | Measure-Object).Count -gt $script:MaxCollectionMembershipDirectRule) { $_ } } | Measure-Object).Count
                }
                Export-RFLXMLFile -VariableName 'CollectionUserFilterCount' -ClearVariable
            }
        }
        #endregion
        
        #region sub-Rules
        $arrRuleID = @(100,101,284,292,293,299,351,352,353)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\DeploymentList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "DeploymentList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $DeploymentList += Get-CMDeployment
                Export-RFLXMLFile -VariableName 'DeploymentList' -ClearVariable
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(103,104)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\AlertSubscriptionList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "AlertSubscriptionList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $AlertSubscriptionList += Get-CMAlertSubscription
                Export-RFLXMLFile -VariableName 'AlertSubscriptionList' -ClearVariable
            }
        }
        #endregion
 
        #region sub-Rules
        $arrRuleID = @(105,106,107,108,109,110,111,112,113,114,115,116,117,118,119,120,121,122,123,124,125,126,127,128,129,130,131,132,133,134,135,136,137,138,279,280,281,282,404)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\DeviceList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "DeviceList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $DeviceList += (Get-WmiObject -computer $SMSProviderServer -Namespace "root\sms\site_$($MainSiteCode)" -Query "SELECT * FROM SMS_CM_RES_COLL_SMS00001")
                $ManagedDeviceCount = ($DeviceList | Where-Object {$_.IsClient -eq $true}).Count
                Export-RFLXMLFile -VariableName 'DeviceList' -ClearVariable
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(119,120,121,122,123,124,125,126,127,128,129,130,131,132,133,134,135,136,137,138,163,176,177,178,179,180,181,182)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\EndpointProtectionList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "EndpointProtectionList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $EndpointProtectionList += $SiteRoleList | Where-Object {$_.RoleName -eq 'SMS Endpoint Protection Point'}
                Export-RFLXMLFile -VariableName 'EndpointProtectionList'
            }
        }
        #endregion
        
        #region sub-Rules
        $arrRuleID = @(139,140,141,142,143,144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159,160,161,162,163,403)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            $FileToImport = "$($SaveToFolder)\ClientSettingsList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "ClientSettingsList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $ClientSettingsList += Get-CMClientSetting
                Export-RFLXMLFile -VariableName 'ClientSettingsList'
            }
        }
        #endregion

        #region sub-Rules-- parallel (to verify)
        $arrRuleID = @(139,140,141,142,143,144,145,146,147,148,149,150,151,152,153,154,155,156,157,158,159,160,161,162,163,403)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            $FileToImport = "$($SaveToFolder)\ClientSettingsSettingsList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "ClientSettingsSettingsList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $ClientSettingsList | ForEach-Object {
                    $item = $_
                    Write-RFLLog -logtype "Info" -logmessage "Getting Client Setting '$($item.Name)' Setting List Information"
                    foreach ($itemName in $script:ClientSettingsListName) {
                        Write-RFLLog -logtype "Info" -logmessage "Getting Client Setting Settings for '$($itemName)'"
                        try {
                            Get-CMClientSetting -Name $item.Name -Setting $itemName | ForEach-Object {
                                $_.GetEnumerator() | ForEach-Object { $ClientSettingsSettingsList += New-Object -TypeName PSObject -Property @{'Name' = $item.Name; 'SettingsName' = $itemName; 'Key' = $_.Key; 'Value' = $_.Value } }
                                #$_.GetEnumerator() | ForEach-Object { $ClientSettingsSettingsList += new-object HealthCheckClasses.ConfigMgr.CEClassPolicySettings($item.Name, $itemName, $_.Key, $_.Value) }
                            }
                        } catch {
                            $Global:ErrorCapture += $_
                            #write error on log and continue. This is required if the $itemname does not exist (running it against an old site)
                            Write-RFLLog -logtype "EXCEPTION" -logmessage "Error Message: '$($_)'"
                        }
                    }
                }
                Export-RFLXMLFile -VariableName 'ClientSettingsSettingsList' -ClearVariable
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(164,165)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\MaintenanceTaskList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "MaintenanceTaskList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {

                if ($ModuleConfigMgrVersionBuild -lt 1702) {                    
                    $SiteList | Select-Object SiteCode | Get-Unique -AsString | ForEach-Object {
                        Write-RFLLog -logtype "Info" -logmessage "Getting Site Role List Information for Site '$($_.SiteCode)'"
                        $MaintenanceTaskList += Get-CMSiteMaintenanceTask -SiteCode $_.SiteCode
                    }
                } else {
                    $MaintenanceTaskList += Get-CMSiteMaintenanceTask
                }
                Export-RFLXMLFile -VariableName 'MaintenanceTaskList' -ClearVariable
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(166,167,168,169,170,171,172,173,174,175)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            $FileToImport = "$($SaveToFolder)\BoundaryGroupList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "BoundaryGroupList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $BoundaryGroupList += Get-CMBoundaryGroup
                Export-RFLXMLFile -VariableName 'BoundaryGroupList' -ClearVariable
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(166,167,168,169,170,171,172,173,174,175)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            $FileToImport = "$($SaveToFolder)\BoundaryGroupRelationshipList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "BoundaryGroupRelationshipList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                if ($ModuleConfigMgrVersionBuild -gt 1702) {
                    $BoundaryGroupRelationshipList += Get-CMBoundaryGroupRelationship
                }
            
                Export-RFLXMLFile -VariableName 'BoundaryGroupRelationshipList' -ClearVariable
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(168,169)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            $FileToImport = "$($SaveToFolder)\DPList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "DPList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                if ([Convert]::ToBoolean($script:IgnoreCloudDP) -eq $true) {
                    $SiteRoleList | Where-Object {($_.RoleName -eq 'SMS Distribution Point')} | ForEach-Object {
                        $item = $_
                        if ($item.Props | Where-Object {($_.PropertyName -eq 'IsCloud') -and ($_.Value -eq 1)}) {
                        } else {
                            $DPList += $item
                        }
                    }
                } else {
                    $DPList += $SiteRoleList | Where-Object {$_.RoleName -eq 'SMS Distribution Point'}
                }
                Export-RFLXMLFile -VariableName 'DPList' -ClearVariable
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(172,173)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            $FileToImport = "$($SaveToFolder)\SMPList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "SMPList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {

                $SMPList += $SiteRoleList | Where-Object {$_.RoleName -eq 'SMS State Migration Point'}
                Export-RFLXMLFile -VariableName 'SMPList' -ClearVariable
            }
        }
        #endregion
        
        #region sub-Rules
        $arrRuleID = @(176)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\MalwareDetectedList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "MalwareDetectedList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                if ($null -ne $EndpointProtectionList) {
                    $MalwareDetectedList += Get-CMDetectedMalware -CollectionId 'SMS00001'
                    Export-RFLXMLFile -VariableName 'MalwareDetectedList' -ClearVariable
                }
            }
        }
        #endregion
        
        #region sub-Rules
        $arrRuleID = @(177,178,179,180,181,182)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\MalwarePolicyList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "MalwarePolicyList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                if ($null -ne $EndpointProtectionList) {
                    $MalwarePolicyList += Get-CMAntimalwarePolicy
                    Export-RFLXMLFile -VariableName 'MalwarePolicyList'
                }
            }
        }
        #endregion

        #region sub-Rules-- parallel verify
        $arrRuleID = @(177,178,179,180,181,182)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\MalwarePolicySettingsList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "MalwarePolicySettingsList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                if ($null -ne $EndpointProtectionList) {
                    $MalwarePolicyList | ForEach-Object {
                        $item = $_
                        Write-RFLLog -logtype "Info" -logmessage "Getting Malware Policy '$($item.Name)' Setting List Information"
                        foreach ($itemName in $script:AntiMalwarePolicySettingsListName) {
                            Write-RFLLog -logtype "Info" -logmessage "Getting Anti-Malware Policy Settings for '$($itemName)'"
                            try {
                                Get-CMAntimalwarePolicy -Name $item.Name -Policy $itemName | ForEach-Object {
                                    $_.GetEnumerator() | ForEach-Object { $MalwarePolicySettingsList += New-Object -TypeName PSObject -Property @{'Name' = $item.Name; 'SettingsName' = $itemName; 'Key' = $_.Key; 'Value' = $_.Value } }
                                    #$_.GetEnumerator() | ForEach-Object { $MalwarePolicySettingsList += new-object HealthCheckClasses.ConfigMgr.CEClassPolicySettings($item.Name, $itemName, $_.Key, $_.Value) }
                                }
                            } catch {
                                $Global:ErrorCapture += $_
                                #write error on log and continue. This is required if the $itemname does not exist
                                Write-RFLLog -logtype "EXCEPTION" -logmessage "Error Message: '$($_)'"
                            }
                        }
                    }
                    Export-RFLXMLFile -VariableName 'MalwarePolicySettingsList' -ClearVariable
                }
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(181,182)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\FirewallPolicyList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "MalwarePolicyList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $CMPSSuppressFastNotUsedCheck = $true
                $FirewallPolicyList += Get-CMWindowsFirewallPolicy
                Export-RFLXMLFile -VariableName 'FirewallPolicyList' -ClearVariable
            }
        }
        #endregion
        
        #region sub-Rules
        $arrRuleID = @(183)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\SwMeteringSettingsList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "SwMeteringSettingsList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $SwMeteringSettingsList += Get-CMSoftwareMeteringSetting
                Export-RFLXMLFile -VariableName 'SwMeteringSettingsList' -ClearVariable
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(184)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\SwMeteringRuleList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "SwMeteringRuleList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $SwMeteringRuleList += Get-CMSoftwareMeteringRule
                Export-RFLXMLFile -VariableName 'SwMeteringRuleList' -ClearVariable
            }
        }
        #endregion
        
        #region sub-Rules
        $arrRuleID = @(185,186,187,188,189,190,191,192,275,301,382)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\BootList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "BootList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $BootList += Get-CMBootImage
                Export-RFLXMLFile -VariableName 'BootList' -ClearVariable
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(186,187,298,299,300,301,302,303)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\TaskSequenceList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "TaskSequenceList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $TaskSequenceList += Get-CMTaskSequence
                Export-RFLXMLFile -VariableName 'TaskSequenceList'
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(186,283,284,292,293,295,297,301,302,303)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\TaskSequenceReferenceList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "TaskSequenceReferenceList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $TaskSequenceList | ForEach-Object {
                    $item = $_
                    Write-RFLLog -logtype "Info" -logmessage "Getting Task Sequence $($item.Name) Information"
                    $Code = {
                        Param (
                            $SMSProviderServer,
                            $MainSiteCode,
                            $PackageID
                        )
                        (Get-WmiObject -computer $SMSProviderServer -Namespace "root\sms\site_$($MainSiteCode)" -Query "SELECT ts.*, content.* FROM SMS_ObjectContentExtraInfo content INNER JOIN SMS_TaskSequencePackageReference tspr ON tspr.RefPackageID = content.PackageID INNER JOIN SMS_TaskSequencePackage ts on ts.PackageID = tspr.PackageID where ts.PackageID = '$($PackageID)'")
                    }

                    $TaskSequenceReferenceList += Execute-RFLRunSpace -code $Code -ParameterList @($SMSProviderServer, $MainSiteCode, $item.PackageID)
                }
                Export-RFLXMLFile -VariableName 'TaskSequenceReferenceList' -ClearVariable
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(193,194)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\SoftwareUpdateSummarizationList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "SoftwareUpdateSummarizationList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $SoftwareUpdateSummarizationList += Get-CMSoftwareUpdateSummarizationSchedule
                Export-RFLXMLFile -VariableName 'SoftwareUpdateSummarizationList' -ClearVariable
            }
        }
        #endregion
        
        #region sub-Rules
        $arrRuleID = @(195,196,197,198)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\SoftwareUpdateList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "SoftwareUpdateList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                if ($ModuleConfigMgrVersionBuild -lt 1702) {
                    $SoftwareUpdateList += (Get-WmiObject -computer $SMSProviderServer -Namespace "root\sms\site_$($MainSiteCode)" -Query "SELECT ci.* FROM SMS_SoftwareUpdate ci WHERE ci.CI_ID NOT IN ( SELECT CI_ID FROM SMS_CIAllCategories WHERE CategoryInstance_UniqueID='UpdateClassification:3689bdc8-b205-4af4-8d4a-a63924c5e9d5') AND ci.CI_ID NOT IN (SELECT CI_ID FROM SMS_CIAllCategories WHERE CategoryInstance_UniqueID='Product:30eb551c-6288-4716-9a78-f300ec36d72b') ORDER BY DateRevised DESC")
                } else {
                    #$SoftwareUpdateList += Get-CMSoftwareUpdate
                    $SoftwareUpdateList += Get-CMSoftwareUpdate -Fast
                }
                Export-RFLXMLFile -VariableName 'SoftwareUpdateList' -ClearVariable
            }
        }
        #endregion
        
        #region sub-Rules
        $arrRuleID = @(199)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\SoftwareUpdateDeploymentList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "SoftwareUpdateDeploymentList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                if ($ModuleConfigMgrVersionBuild -gt 1702) {
                    $SoftwareUpdateDeploymentList += Get-CMSoftwareUpdateDeployment | Where-Object {$_.AssignmentType -eq 1}
                }
                Export-RFLXMLFile -VariableName 'SoftwareUpdateDeploymentList' -ClearVariable
            }
        }
        #endregion
        
        #region sub-Rules
        $arrRuleID = @(200,201,202,203,204,205,206,207,208,209,210)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\SoftwareUpdateGroupList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "SoftwareUpdateGroupList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $SoftwareUpdateGroupList += Get-CMSoftwareUpdateGroup
                Export-RFLXMLFile -VariableName 'SoftwareUpdateGroupList'
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(207,208,209)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\SoftwareUpdateGroupDeploymentList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "SoftwareUpdateGroupDeploymentList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                if ($ModuleConfigMgrVersionBuild -lt 1702) {
                    $SoftwareUpdateGroupList | ForEach-Object {
                        $SoftwareUpdateGroupDeploymentList += Get-CMUpdateGroupDeployment -UpdateGroup $_
                    }
                } else {
                    $SoftwareUpdateGroupDeploymentList += Get-CMUpdateGroupDeployment
                }
                Export-RFLXMLFile -VariableName 'SoftwareUpdateGroupDeploymentList' -ClearVariable
            }
        }
        #endregion
        
        #region sub-Rules
        $arrRuleID = @(210,211,212,213,214,215,216,217,218,219,220,221)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\SoftwareUpdateADRList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "SoftwareUpdateADRList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $SoftwareUpdateADRList += Get-CMSoftwareUpdateAutoDeploymentRule
                Export-RFLXMLFile -VariableName 'SoftwareUpdateADRList' -ClearVariable
            }
        }
        #endregion
        
        #region sub-Rules
        $arrRuleID = @(213,214,218,219,220,221)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\SoftwareUpdateADRDeploymetList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "SoftwareUpdateADRDeploymetList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                if ($ModuleConfigMgrVersionBuild -gt 1702) {
                    $SoftwareUpdateADRDeploymetList += Get-CMAutoDeploymentRuleDeployment
                }
                Export-RFLXMLFile -VariableName 'SoftwareUpdateADRDeploymetList' -ClearVariable
            }
        }
        #endregion
        
        #region sub-Rules
        $arrRuleID = @(222,223,224,316,317,318)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\AutoUpgradeConfigs.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "AutoUpgradeConfigs" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script

                if (Test-Path -LiteralPath "$($SaveToFolder)\AutoUpgradeConfigsError.xml") {
                    New-Variable -Name "AutoUpgradeConfigsError" -Value (Import-Clixml -Path "$($SaveToFolder)\AutoUpgradeConfigsError.xml") -Force -Option AllScope -Scope Script
                }
            } else {                
                ($SiteList | Where-Object {$_.Type -eq 2}) | ForEach-Object {
                    $Class = [wmiclass]""
                    $class.psbase.path = "\\$($SMSProviderServer)\root\sms\site_$($_.SiteCode):SMS_Site"
                    try {
                        $AutoUpgradeConfigs += $Class.InvokeMethod("GetAutoUpgradeConfigs", $null, $null)
                    } catch {
                        $Global:ErrorCapture += $_
                        Write-RFLLog -logtype "EXCEPTION" -logmessage "Error Message: '$($_)'"
                        $AutoUpgradeConfigsError += $SiteList
                    }
                }
                Export-RFLXMLFile -VariableName 'AutoUpgradeConfigs' -ClearVariable
                Export-RFLXMLFile -VariableName 'AutoUpgradeConfigsError' -ClearVariable
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(225,226,227)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\EmailNotificationList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "EmailNotificationList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $EmailNotificationList += Get-CMEmailNotificationComponent
                Export-RFLXMLFile -VariableName 'EmailNotificationList' -ClearVariable
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(228,229,230,231,232,233)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\ADForestlist.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "ADForestlist" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $ADForestlist += Get-CMActiveDirectoryForest
                Export-RFLXMLFile -VariableName 'ADForestlist'
            }
        }
        #endregion

        #region sub-Rules-- parallel verify
        $arrRuleID = @(228,229,230,231,232,233)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\ADForestDiscoveryStatusList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "ADForestDiscoveryStatusList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $ADForestlist | ForEach-Object {
                    $item = $_

                    $StatusList = (Get-WmiObject -computer $SMSProviderServer -Namespace "root\sms\site_$($MainSiteCode)" -Query "SELECT * FROM SMS_ADForestDiscoveryStatus WHERE ForestID = $($item.ForestID)")
                    $StatusList | ForEach-Object {
                        $dt1 = Get-Date -Date "01/01/1970"
                        $dt2 = Get-Date -Date "01/01/1970"
                        if (-not [string]::IsNullOrEmpty($_.LastDiscoveryTime)) {
                            $dt1 = [datetime]::parseexact($_.LastDiscoveryTime.split('.')[0],"yyyyMMddHHmmss",[System.Globalization.CultureInfo]::InvariantCulture)
                        }

                        if (-not [string]::IsNullOrEmpty($_.LastPublishingTime)) {
                            $dt2 = [datetime]::parseexact($_.LastPublishingTime.split('.')[0],"yyyyMMddHHmmss",[System.Globalization.CultureInfo]::InvariantCulture)
                        }

                        $ADForestDiscoveryStatusList += New-Object -TypeName PSObject -Property @{'DiscoveryEnabled' = $_.DiscoveryEnabled; 'DiscoveryStatus' = $_.DiscoveryStatus; 'ForestFQDN' = $item.ForestFQDN; 'LastDiscoveryTime' = $dt1; 'LastPublishingTime' = $dt2; 'PublishingEnabled' = $_.PublishingEnabled; 'PublishingStatus' = $_.PublishingStatus; 'SiteCode' = $_.SiteCode; }
                        #$ADForestDiscoveryStatusList += new-object HealthCheckClasses.ConfigMgr.CEADForestDiscoveryStatus($_.DiscoveryEnabled, $_.DiscoveryStatus, $item.ForestFQDN, $dt1, $dt2, $_.PublishingEnabled, $_.PublishingStatus, $_.SiteCode)
                    }
                }
                Export-RFLXMLFile -VariableName 'ADForestDiscoveryStatusList' -ClearVariable
            }
        }
        #endregion     
        
        #region sub-Rules
        $arrRuleID = @(234,235,236,237,238)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\DatabaseReplicationStatusList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "DatabaseReplicationStatusList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                if (($SiteList | Measure-Object).Count -gt 1) {
                    $DatabaseReplicationStatusList += Get-CMDatabaseReplicationStatus
                    Export-RFLXMLFile -VariableName 'DatabaseReplicationStatusList' -ClearVariable
                }
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(240,241)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\DatabaseReplicationScheduleList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "DatabaseReplicationScheduleList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                if (($SiteList | Measure-Object).Count -gt 1) {
                    #cade
                    $DatabaseReplicationScheduleList += (Get-WmiObject -computer $SMSProviderServer -Namespace "root\sms\site_$($MainSiteCode)" -class SMS_RcmSqlControl)
                    Export-RFLXMLFile -VariableName 'DatabaseReplicationScheduleList' -ClearVariable
                }
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(242,243,244,245,246,247,248,249,250,251,252,253)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\SiteSummarizationList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "SiteSummarizationList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {                
                ($SiteList | Where-Object {$_.Type -eq 2}) | ForEach-Object {
                    Write-RFLLog -logtype "Info" -logmessage "Getting Status Summarization List Information for Site '$($_.SiteCode)'"
                    $Class = [wmiclass]""
                    $class.psbase.path = "\\$($SMSProviderServer)\root\sms\site_$($MainSiteCode):sms_summarizationsettings"
                    $method = "GetSummarizationSettings"
                    $InParams = $class.GetMethodParameters($Method)
                    $InParams.SiteCode = $_.SiteCode
                    $InParams.SummarizationType = [uint32]2

                    $returnSiteSummarization = $Class.InvokeMethod($method, $InParams, $null)
                    $SiteSummarizationList += New-Object -TypeName PSObject -Property @{ 'Name' = "Application Deployment Summarizer"; 'FirstIntervalMins' = $returnSiteSummarization.FirstIntervalMins; 'SecondIntervalMins' = $returnSiteSummarization.SecondIntervalMins; 'ThirdIntervalMins' = $returnSiteSummarization.ThirdIntervalMins; 'SiteCode' = $_.SiteCode; }
                    #$SiteSummarizationList += New-Object HealthCheckClasses.ConfigMgr.CESummarizationInterval($_.SiteCode, "Application Deployment Summarizer", $returnSiteSummarization.FirstIntervalMins, $returnSiteSummarization.SecondIntervalMins, $returnSiteSummarization.ThirdIntervalMins)

                    $InParams.SummarizationType = [uint32]3
                    $returnSiteSummarization = $Class.InvokeMethod($method, $InParams, $null)
                    $SiteSummarizationList += New-Object -TypeName PSObject -Property @{ 'Name' = "Application Statistics Summarizer"; 'FirstIntervalMins' = $returnSiteSummarization.FirstIntervalMins; 'SecondIntervalMins' = $returnSiteSummarization.SecondIntervalMins; 'ThirdIntervalMins' = $returnSiteSummarization.ThirdIntervalMins; 'SiteCode' = $_.SiteCode; }
                    #$SiteSummarizationList += New-Object HealthCheckClasses.ConfigMgr.CESummarizationInterval($_.SiteCode, "Application Statistics Summarizer", $returnSiteSummarization.FirstIntervalMins, $returnSiteSummarization.SecondIntervalMins, $returnSiteSummarization.ThirdIntervalMins)
                }
                Export-RFLXMLFile -VariableName 'SiteSummarizationList' -ClearVariable
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(259,260)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            $FileToImport = "$($SaveToFolder)\ProcessInfoList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "ProcessAverageTimeList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $NumberOfSamples = [math]::Round([int]$Script:ProcessListSamplesMinutes * 60 / [int]$Script:ProcessListSamplesWaitSeconds)
                $SiteRoleListWOCDP | select-Object SiteCode, @{Name='NetworkOSPath';Expression={$_.NetworkOSPath.Tolower().Trim()}} -Unique | ForEach-Object {
                    $item = $_
                    $RemoteComputer = ($item.NetworkOSPath.Replace('\\',''))
                    While (@(Get-Job | where-object { $_.State -eq "Running" }).Count -ge $Script:MaxThreads) {  
                        Start-Sleep -Seconds 3
                    }
                    Write-RFLLog -logtype "Info" -logmessage "Getting 'Processor CPU Utilization' information for '$($RemoteComputer)'"
                    $Scriptblock = {
                        Param (
                            $RemoteComputer,
                            $NumberOfSamples,
                            $WaitSeconds
                        )
                        $ReturnInfo = @()
                        For ($i=1; $i -le $NumberOfSamples; $i++) {
                            try {
                                $itemReturn = (Get-WmiObject -ComputerName $RemoteComputer -namespace "root\cimv2" -class "Win32_PerfFormattedData_PerfProc_Process" -ErrorAction SilentlyContinue) | Where-Object { ($_.name -inotmatch '_total|idle') }
                                if ($null -ne $itemReturn) {
                                    $itemReturn | foreach-object {
                                        $ReturnInfo += New-Object -TypeName PSObject -Property @{'Success' = $true; 'ServerName' = $RemoteComputer; 'ConnectionType' = '' ; 'Error'= ''; 'Caption' = $_.Caption; 'CreatingProcessID' = $_.CreatingProcessID; 'Description' = $_.Description; 'ElapsedTime' = $_.ElapsedTime; 'Frequency_Object' = $_.Frequency_Object; 'Frequency_PerfTime' = $_.Frequency_PerfTime; 'Frequency_Sys100NS' = $_.Frequency_Sys100NS; 'HandleCount' = $_.HandleCount; 'IDProcess' = $_.IDProcess; 'IODataOperationsPerSec' = $_.IODataOperationsPerSec; 'IOOtherOperationsPerSec' = $_.IOOtherOperationsPerSec; 'IOReadBytesPerSec' = $_.IOReadBytesPerSec; 'IOReadOperationsPerSec' = $_.IOReadOperationsPerSec; 'IOWriteBytesPerSec' = $_.IOWriteBytesPerSec; 'IOWriteOperationsPerSec' = $_.IOWriteOperationsPerSec; 'IODataBytesPerSec' = $_.IODataBytesPerSec; 'IOOtherBytesPerSec' = $_.IOOtherBytesPerSec; 'Name' = $_.Name; 'PageFaultsPerSec' = $_.PageFaultsPerSec; 'PageFileBytes' = $_.PageFileBytes; 'PageFileBytesPeak' = $_.PageFileBytesPeak; 'PercentPrivilegedTime' = $_.PercentPrivilegedTime; 'PercentProcessorTime' = $_.PercentProcessorTime; 'PercentUserTime' = $_.PercentUserTime; 'PoolNonpagedBytes' = $_.PoolNonpagedBytes; 'PoolPagedBytes' = $_.PoolPagedBytes; 'PriorityBase' = $_.PriorityBase; 'PrivateBytes' = $_.PrivateBytes; 'ThreadCount' = $_.ThreadCount; 'Timestamp_Object' = $_.Timestamp_Object; 'Timestamp_PerfTime' = $_.Timestamp_PerfTime; 'Timestamp_Sys100NS' = $_.Timestamp_Sys100NS; 'VirtualBytes' = $_.VirtualBytes; 'VirtualBytesPeak' = $_.VirtualBytesPeak; 'WorkingSet' = $_.WorkingSet; 'WorkingSetPeak' = $_.WorkingSetPeak; }
                                    }
                                } else {
                                    $ReturnInfo += New-Object -TypeName PSObject -Property @{'Success' = $false; 'ServerName' = $RemoteComputer; 'ConnectionType' = 'WMI (root\cimv2) Performance' ; 'Error'= ''; 'Caption' = ''; 'CreatingProcessID' = 0; 'Description' = ''; 'ElapsedTime' = 0; 'Frequency_Object' = 0; 'Frequency_PerfTime' = 0; 'Frequency_Sys100NS' = 0; 'HandleCount' = 0; 'IDProcess' = 0; 'IODataOperationsPerSec' = 0; 'IOOtherOperationsPerSec' = 0; 'IOReadBytesPerSec' = 0; 'IOReadOperationsPerSec' = 0; 'IOWriteBytesPerSec' = 0; 'IOWriteOperationsPerSec' = 0; 'IODataBytesPerSec' = 0; 'IOOtherBytesPerSec' = 0; 'Name' = ''; 'PageFaultsPerSec' = 0; 'PageFileBytes' = 0; 'PageFileBytesPeak' = 0; 'PercentPrivilegedTime' = 0; 'PercentProcessorTime' = 0; 'PercentUserTime' = 0; 'PoolNonpagedBytes' = 0; 'PoolPagedBytes' = 0; 'PriorityBase' = 0; 'PrivateBytes' = 0; 'ThreadCount' = 0; 'Timestamp_Object' = 0; 'Timestamp_PerfTime' = 0; 'Timestamp_Sys100NS' = 0; 'VirtualBytes' = 0; 'VirtualBytesPeak' = 0; 'WorkingSet' = 0; 'WorkingSetPeak' = 0; }
                                    break
                                }
                            } catch {
                                $Global:ErrorCapture += $_
                                $ReturnInfo += New-Object -TypeName PSObject -Property @{'Success' = $false; 'ServerName' = $RemoteComputer; 'ConnectionType' = 'WMI (root\cimv2) Performance' ; 'Error'= $_; 'Caption' = ''; 'CreatingProcessID' = 0; 'Description' = ''; 'ElapsedTime' = 0; 'Frequency_Object' = 0; 'Frequency_PerfTime' = 0; 'Frequency_Sys100NS' = 0; 'HandleCount' = 0; 'IDProcess' = 0; 'IODataOperationsPerSec' = 0; 'IOOtherOperationsPerSec' = 0; 'IOReadBytesPerSec' = 0; 'IOReadOperationsPerSec' = 0; 'IOWriteBytesPerSec' = 0; 'IOWriteOperationsPerSec' = 0; 'IODataBytesPerSec' = 0; 'IOOtherBytesPerSec' = 0; 'Name' = ''; 'PageFaultsPerSec' = 0; 'PageFileBytes' = 0; 'PageFileBytesPeak' = 0; 'PercentPrivilegedTime' = 0; 'PercentProcessorTime' = 0; 'PercentUserTime' = 0; 'PoolNonpagedBytes' = 0; 'PoolPagedBytes' = 0; 'PriorityBase' = 0; 'PrivateBytes' = 0; 'ThreadCount' = 0; 'Timestamp_Object' = 0; 'Timestamp_PerfTime' = 0; 'Timestamp_Sys100NS' = 0; 'VirtualBytes' = 0; 'VirtualBytesPeak' = 0; 'WorkingSet' = 0; 'WorkingSetPeak' = 0; }
                                break
                            }
                            if ($i -lt $NumberOfSamples) { start-sleep $WaitSeconds }
                        }
                        $ReturnInfo
                    }
                    Start-Job -ScriptBlock $Scriptblock -ArgumentList @($RemoteComputer, $NumberOfSamples, $Script:ProcessListSamplesWaitSeconds) | out-null
                }
                While (@(Get-Job | where-object { $_.State -eq "Running" }).Count -ge 1) {  
                    Start-Sleep -Seconds 3
                }

                $returninfo = ForEach ($Job in (Get-Job)) {
                    Receive-Job $Job
                    Remove-Job $Job
                }

                $ProcessInfoList += $returninfo | where-object {$_.Success -eq $true} 
                
                $returninfo | where-object {$_.Success -eq $false} | ForEach-Object {
                    if (-not [string]::IsNullOrEmpty($_.Error)) {
                        Write-RFLLog -logtype "EXCEPTION" -logmessage "Server '$($_.ServerName)' generated Error. Error Message: '$($_.Error)'"
                    }
                    $Script:ServerDown += New-Object -TypeName PSObject -Property @{'ServerName' =$_.ServerName; 'ConnectionType' = $_.ConnectionType }
                }

                Export-RFLXMLFile -VariableName 'ProcessInfoList'
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(259,260)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            $FileToImport = "$($SaveToFolder)\ProcessAverageTimeList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "ProcessAverageTimeList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $NumberOfSamples = [math]::Round([int]$Script:ProcessListSamplesMinutes * 60 / [int]$Script:ProcessListSamplesWaitSeconds)
                $ProcessInfoList | Select-Object ServerName | Get-Unique -AsString | ForEach-Object {
                    $Item = $_
                    $ProcessAverageTimeList += $ProcessInfoList | Where-Object {$_.ServerName -eq $Item.ServerName} | Group-Object Name | Select-Object -Property  @{ Name = 'ComputerName'; Expression = { $Item.ServerName }}, Name, @{ Name = 'Average'; Expression = { ($_.Group | Measure-Object -Property PercentProcessorTime -Sum).Sum / $NumberOfSamples } }
                }
                Export-RFLXMLFile -VariableName 'ProcessAverageTimeList' -ClearVariable
                Remove-RFLVariable -VariableName 'ProcessInfoList'
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(261,262)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            $FileToImport = "$($SaveToFolder)\ServerRegistryInformation.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "ServerRegistryInformation" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {                
                $SiteRoleListWOCDP | select-Object SiteCode, @{Name='NetworkOSPath';Expression={$_.NetworkOSPath.Tolower().Trim()}} -Unique | ForEach-Object {
                    $item = $_
                    $RemoteComputer = ($item.NetworkOSPath.Replace('\\',''))
                    Write-RFLLog -logtype "Info" -logmessage "Getting Registry information ('Short file name creation') for '$($RemoteComputer)'"
                    $code = {
                        Param (
                            $RemoteComputer,
                            $SiteCode
                        )
                        try {
                            $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $RemoteComputer)
                            $RegKey= $Reg.OpenSubKey("SYSTEM\CurrentControlSet\Control\FileSystem")
                            if ($null -eq $RegKey) {
                                $RegKey= $Reg.OpenSubKey("SYSTEM\CurrentControlSet\Control\File System") #2008 format
                            }

                            $ShortNameCreation = $RegKey.GetValue("NtfsDisable8dot3NameCreation")

                            $RegKey= $Reg.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion")
                            $ProgramFiles = $RegKey.GetValue("ProgramFilesDir")

                            $ReturnInfo = New-Object -TypeName PSObject -Property @{'Success' = $true; 'SiteCode' = $SiteCode; 'ServerName' = $RemoteComputer; 'ShortNameCreation' = $ShortNameCreation; 'ProgramFiles' = $ProgramFiles; 'ConnectionType' = ''; 'Error'='' }
                        } catch {
                            $Global:ErrorCapture += $_
                            $ReturnInfo = New-Object -TypeName PSObject -Property @{'Success' = $false; 'SiteCode' = $SiteCode; 'ServerName' = $RemoteComputer; 'ShortNameCreation' = ''; 'ProgramFiles' = ''; 'ConnectionType' = 'Short file name creation Remote Registry (RRP/RPC)'; 'Error'=$_ }
                        }
                        $ReturnInfo
                    }
                    $ReturnInfo = Execute-RFLRunSpace -code $Code -ParameterList @($RemoteComputer, $item.SiteCode)

                    $ServerRegistryInformation += $ReturnInfo | where-object {$_.Success -eq $true}

                    $ReturnInfo | where-object {$_.Success -eq $false} | ForEach-Object {
                        Write-RFLLog -logtype "EXCEPTION" -logmessage "Error Message: '$($_.Error)'"
                        $Script:ServerDown += New-Object -TypeName PSObject -Property @{'ServerName' =$_.ServerName; 'ConnectionType' = $_.ConnectionType }
                    }
                }
                Export-RFLXMLFile -VariableName 'ServerRegistryInformation' -ClearVariable
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(263,264,265,266,267,268,269,270,271,272,273,274)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\DistributionPointList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "DistributionPointList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {                
                $SiteList | Select-Object SiteCode | Get-Unique -AsString | ForEach-Object {
                    Write-RFLLog -logtype "Info" -logmessage "Getting Distribution Point Information for Site '$($_.SiteCode)'"
                    $DistributionPointList += Get-CMDistributionPoint -SiteCode $_.SiteCode
                }

                Export-RFLXMLFile -VariableName 'DistributionPointList'
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(263,264,265,266,267,268,269,270,271,272,273,274)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\DistributionPointInformationList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "DistributionPointInformationList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {                
                $DistributionPointList | ForEach-Object {
                    Write-RFLLog -logtype "Info" -logmessage "Getting Distribution Point '$(($_.NetworkOSPath -replace '\\', ''))' Information"
                    $DistributionPointInformationList += Get-CMDistributionPointInfo -InputObject $_
                }
                Export-RFLXMLFile -VariableName 'DistributionPointInformationList' -ClearVariable
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(263,264,265,266,267,268,269,270,271,272,273,274)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\BoundarySiteSystemsList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "BoundarySiteSystemsList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {                
                #cade
                $BoundarySiteSystemsList += (Get-WmiObject -computer $SMSProviderServer -Namespace "root\sms\site_$($MainSiteCode)" -Query "select * from SMS_BoundaryGroupSiteSystems where Flags = 0")
                Export-RFLXMLFile -VariableName 'BoundarySiteSystemsList' -ClearVariable
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(263,264,265,266,267,268,269,270,271,272,273,274)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\DistributionPointDriveInfo.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "DistributionPointDriveInfo" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {                
                #cade
                $DistributionPointDriveInfo += (Get-WmiObject -computer $SMSProviderServer -Namespace "root\sms\site_$($MainSiteCode)" -Query "select * from SMS_DistributionPointDriveInfo")
                Export-RFLXMLFile -VariableName 'DistributionPointDriveInfo' -ClearVariable
            }
        }
        #endregion
        
        #region sub-Rules
        $arrRuleID = @(275,276,277,332,333)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\DistributionStatusList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "DistributionStatusList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                if ($ModuleConfigMgrVersionBuild -lt 1702) {
                    $DistributionStatusList += (Get-WmiObject -computer $SMSProviderServer -Namespace "root\sms\site_$($MainSiteCode)" -Query "SELECT * FROM SMS_ObjectContentExtraInfo")
                } else {
                    $DistributionStatusList += Get-CMDistributionStatus
                }
                Export-RFLXMLFile -VariableName 'DistributionStatusList' -ClearVariable
            }
        }
        #endregion
        
        #region sub-Rules
        $arrRuleID = @(278,279,280,281,282,283,284,286,287,338)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\ApplicationList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "ApplicationList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $ApplicationList += Get-CMApplication
                Export-RFLXMLFile -VariableName 'ApplicationList'
            }
        }
        #endregion
        
        #region sub-Rules
        $arrRuleID = @(286,287)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\DeploymentTypeList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "DeploymentTypeList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {                
                $ApplicationList | ForEach-Object {
                    $DeploymentTypeList += Get-CMDeploymentType -InputObject $_
                }
                
                Export-RFLXMLFile -VariableName 'DeploymentTypeList'
            }
        }
        #endregion

        #region sub-Rules-- parallel
        $arrRuleID = @(286,287)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\PathDTInformationList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "PathDTInformationList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {                
                $ApplicationList | ForEach-Object {
                    $item = $_

                    $DeploymentTypeList | Where-Object {$_.AppModelName -eq $item.ModelName} | ForEach-Object {
                        $subItem = $_
                        #todo: needneed to ignore more?
                        #query for all technology
                        #SELECT distinct SDMPackageDigest.value('declare namespace p1="http://schemas.microsoft.com/SystemCenterConfigurationManager/2009/AppMgmtDigest"; (p1:AppMgmtDigest/p1:DeploymentType/p1:Installer/@Technology)[1]','nvarchar(max)')AS DTTechnology FROM[v_ConfigurationItems] WHERE CIType_ID = 21 
                        if (@('AndroidDeepLink', 'iOSDeepLink', 'WinPhone8Deeplink', 'Deeplink', 'WebApp') -contains $subitem.Technology)  {
                            #ignoring
                        } else {
                            While (@(Get-Job | where-object { $_.State -eq "Running" }).Count -ge $Script:MaxThreads) {  
                                Start-Sleep -Seconds 3
                            }
                            Write-RFLLog -logtype "INFO" -logmessage "Checking folder information for application '$($item.LocalizedDisplayName)' and DeploymentType $($subItem.LocalizedDisplayName)"

                            if ([string]::IsNullOrEmpty($Item.SDMPackageXML) -eq $true) {
                                $arrItem = $subitem.ModelName.Split('/')
                                $itemxml = ([xml]$item.SDMPackageXML)
                                $subitemxml = $itemxml.AppMgmtDigest.DeploymentType | where-object {($_.AuthoringScopeId -eq $arrItem[0]) -and ($_.LogicalName -eq $arrItem[1])}
                                $folderName = $subitemxml.Installer.Contents.Content.Location
                            } else {
                                $subitemxml = [xml]$subItem.SDMPackageXML
                                $folderName = $subitemxml.AppMgmtDigest.DeploymentType.Installer.Contents.Content.Location
                            }
                            if ([string]::IsNullOrEmpty($folderName) -eq $false) {
                                if ($folderName -is [System.Array]) { $folderName = $FolderName[0] }
                                if (Test-Path -LiteralPath "filesystem::$($folderName)" -ErrorAction SilentlyContinue) {
                                    $bPathExist = $true
                                } else {
                                    $bPathExist = $false
                                }

                                $PathDTInformationList += New-Object -TypeName PSObject -Property @{'Application' = $Item.LocalizedDisplayName; 'DTName' = $subItem.LocalizedDisplayName; 'Folder' = $folderName; 'Username' = "$($env:USERDOMAIN)\$($env:USERNAME)"; 'Exist' = $bPathExist }
                            }
                        }
                    }
                }
                Export-RFLXMLFile -VariableName 'PathDTInformationList' -ClearVariable
                Remove-RFLVariable -VariableName 'ApplicationList'
                Remove-RFLVariable -VariableName 'DeploymentTypeList'
            }
        }
        #endregion
        
        #region sub-Rules
        $arrRuleID = @(288,289)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\DPContentList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "DPContentList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {                
                $sqlQuery = 'select * from SMS_DPContentInfo'
                if ([Convert]::ToBoolean($script:IgnoreCloudDP) -eq $true) {
                    $ignoreItemList = ''
                    $SiteRoleList | Where-Object {($_.RoleName -eq 'SMS Distribution Point')} | ForEach-Object {
                        $item = $_
                        if ($item.Props | Where-Object {($_.PropertyName -eq 'IsCloud') -and ($_.Value -eq 1)}) {
                            if (-not [string]::IsNullOrEmpty($ignoreItemList)) { $ignoreItemList += ','}
                            $ignoreItemList = "'$($item.NetworkOSPath)'"
                        }
                    }
                    $sqlQuery += " where NALPath not in ($($ignoreItemList))"
                }
                $DPContentList += (Get-WmiObject -computer $SMSProviderServer -Namespace "root\sms\site_$($MainSiteCode)" -Query $sqlQuery)
                Export-RFLXMLFile -VariableName 'DPContentList' -ClearVariable
            }
        }
        #endregion
        
        #region sub-Rules
        $arrRuleID = @(288,289)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\DPGroupContentList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "DPGroupContentList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {                
                #cade
                $DPGroupContentList += (Get-WmiObject -computer $SMSProviderServer -Namespace "root\sms\site_$($MainSiteCode)" -Query 'select * from SMS_DPGroupContentInfo')
                Export-RFLXMLFile -VariableName 'DPGroupContentList' -ClearVariable
            }
        }
        #endregion
        
        #region sub-Rules
        $arrRuleID = @(290,291,292,293,379,380)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\PackageList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "PackageList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $PackageList += Get-CMPackage
                Export-RFLXMLFile -VariableName 'PackageList'
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(290,291,292,293)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\PathPkgInformationList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "PathPkgInformationList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $PackageList | where-object {$_.PkgSourceFlag -eq 2} | ForEach-Object {
                    $Item = $_
                    Write-RFLLog -logtype "Info" -logmessage "Getting 'Package' information for '$($item.Name)'"
                    $code = {
                        Param (
                            $pkgName,
                            $PkgSourcePath,
                            $HiddenPackages,
                            $pkgID
                        )
                        if (Test-Path -LiteralPath "filesystem::$($PkgSourcePath)" -ErrorAction SilentlyContinue) {
                            $bPathExist = $true
                        } else {
                            $bPathExist = $false
                       }
                        New-Object -TypeName PSObject -Property @{'Name' = $pkgName; 'ID' = $pkgID; 'Folder' = $PkgSourcePath; 'Username' = "$($env:USERDOMAIN)\$($env:USERNAME)"; 'Exist' = $bPathExist }
                    }
                    $PathPkgInformationList += Execute-RFLRunSpace -code $Code -ParameterList @($item.Name, $Item.PkgSourcePath,  $Script:HiddenPackages, $item.PackageID)
                }
                Export-RFLXMLFile -VariableName 'PathPkgInformationList' -ClearVariable
                Remove-RFLVariable -VariableName 'PackageList'
            }
        }
        #endregion
        
        #region sub-Rules
        $arrRuleID = @(294,295)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\OperatingSystemImageList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "OperatingSystemImageList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $OperatingSystemImageList += Get-CMOperatingSystemImage                
                Export-RFLXMLFile -VariableName 'OperatingSystemImageList'
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(294,295)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\PathOSImgInformationList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "PathOSImgInformationList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $OperatingSystemImageList | ForEach-Object {
                    $Item = $_
                    if (-not [string]::IsNullOrEmpty($Item.PkgSourcePath)) {
                        Write-RFLLog -logtype "Info" -logmessage "Getting 'Operating System Image' information for '$($item.Name)'"
                        $code = {
                            Param (
                                $pkgName,
                                $PkgSourcePath,
                                $HiddenPackages,
                                $pkgID
                            )
                            if (Test-Path -LiteralPath "filesystem::$($PkgSourcePath)" -ErrorAction SilentlyContinue) {
                                $bPathExist = $true
                            } else {
                                $bPathExist = $false
                            }
                            New-Object -TypeName PSObject -Property @{'Name' = $pkgName; 'ID' = $pkgID; 'Folder' = $PkgSourcePath; 'Username' = "$($env:USERDOMAIN)\$($env:USERNAME)"; 'Exist' = $bPathExist }
                        }
                        $PathOSImgInformationList += Execute-RFLRunSpace -code $Code -ParameterList @($item.Name, $Item.PkgSourcePath,  $Script:HiddenPackages, $item.PackageID)
                    }
                }
                Export-RFLXMLFile -VariableName 'PathOSImgInformationList' -ClearVariable
                Remove-RFLVariable -VariableName 'OperatingSystemImageList'
            }
        }
        #endregion
        
        #region sub-Rules
        $arrRuleID = @(296,297)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\OperatingSystemInstallerList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "OperatingSystemInstallerList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $OperatingSystemInstallerList += Get-CMOperatingSystemInstaller                
                Export-RFLXMLFile -VariableName 'OperatingSystemInstallerList'
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(296,297)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\PathOSInstallerInformationList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "PathOSInstallerInformationList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $OperatingSystemInstallerList | ForEach-Object {
                    $Item = $_
                    if (-not [string]::IsNullOrEmpty($Item.PkgSourcePath)) {
                        Write-RFLLog -logtype "Info" -logmessage "Getting 'Operating System Installer' information for '$($item.Name)'"
                        $code = {
                            Param (
                                $pkgName,
                                $PkgSourcePath,
                                $HiddenPackages,
                                $pkgID
                            )
                            if (Test-Path -LiteralPath "filesystem::$($PkgSourcePath)" -ErrorAction SilentlyContinue) {
                                $bPathExist = $true
                            } else {
                                $bPathExist = $false
                            }
                            New-Object -TypeName PSObject -Property @{'Name' = $pkgName; 'ID' = $pkgID; 'Folder' = $PkgSourcePath; 'Username' = "$($env:USERDOMAIN)\$($env:USERNAME)"; 'Exist' = $bPathExist }
                        }
                        $PathOSInstallerInformationList += Execute-RFLRunSpace -code $Code -ParameterList @($item.Name, $Item.PkgSourcePath,  $Script:HiddenPackages, $item.PackageID)
                    }
                }
                Export-RFLXMLFile -VariableName 'PathOSInstallerInformationList' -ClearVariable
                Remove-RFLVariable -VariableName 'OperatingSystemInstallerList'
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(300)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\TaskSequenceRebootOptions.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "TaskSequenceRebootOptions" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                
                if ($ModuleConfigMgrVersionBuild -gt 1702) {
                    $TaskSequenceList | ForEach-Object {
                        $item = $_
						
						try {
							Get-CMTaskSequenceStepReboot -TaskSequenceID $item.PackageID | Where-Object {($_.Enabled -eq $true) -and ($_.Target -eq 'WinPE')} | ForEach-Object {
								$subItem = $_
								$TaskSequenceRebootOptions += New-Object -TypeName PSObject -Property @{'Name' = $item.Name; 'StepName' = $subItem.Name}
							}
						} catch {
                            $Global:ErrorCapture += $_
							Write-RFLLog -logtype "EXCEPTION" -logmessage "Error Message: '$($_)'"
						}
					}
                }
                Export-RFLXMLFile -VariableName 'TaskSequenceRebootOptions' -ClearVariable
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(304,305)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\inboxList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "inboxList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {                
                $SiteList | ForEach-Object {
                    Write-RFLLog -logtype "Info" -logmessage "Getting Inbox Files Information for Site '$($_.SiteCode)'"
                    $item = $_
                    $code = {
                        Param (
                            $servername,
                            $siteCode
                        )
                        $returninfo = @()
                        try {
                            if (Test-Path -LiteralPath "filesystem::\\$($ServerName)\SMS_$($SiteCode)\inboxes") {
                                $ChildFolders = Get-ChildItem "filesystem::\\$($ServerName)\SMS_$($SiteCode)\inboxes" -Recurse -ErrorAction Stop | Where-Object {$_.PSIsContainer}
                                foreach($subitem in $ChildFolders) {
                                    if(Test-Path "filesystem::$($subitem.FullName)")
                                    {
                                        $fcount = (Get-ChildItem "filesystem::$($subitem.FullName)" | Where-Object {!$_.PSIsContainer} | Measure-Object).Count
                                        $fsize = "{0:N2}" -f ((Get-ChildItem "filesystem::$($subitem.FullName)" | Where-Object {!$_.PSIsContainer} | Measure-Object).Sum / 1MB)
                                        $returninfo += New-Object -TypeName PSObject -Property @{'ReturnType' = 1; 'SiteCode' = $SiteCode; 'ServerName' = $ServerName; 'FolderName' = $subitem.Name; 'FolderPath' = $subitem.FullName; 'FolderCount' = $fCount; 'FolderSize' = $fsize; 'ConnectionType'='';'Error'=''}
                                    } else {
                                        $returninfo += New-Object -TypeName PSObject -Property @{'ReturnType' = 2; 'SiteCode' = $SiteCode; 'ServerName' = $ServerName; 'FolderName' = $subitem.FullName; 'FolderPath' = $subitem.FullName; 'FolderCount' = 0; 'FolderSize' = 0; 'ConnectionType'='';'Error'=''}
                                    }
                                }
                            } else {
                                $returninfo += New-Object -TypeName PSObject -Property @{'ReturnType' = 3; 'SiteCode' = $SiteCode; 'ServerName' = $ServerName; 'FolderName' = "$($erverName)\SMS_$($SiteCode)\inboxes"; 'FolderPath' = "$($erverName)\SMS_$($SiteCode)\inboxes"; 'FolderCount' = 0; 'FolderSize' = 0; 'ConnectionType'='';'Error'=''}
                            }
                        } catch {
                            $Global:ErrorCapture += $_
                            $returninfo += New-Object -TypeName PSObject -Property @{'ReturnType' = 4; 'SiteCode' = $SiteCode; 'ServerName' = $ServerName; 'FolderName' = ''; 'FolderPath' = ''; 'FolderCount' = 0; 'FolderSize' = 0; 'ConnectionType'='Folder Access (inbox) (SMB)';'Error'=$_}
                        }
                        $returninfo
                    }
                    $returninfo = Execute-RFLRunSpace -code $Code -ParameterList @($item.ServerName, $item.SiteCode)

                    $inboxList += $returninfo | where-object {$_.ReturnType -eq 1}

                    $returninfo | where-object {$_.ReturnType -eq 2} | foreach-object {
                        Write-RFLLog -logtype "ERROR" -logmessage "Folder '$($_.FolderPath)' does not exist"
                    }

                    $returninfo | where-object {$_.ReturnType -eq 3} | foreach-object {
                        Write-RFLLog -logtype "ERROR" -logmessage "Folder '$($_.FolderPath)' does not exist"
                        $Script:ServerDown += New-Object -TypeName PSObject -Property @{'ServerName' = ($_.ServerName); 'ConnectionType' = $_.ConnectionType }
                    }

                    $returninfo | where-object {$_.ReturnType -eq 3} | foreach-object {
                        Write-RFLLog -logtype "EXCEPTION" -logmessage "Server '$($_.ServerName)' generated Error. Error Message: '$($_.Error)'"
                        $Script:ServerDown += New-Object -TypeName PSObject -Property @{'ServerName' = ($_.ServerName); 'ConnectionType' = $_.ConnectionType }
                    }    
                }
                Export-RFLXMLFile -VariableName 'inboxList' -ClearVariable
            }
        }
        #endregion
        
        #region sub-Rules
        $arrRuleID = @(306)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\DriverPackageList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "DriverPackageList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $DriverPackageList += Get-CMDriverPackage
                Export-RFLXMLFile -VariableName 'DriverPackageList' -ClearVariable
            }
        }
        #endregion
        
        #region sub-Rules
        $arrRuleID = @(307)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\ComponentSummarizerList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "ComponentSummarizerList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                #Tally Interval = https://docs.microsoft.com/en-us/previous-versions/system-center/developer/cc144112(v=msdn.10)
                #SMS_ComponentSummarizer = https://docs.microsoft.com/en-us/configmgr/develop/reference/core/servers/manage/sms_componentsummarizer-server-wmi-class
                #Status = 0=green, 1=warning, 2=red
                $ComponentSummarizerList += (Get-WmiObject -computer $SMSProviderServer -Namespace "root\sms\site_$($MainSiteCode)" -Query "SELECT * FROM SMS_ComponentSummarizer WHERE TallyInterval='0001128000100008'")
                Export-RFLXMLFile -VariableName 'ComponentSummarizerList' -ClearVariable
            }
        }
        #endregion
        
        #region sub-Rules
        $arrRuleID = @(308,363)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\ComponentStatusMessageList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "ComponentStatusMessageList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script

                if (Test-Path -LiteralPath "$($SaveToFolder)\ComponentStatusMessageListError.xml") {
                    New-Variable -Name "ComponentStatusMessageListError" -Value (Import-Clixml -Path "$($SaveToFolder)\ComponentStatusMessageListError.xml") -Force -Option AllScope -Scope Script
                }
            } else {
                try {
                    $ComponentStatusMessageList += Get-CMComponentStatusMessage -ViewingPeriod (Get-Date).AddDays(([int]$script:ComponentStatusMessageDateOld)*-1) -Severity Warning
                    $ComponentStatusMessageList += Get-CMComponentStatusMessage -ViewingPeriod (Get-Date).AddDays([int]($script:ComponentStatusMessageDateOld)*-1) -Severity Error
                } catch {
                    $Global:ErrorCapture += $_
                    Write-RFLLog -logtype "EXCEPTION" -logmessage "Error Message: '$($_)'"
                    $ComponentStatusMessageList = @()
                    $ComponentStatusMessageListError += New-Object -TypeName PSObject -Property @{'Error' = $true; }
                }
                Export-RFLXMLFile -VariableName 'ComponentStatusMessageList'
                Export-RFLXMLFile -VariableName 'ComponentStatusMessageListError' -ClearVariable 
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(308,363)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\ComponentStatusMessageCompletedList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "ComponentStatusMessageCompletedList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $ComponentStatusMessageList | Group-Object {$_.MessageID} | ForEach-Object {
                    try {
                        $item = $_
                        $Resolution = ''
                        $Message = ''
                        $objMessageresult = ''
                        $objRecordID = ''
                        $objMessage = ''
                        $sizeOfBuffer = [int]16384
                        $stringArrayInput = {"%1","%2","%3","%4","%5", "%6", "%7", "%8", "%9"}
                        $stringOutput = New-Object System.Text.StringBuilder $sizeOfBuffer

                        Write-RFLLog -logtype "Info" -logmessage "Getting 'Component Status Message Details for MessageID $($item.Group[0].MessageID)' List Information"

                        $objMessageresult = switch ($item.Group[0].ModuleName) {
                            'SMS Client' { 
                                $objMessageresult = $Win32FormatMessage::FormatMessage($flags, $ptrCliModule, $item.Group[0].Severity -bor $item.Group[0].MessageID, 0, $stringOutput, $sizeOfBuffer, $stringArrayInput)
                            }
                            'SMS Provider' {
                                $objMessageresult = $Win32FormatMessage::FormatMessage($flags, $ptrPrvModule, $item.Group[0].Severity -bor $item.Group[0].MessageID, 0, $stringOutput, $sizeOfBuffer, $stringArrayInput)
                            }
                            default {
                                $objMessageresult = $Win32FormatMessage::FormatMessage($flags, $ptrsrvModule, $item.Group[0].Severity -bor $item.Group[0].MessageID, 0, $stringOutput, $sizeOfBuffer, $stringArrayInput)
                            }
                        }

                        #if ($item.Group[0].ModuleName -eq 'SMS Client') {
                        #    $objMessageresult = $Win32FormatMessage::FormatMessage($flags, $ptrCliModule, $item.Group[0].Severity -bor $item.Group[0].MessageID, 0, $stringOutput, $sizeOfBuffer, $stringArrayInput)
                        #} else {
                        #    $objMessageresult = $Win32FormatMessage::FormatMessage($flags, $ptrsrvModule, $item.Group[0].Severity -bor $item.Group[0].MessageID, 0, $stringOutput, $sizeOfBuffer, $stringArrayInput)
                        #}

                        $objRecordID = (Get-WmiObject -computer $SMSProviderServer -Namespace "root\sms\site_$($MainSiteCode)" -Query "Select * from SMS_StatMsgInsStrings where recordid = $($item.Group[0].RecordID)")
                        $objMessage = $stringOutput.toString().Replace("%11","").Replace("%12","").Replace("%3%4%5%6%7%8%9%10","")
                        $objRecordID | ForEach-Object {
                            $objMessage = $objMessage.Replace("%$($_.InsStrIndex+1)", $_.InsStrValue)
                        }

                        $indexof = $objMessage.tolower().indexof('possible cause')
                        if ($indexof -ge 0) {
                            $arrMessage = $objMessage.Split([System.Environment]::NewLine)
                            $Message = $arrMessage[0]
                            $FullMessage = $Message

                            $intSubstring = $Message.tolower().indexof('possible cause')
                            if ($intSubstring -ge 0) {
                                $Message = $Message.Substring(0, $intSubstring).trim()
                            }

                            $intSubstring = $Message.tolower().indexof('solution')
                            if ($intSubstring -ge 0) {
                                $Message = $Message.Substring(0, $intSubstring).trim()
                            }

                            for($i = 0; $i -lt $arrMessage.Count; $i++) {
                                if ([string]::IsNullOrEmpty($arrMessage[$i])) {
                                    continue
                                }
                                $intPossibleCause = $arrMessage[$i].tolower().indexof('possible cause:')
                                if ($intPossibleCause -lt 0) {
                                    $intPossibleCause = $arrMessage[$i].tolower().indexof('possible causes:')
                                }
                                $intSolution = $arrMessage[$i].tolower().indexof('solution:')
                                if ($intSolution -lt 0) {
                                    $intSolution = $arrMessage[$i].tolower().indexof('solutions:')
                                }
                                if ($intPossibleCause -ge 0) {
                                    if (-not [String]::IsNullOrEmpty($Resolution)) {
                                        $Resolution += '[NL][NL]'
                                    }
                                    $Resolution += $arrMessage[$i].Substring($intPossibleCause).Replace('Possible cause: ','').Replace('Possible causes: ','').trim()
                                } elseif ($intSolution -ge 0) {
                                    $Resolution += " $($arrMessage[$i].Substring($intSolution).Replace('Solution: ','').Replace('Solutions: ','').trim())"
                                }
                            }
                        } else {
                            $Message = $objMessage.Trim().Replace([System.Environment]::NewLine, ' ')
                            $intSubstring = $Message.tolower().indexof('possible cause')
                            if ($intSubstring -ge 0) {
                                $Message = $Message.Substring(0, $intSubstring).trim()
                            }

                            $intSubstring = $Message.tolower().indexof('solution')
                            if ($intSubstring -ge 0) {
                                $Message = $Message.Substring(0, $intSubstring).trim()
                            }

                            $FullMessage = $Message
                        }

                        $ComponentStatusMessageCompletedList += New-Object -TypeName PSObject -Property @{'ItemCount' = $item.Count; 'Component' = $item.Group[0].Component; 'MachineName' = $item.Group[0].MachineName; 'MessageID' = $item.Group[0].MessageID; 'RecordID' = $item.Group[0].RecordID; 'Message' = $Message; 'FullMessage' = $FullMessage; 'Resolution' = $Resolution; 'Time' = $item.Group[0].Time }
                    } catch {
                        $Global:ErrorCapture += $_
                        Write-RFLLog -logtype "EXCEPTION" -logmessage "Error Message: '$($_)'"
                    }
                }
                Export-RFLXMLFile -VariableName 'ComponentStatusMessageCompletedList' -ClearVariable
                Remove-RFLVariable -VariableName 'ComponentStatusMessageList'
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(312)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\SUPWIDList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "SUPWIDList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {                
                $SUPList | ForEach-Object {
                    $item = $_
                    $WSUSServerName = ($item.NetworkOSPath.Replace('\\',''))
                    Write-RFLLog -logtype "Info" -logmessage "Getting 'WSUS' information for '$($WSUSServerName)'"
                    $code = {
                        Param (
                            $sitecode,
                            $WSUSServerName,
                            $HiddenPackages,
                            $pkgID
                        )
                        try {
                            $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $WSUSServerName)
                            $RegKey= $Reg.OpenSubKey("SOFTWARE\Microsoft\Update Services\Server\Setup\Installed Role Services")
                            $WIDExist = -not [String]::IsNullOrEmpty(($RegKey.GetValueNames() | Where-Object {$_ -eq 'UpdateServices-WidDatabase'}))

                            if ($WIDExist) {
                                New-Object -TypeName PSObject -Property @{'Success' = $true; 'SiteCode' = $sitecode; 'ServerName' = $WSUSServerName; 'ConnectionType' = ''; 'Error'=''  }
                            }
                        } catch {
                            $Global:ErrorCapture += $_
                            New-Object -TypeName PSObject -Property @{'Success' = $false; 'SiteCode' = $sitecode; 'ServerName' = $WSUSServerName; 'ConnectionType' = 'WID Remote Registry (RRP/RPC)'; 'Error'= $_  }
                        }
                    }
                    $returninfo = Execute-RFLRunSpace -code $Code -ParameterList @($item.SiteCode, $WSUSServerName)

                    $SUPWIDList += $returninfo | where-object {$_.Success -eq $true}

                    $returninfo | where-object {$_.Success -eq $false} | ForEach-Object {
                        Write-RFLLog -logtype "EXCEPTION" -logmessage "Error Message: '$($_.Error)'"
                        $Script:ServerDown += New-Object -TypeName PSObject -Property @{'ServerName' = $_.ServerName; 'ConnectionType' = $_.ConnectionType }
                    }
                }
                Export-RFLXMLFile -VariableName 'SUPWIDList' -ClearVariable
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(313)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            $FileToImport = "$($SaveToFolder)\ServerNOSMSONDriveInformation.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "ServerNOSMSONDriveInformation" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {                
                $SiteRoleListWOCDP | select-Object SiteCode, @{Name='NetworkOSPath';Expression={$_.NetworkOSPath.Tolower().Trim()}} -Unique | ForEach-Object {
                    $item = $_
                    $RemoteComputer = ($item.NetworkOSPath.Replace('\\',''))
                    Write-RFLLog -logtype "Info" -logmessage "Getting File information ('NO_SMS_ON_DRIVE.SMS on SystemDrive') for '$($RemoteComputer)'"
                    $code = {
                        Param (
                            $RemoteComputer,
                            $siteCode,
                            $HiddenPackages,
                            $pkgID
                        )
                        try {
                            $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $RemoteComputer)
                            $RegKey= $Reg.OpenSubKey("SOFTWARE\Microsoft\Windows NT\CurrentVersion")
                    
                            $SystemRoot = $RegKey.GetValue("SystemRoot").Split('\')[0].Replace(':','$')
                            if (Test-Path -LiteralPath "filesystem::\\$($RemoteComputer)\$($SystemRoot)\NO_SMS_ON_DRIVE.SMS" -ErrorAction SilentlyContinue) {
                                $bPathExist = $true
                            } else {
                                $bPathExist = $false
                            }
                            New-Object -TypeName PSObject -Property @{'Success' = $true; 'SiteCode' = $SiteCode; 'ServerName' = $RemoteComputer; 'FileExist' = $bPathExist; 'Folder' = $SystemRoot; 'ConnectionType'='';'Error' =''; }
                        } catch {
                            $Global:ErrorCapture += $_
                            New-Object -TypeName PSObject -Property @{'Success' = $false; 'SiteCode' = $SiteCode; 'ServerName' = $RemoteComputer; 'FileExist' = $bPathExist; 'Folder' = 'C:\'; 'ConnectionType'='NO_SMS_ON_DRIVE.SMS';'Error' = $_; }
                        }
                    }
                    $returninfo = Execute-RFLRunSpace -code $Code -ParameterList @($RemoteComputer, $item.SiteCode)

                    $returninfo | where-object {$_.Success -eq $true} | foreach-object {
                        $ServerNOSMSONDriveInformation += $_
                    }

                    $returninfo | where-object {$_.Success -eq $false} | foreach-object {
                        Write-RFLLog -logtype "EXCEPTION" -logmessage "Error Message: '$($_.Error)'"
                        $Script:ServerDown += New-Object -TypeName PSObject -Property @{'ServerName' = $_.ServerName; 'ConnectionType' = $_.ConnectionType }
                    }
                }
                Export-RFLXMLFile -VariableName 'ServerNOSMSONDriveInformation' -ClearVariable
            }
        }
        #endregion
        
        #region sub-Rules
        $arrRuleID = @(314)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\SUPSQL.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "SUPSQL" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {                
                $SUPList | ForEach-Object {
                    $item = $_
                    $WSUSServerName = ($item.NetworkOSPath.Replace('\\',''))
                    Write-RFLLog -logtype "Info" -logmessage "Getting File information ('WSUS Information') for '$($WSUSServerName)'"
                    $code = {
                        Param (
                            [string]$WSUSServerName,
                            $siteCode
                        )
                        try {
                            $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $WSUSServerName)
                            $RegKey= $Reg.OpenSubKey("SOFTWARE\Microsoft\Update Services\Server\Setup")
                            $WSUSSQL = $RegKey.GetValue('SqlServerName').ToString()    
                            New-Object -TypeName PSObject -Property @{'Success' = $true;'SiteCode' = $SiteCode; 'ServerName' = $WSUSServerName; 'SQLServer' = $WSUSSQL; 'ConnectionType' = ''; 'Error' = '' }
                        } catch {
                            $Global:ErrorCapture += $_
                            New-Object -TypeName PSObject -Property @{'Success' = $false;'SiteCode' = $SiteCode; 'ServerName' = $WSUSServerName; 'SQLServer' = $WSUSSQL; 'ConnectionType' = 'WSUS Remote Registry (RRP/RPC)'; 'Error' = $_ }
                        }
                    }
                    $returninfo = Execute-RFLRunSpace -code $Code -ParameterList @($WSUSServerName, $item.SiteCode)

                    $returninfo | where-object {$_.Success -eq $true} | foreach-object {
                        $SUPSQL += $_
                    }

                    $returninfo | where-object {$_.Success -eq $false} | foreach-object {
                        Write-RFLLog -logtype "EXCEPTION" -logmessage "Error Message: '$($_.Error)'"
                        $Script:ServerDown += New-Object -TypeName PSObject -Property @{'ServerName' = $_.ServerName; 'ConnectionType' = $_.ConnectionType }
                    }
                }
                Export-RFLXMLFile -VariableName 'SUPSQL' -ClearVariable
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(315)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\ApprovalRequestList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "ApprovalRequestList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $ApprovalRequestList += Get-CMApprovalRequest
                Export-RFLXMLFile -VariableName 'ApprovalRequestList' -ClearVariable
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(319)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\SUPComponentSyncManager.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "SUPComponentSyncManager" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $SUPComponentSyncManager += Get-CMSoftwareUpdatePointComponent -WsusSyncManager
                Export-RFLXMLFile -VariableName 'SUPComponentSyncManager' -ClearVariable
            }
        }
        #endregion
        
        #region sub-Rules
        $arrRuleID = @(320)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\SUPComponent.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "SUPComponent" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $SUPComponent += Get-CMSoftwareUpdatePointComponent
                Export-RFLXMLFile -VariableName 'SUPComponent' -ClearVariable
            }
        }
        #endregion
        
        #region sub-Rules
        $arrRuleID = @(325,326)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\SiteDefinition.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "SiteDefinition" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $SiteDefinition += Get-CMSiteDefinition
                Export-RFLXMLFile -VariableName 'SiteDefinition' -ClearVariable
            }
        }
        #endregion        
        
        #region sub-Rules
        $arrRuleID = @(327,328,405)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\SoftwareVersionList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "SoftwareVersionList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $SiteList | ForEach-Object {
                    $item = $_
                    $ServerName = $item.ServerName

                    try {
                        $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ServerName)
                        $RegKey= $Reg.OpenSubKey("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall")
                        $RegKey.GetSubKeyNames() | ForEach-Object {
                            $RegSubKey= $RegKey.OpenSubKey($_)
                            $SoftwareVersionList += New-Object -TypeName PSObject -Property @{'SiteCode' = $item.SiteCode; 'ServerName' = $ServerName; 'Key' = $_; 'Name' = $RegSubKey.GetValue("DisplayName"); 'Version' = $RegSubKey.GetValue("DisplayVersion"); 'Publisher' = $RegSubKey.GetValue("Publisher"); 'Architecture' = '64bit' }
                        }
                    } catch {
                        $Global:ErrorCapture += $_
                        Write-RFLLog -logtype "EXCEPTION" -logmessage "Error Message: '$($_)'"
                        $Script:ServerDown += New-Object -TypeName PSObject -Property @{'ServerName' = $ServerName; 'ConnectionType' = 'Add/Remove Programs Remote Registry (64bit)' }
                    }

                    try {
                        $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $ServerName)
                        $RegKey= $Reg.OpenSubKey("SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall")
                        $RegKey.GetSubKeyNames() | ForEach-Object {
                            $RegSubKey= $RegKey.OpenSubKey($_)
                            $SoftwareVersionList += New-Object -TypeName PSObject -Property @{'SiteCode' = $item.SiteCode; 'ServerName' = $ServerName; 'Key' = $_; 'Name' = $RegSubKey.GetValue("DisplayName"); 'Version' = $RegSubKey.GetValue("DisplayVersion"); 'Publisher' = $RegSubKey.GetValue("Publisher"); 'Architecture' = '32bit' }
                        }
                    } catch {
                        $Global:ErrorCapture += $_
                        Write-RFLLog -logtype "EXCEPTION" -logmessage "Error Message: '$($_)'"
                        $Script:ServerDown += New-Object -TypeName PSObject -Property @{'ServerName' = $ServerName; 'ConnectionType' = 'Add/Remove Programs Remote Registry (32bit)' }

                    }
                }
                Export-RFLXMLFile -VariableName 'SoftwareVersionList' -ClearVariable
            }
        }
        #endregion
        
        #region sub-Rules
        $arrRuleID = @(329)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\ServiceList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "ServiceList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {                
                $SiteRoleListWOCDP | select-Object SiteCode, @{Name='NetworkOSPath';Expression={$_.NetworkOSPath.Tolower().Trim()}} -Unique | ForEach-Object {
                    $item = $_
                    $RemoteComputer = ($item.NetworkOSPath.Replace('\\',''))
                    While (@(Get-Job | where-object { $_.State -eq "Running" }).Count -ge $Script:MaxThreads) {  
                        Start-Sleep -Seconds 3
                    }
                    Write-RFLLog -logtype "Info" -logmessage "Getting File information ('ConfigMgr Services') for '$($RemoteComputer)'"
                    $Scriptblock = {
                        Param (
                            $RemoteComputer
                        )
                        $returnInfo = @()
                        try {
                            $itemReturn = (Get-WmiObject -ComputerName $RemoteComputer -namespace "root\cimv2" -class "win32_Service" -ErrorAction SilentlyContinue) 
                    
                            if ($null -ne $itemReturn) {
                                $itemReturn | ForEach-Object {
                                    $returnInfo += New-Object -TypeName PSObject -Property @{'ReturnType' = 1; 'ConnectionType'='';'Error'=''; 'ServerName' = $RemoteComputer; 'AcceptPause' = $_.AcceptPause; 'AcceptStop' = $_.AcceptStop; 'Caption' = $_.Caption; 'CheckPoint' = $_.CheckPoint; 'CreationClassName' = $_.CreationClassName; 'DelayedAutoStart' = $_.DelayedAutoStart; 'Description'=$_.Description;'DesktopInteract'=$_.DesktopInteract;'DisplayName'=$_.DisplayName;'ErrorControl'=$_.ErrorControl;'ExitCode'=$_.ExitCode;'InstallDate'=$_.InstallDate;'Name'=$_.Name;'PathName'=$_.PathName;'ProcessId'=$_.ProcessId;'ServiceSpecificExitCode'=$_.ServiceSpecificExitCode;'ServiceType'=$_.ServiceType;'Started'=$_.Started;'StartMode'=$_.StartMode;'StartName'=$_.StartName;'State'=$_.State;'Status'=$_.Status;'SystemCreationClassName'=$_.SystemCreationClassName;'SystemName'=$_.SystemName;'TagId'=$_.TagId;'WaitHint'=$_.WaitHint; }
                                }
                            } else {
                                $returnInfo = New-Object -TypeName PSObject -Property @{'ReturnType' = 2; 'ConnectionType'='WMI (root\cimv2) Service';'Error'=''; 'ServerName' = $RemoteComputer; 'AcceptPause' = $false; 'AcceptStop' = $false; 'Caption' = ''; 'CheckPoint' = 0; 'CreationClassName' = ''; 'DelayedAutoStart' = $false; 'Description'='';'DesktopInteract'=$false;'DisplayName'='';'ErrorControl'='';'ExitCode'=0;'InstallDate'=(Get-Date);'Name'='';'PathName'='';'ProcessId'=0;'ServiceSpecificExitCode'=0;'ServiceType'='';'Started'=$false;'StartMode'='';'StartName'='';'State'='';'Status'='';'SystemCreationClassName'='';'SystemName'='';'TagId'=0;'WaitHint'=0; }
                                break
                            }
                        } catch {
                            $Global:ErrorCapture += $_
                            $returnInfo = New-Object -TypeName PSObject -Property @{'ReturnType' = 3; 'ConnectionType'='WMI (root\cimv2) Service';'Error'=$_; 'ServerName' = $RemoteComputer; 'AcceptPause' = $false; 'AcceptStop' = $false; 'Caption' = ''; 'CheckPoint' = 0; 'CreationClassName' = ''; 'DelayedAutoStart' = $false; 'Description'='';'DesktopInteract'=$false;'DisplayName'='';'ErrorControl'='';'ExitCode'=0;'InstallDate'=(Get-Date);'Name'='';'PathName'='';'ProcessId'=0;'ServiceSpecificExitCode'=0;'ServiceType'='';'Started'=$false;'StartMode'='';'StartName'='';'State'='';'Status'='';'SystemCreationClassName'='';'SystemName'='';'TagId'=0;'WaitHint'=0; }
                            break
                        }
                        $returnInfo
                    }
                    Start-Job -ScriptBlock $Scriptblock -ArgumentList @($RemoteComputer) | out-null
                }
                While (@(Get-Job | where-object { $_.State -eq "Running" }).Count -ge 1) {  
                    Start-Sleep -Seconds 3
                }
                
                $returninfo = ForEach ($Job in (Get-Job)) {
                    Receive-Job $Job
                    Remove-Job $Job
                }
                $ServiceList += $returninfo | where-object {$_.ReturnType -eq 1}
                $returninfo | where-object {$_.ReturnType -eq 2} | ForEach-Object {
                    $Script:ServerDown += New-Object -TypeName PSObject -Property @{'ServerName' = $_.ServerName; 'ConnectionType' = $_.ConnectionType }
                }
                $returninfo | where-object {$_.ReturnType -eq 3} | ForEach-Object {
                    Write-RFLLog -logtype "EXCEPTION" -logmessage "Server '$($_.ServerName)' generated Error. Error Message: '$($_.Error)'"
                    $Script:ServerDown += New-Object -TypeName PSObject -Property @{'ServerName' = $_.ServerName; 'ConnectionType' = $_.ConnectionType }
                }
                Export-RFLXMLFile -VariableName 'ServiceList' -ClearVariable
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(334,335,336,337,381)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\PingList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "PingList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $SiteRoleListWOCDP | select-Object SiteCode, @{Name='NetworkOSPath';Expression={$_.NetworkOSPath.Tolower().Trim()}} -Unique | ForEach-Object {
                    $item = $_
                    $RemoteComputer = ($item.NetworkOSPath.Replace('\\',''))
                    While (@(Get-Job | where-object { $_.State -eq "Running" }).Count -ge $Script:MaxThreads) {  
                        Start-Sleep -Seconds 3
                    }
                    Write-RFLLog -logtype "Info" -logmessage "Getting File information ('Ping Information') for '$($RemoteComputer)'"
                    $Scriptblock = {
                        Param (
                            [string]$CN,
                            [int]$MaxPingCount,
                            [int]$PingDelay
                        )
                        $returnInfo = @()
                        for($i=1; $i -le $MaxPingCount; $i++) {
                            $pingreturn = Test-Connection -ComputerName $CN -Count 1 -ErrorAction SilentlyContinue
                            if ($null -eq $pingreturn) {
                                $returnInfo += New-Object -TypeName PSObject -Property @{'Source' = $pingreturn.__SERVER; 'Destination' = $CN; 'IPV4' = ''; 'ResponseTime' = 4000; 'Success' = $false  }
                            } else {
                                $returnInfo += New-Object -TypeName PSObject -Property @{'Source' = $pingreturn.__SERVER; 'Destination' = $pingreturn.Address; 'IPV4' = $pingreturn.IPV4Address.IPAddressToString; 'ResponseTime' = $pingreturn.ResponseTime; 'Success' = $true  }
                            }
                            Start-Sleep $PingDelay
                        }
                        $returnInfo
                    }
                    Start-Job -ScriptBlock $Scriptblock -ArgumentList @($RemoteComputer, [int]$Script:MaxPingCount, $Script:PingDelay) | out-null
                }
                While (@(Get-Job | where-object { $_.State -eq "Running" }).Count -ge 1) {  
                    Start-Sleep -Seconds 3
                }
                
                $PingList += ForEach ($Job in (Get-Job)) {
                    Receive-Job $Job
                    Remove-Job $Job
                }
                Export-RFLXMLFile -VariableName 'PingList' -ClearVariable
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(339)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\IntuneSubscription.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "IntuneSubscription" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                if ($ModuleConfigMgrVersionBuild -ge 1910) {
                    $IntuneSubscription = @()
                } else {
                    $IntuneSubscription += Get-CMIntuneSubscription
                }
                Export-RFLXMLFile -VariableName 'IntuneSubscription' -ClearVariable
            }
        }
        #endregion
        
        #region sub-Rules
        $arrRuleID = @(340,343)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\Boundary.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "Boundary" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                #xx test
                $Boundary += Get-CMBoundary
                Export-RFLXMLFile -VariableName 'Boundary' -ClearVariable
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(344,345)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            $FileToImport = "$($SaveToFolder)\LogicalDiskInfoList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "LogicalDiskInfoList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {                
                $SiteRoleListWOCDP | select-Object SiteCode, @{Name='NetworkOSPath';Expression={$_.NetworkOSPath.Tolower().Trim()}} -Unique | ForEach-Object {
                    $item = $_
                    While (@(Get-Job | where-object { $_.State -eq "Running" }).Count -ge $Script:MaxThreads) {  
                        Start-Sleep -Seconds 3
                    }
                    $RemoteComputer = ($item.NetworkOSPath.Replace('\\',''))
                    Write-RFLLog -logtype "Info" -logmessage "Getting File information ('Logical Disk') for '$($RemoteComputer)'"
                    $Scriptblock = {
                        Param (
                            $RemoteComputer
                        )
                        $returnInfo = @()
                        try {
                            $itemReturn = (Get-WmiObject -ComputerName $RemoteComputer -namespace "root\cimv2" -class "Win32_LogicalDisk" -ErrorAction SilentlyContinue)
                            if ($null -ne $itemReturn) {
                                $itemReturn | ForEach-Object {
                                    $returnInfo += New-Object -TypeName PSObject -Property @{'ReturnType' = 1; 'ConnectionType'='';'Error'=''; 'ServerName' = $RemoteComputer; 'Access'=$_.Access; 'Availability'=$_.Availability; 'BlockSize'=$_.BlockSize; 'Caption'=$_.Caption; 'Compressed'=$_.Compressed; 'ConfigManagerErrorCode'=$_.ConfigManagerErrorCode; 'ConfigManagerUserConfig'=$_.ConfigManagerUserConfig; 'CreationClassName'=$_.CreationClassName; 'Description'=$_.Description; 'DeviceID'=$_.DeviceID; 'DriveType'=$_.DriveType; 'ErrorCleared'=$_.ErrorCleared; 'ErrorDescription'=$_.ErrorDescription; 'ErrorMethodology'=$_.ErrorMethodology; 'FileSystem'=$_.FileSystem; 'FreeSpace'=$_.FreeSpace; 'InstallDate'=$_.InstallDate; 'LastErrorCode'=$_.LastErrorCode; 'MaximumComponentLength'=$_.MaximumComponentLength; 'MediaType'=$_.MediaType; 'Name'=$_.Name; 'NumberOfBlocks'=$_.NumberOfBlocks; 'PNPDeviceID'=$_.PNPDeviceID; 'PowerManagementSupported'=$_.PowerManagementSupported; 'ProviderName'=$_.ProviderName; 'Purpose'=$_.Purpose; 'QuotasDisabled'=$_.QuotasDisabled; 'QuotasIncomplete'=$_.QuotasIncomplete; 'QuotasRebuilding'=$_.QuotasRebuilding; 'Size'=$_.Size; 'Status'=$_.Status; 'StatusInfo'=$_.StatusInfo; 'SupportsDiskQuotas'=$_.SupportsDiskQuotas; 'SupportsFileBasedCompression'=$_.SupportsFileBasedCompression; 'SystemCreationClassName'=$_.SystemCreationClassName; 'SystemName'=$_.SystemName; 'VolumeDirty'=$_.VolumeDirty; 'VolumeName'=$_.VolumeName; 'VolumeSerialNumber'=$_.VolumeSerialNumber; }
                                }
                            } else {
                                $returnInfo += New-Object -TypeName PSObject -Property @{'ReturnType' = 2; 'ConnectionType'='WMI (root\cimv2) Disk';'Error'=''; 'ServerName' = $RemoteComputer; 'Access'=0; 'Availability'=0; 'BlockSize'=0; 'Caption'=''; 'Compressed'=$false; 'ConfigManagerErrorCode'=0; 'ConfigManagerUserConfig'=$false; 'CreationClassName'=''; 'Description'=''; 'DeviceID'=''; 'DriveType'=0; 'ErrorCleared'=$false; 'ErrorDescription'=''; 'ErrorMethodology'=''; 'FileSystem'=''; 'FreeSpace'=0; 'InstallDate'=(Get-Date); 'LastErrorCode'=0; 'MaximumComponentLength'=0; 'MediaType'=0; 'Name'=''; 'NumberOfBlocks'=0; 'PNPDeviceID'=''; 'PowerManagementSupported'=$false; 'ProviderName'=''; 'Purpose'=''; 'QuotasDisabled'=$false; 'QuotasIncomplete'=$false; 'QuotasRebuilding'=$false; 'Size'=0; 'Status'=''; 'StatusInfo'=0; 'SupportsDiskQuotas'=$false; 'SupportsFileBasedCompression'=$false; 'SystemCreationClassName'=''; 'SystemName'=''; 'VolumeDirty'=$false; 'VolumeName'=''; 'VolumeSerialNumber'=''; }
                            }
                        } catch {
                            $Global:ErrorCapture += $_
                            $returnInfo += New-Object -TypeName PSObject -Property @{'ReturnType' = 3; 'ConnectionType'='WMI (root\cimv2) Disk';'Error'=$_; 'ServerName' = $RemoteComputer; 'Access'=0; 'Availability'=0; 'BlockSize'=0; 'Caption'=''; 'Compressed'=$false; 'ConfigManagerErrorCode'=0; 'ConfigManagerUserConfig'=$false; 'CreationClassName'=''; 'Description'=''; 'DeviceID'=''; 'DriveType'=0; 'ErrorCleared'=$false; 'ErrorDescription'=''; 'ErrorMethodology'=''; 'FileSystem'=''; 'FreeSpace'=0; 'InstallDate'=(Get-Date); 'LastErrorCode'=0; 'MaximumComponentLength'=0; 'MediaType'=0; 'Name'=''; 'NumberOfBlocks'=0; 'PNPDeviceID'=''; 'PowerManagementSupported'=$false; 'ProviderName'=''; 'Purpose'=''; 'QuotasDisabled'=$false; 'QuotasIncomplete'=$false; 'QuotasRebuilding'=$false; 'Size'=0; 'Status'=''; 'StatusInfo'=0; 'SupportsDiskQuotas'=$false; 'SupportsFileBasedCompression'=$false; 'SystemCreationClassName'=''; 'SystemName'=''; 'VolumeDirty'=$false; 'VolumeName'=''; 'VolumeSerialNumber'=''; }
                        }
                        $returnInfo
                    }
                    Start-Job -ScriptBlock $Scriptblock -ArgumentList @($RemoteComputer) | out-null
                }
                While (@(Get-Job | where-object { $_.State -eq "Running" }).Count -ge 1) {  
                    Start-Sleep -Seconds 3
                }
                
                $returninfo = ForEach ($Job in (Get-Job)) {
                    Receive-Job $Job
                    Remove-Job $Job
                }
                $LogicalDiskInfoList += $returninfo | where-object {$_.ReturnType -eq 1}
                $returninfo | where-object {$_.ReturnType -eq 2} | ForEach-Object {
                    $Script:ServerDown += New-Object -TypeName PSObject -Property @{'ServerName' = $_.ServerName; 'ConnectionType' = $_.ConnectionType }
                }
                $returninfo | where-object {$_.ReturnType -eq 3} | ForEach-Object {
                    Write-RFLLog -logtype "EXCEPTION" -logmessage "Server '$($_.ServerName)' generated Error. Error Message: '$($_.Error)'"
                    $Script:ServerDown += New-Object -TypeName PSObject -Property @{'ServerName' = $_.ServerName; 'ConnectionType' = $_.ConnectionType }
                } 
                Export-RFLXMLFile -VariableName 'LogicalDiskInfoList' -ClearVariable
            }
        }
        #endregion
        
        #region sub-Rules
        $arrRuleID = @(346,347,348,349)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            $FileToImport = "$($SaveToFolder)\ComputerInformationList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "ComputerInformationList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {                
                $SiteRoleListWOCDP | select-Object SiteCode, @{Name='NetworkOSPath';Expression={$_.NetworkOSPath.Tolower().Trim()}} -Unique | ForEach-Object {
                    $item = $_
                    $RemoteComputer = ($item.NetworkOSPath.Replace('\\',''))
                    While (@(Get-Job | where-object { $_.State -eq "Running" }).Count -ge $Script:MaxThreads) {  
                        Start-Sleep -Seconds 3
                    }
                    Write-RFLLog -logtype "Info" -logmessage "Getting File information ('Computer') for '$($RemoteComputer)'"
                    $Scriptblock = {
                        Param (
                            $RemoteComputer
                        )
                        $returnInfo = @()
                        try {
                            $itemReturn = (Get-WmiObject -ComputerName $RemoteComputer -namespace "root\cimv2" -class "Win32_ComputerSystem" -ErrorAction SilentlyContinue)
                            if ($null -ne $itemReturn) {
                                $itemReturn | ForEach-Object {
                                    $returnInfo += New-Object -TypeName PSObject -Property @{'ReturnType' = 1; 'ConnectionType'='';'Error'=''; 'ServerName' = $RemoteComputer;  'AdminPasswordStatus' = $_.AdminPasswordStatus; 'AutomaticManagedPagefile' = $_.AutomaticManagedPagefile; 'AutomaticResetBootOption' = $_.AutomaticResetBootOption; 'AutomaticResetCapability' = $_.AutomaticResetCapability; 'BootOptionOnLimit' = $_.BootOptionOnLimit; 'BootOptionOnWatchDog' = $_.BootOptionOnWatchDog; 'BootROMSupported' = $_.BootROMSupported; 'BootupState' = $_.BootupState; 'Caption' = $_.Caption; 'ChassisBootupState' = $_.ChassisBootupState; 'ChassisSKUNumber' = $_.ChassisSKUNumber; 'CreationClassName' = $_.CreationClassName; 'CurrentTimeZone' = $_.CurrentTimeZone; 'DaylightInEffect' = $_.DaylightInEffect; 'Description' = $_.Description; 'DNSHostName' = $_.DNSHostName; 'Domain' = $_.Domain; 'DomainRole' = $_.DomainRole; 'EnableDaylightSavingsTime' = $_.EnableDaylightSavingsTime; 'FrontPanelResetStatus' = $_.FrontPanelResetStatus; 'HypervisorPresent' = $_.HypervisorPresent; 'InfraredSupported' = $_.InfraredSupported; 'InstallDate' = $_.InstallDate; 'KeyboardPasswordStatus' = $_.KeyboardPasswordStatus; 'LastLoadInfo' = $_.LastLoadInfo; 'Manufacturer' = $_.Manufacturer; 'Model' = $_.Model; 'Name' = $_.Name; 'NameFormat' = $_.NameFormat; 'NetworkServerModeEnabled' = $_.NetworkServerModeEnabled; 'NumberOfLogicalProcessors' = $_.NumberOfLogicalProcessors; 'NumberOfProcessors' = $_.NumberOfProcessors; 'PartOfDomain' = $_.PartOfDomain; 'PauseAfterReset' = $_.PauseAfterReset; 'PCSystemType' = $_.PCSystemType; 'PCSystemTypeEx' = $_.PCSystemTypeEx; 'PowerManagementSupported' = $_.PowerManagementSupported; 'PowerOnPasswordStatus' = $_.PowerOnPasswordStatus; 'PowerState' = $_.PowerState; 'PowerSupplyState' = $_.PowerSupplyState; 'PrimaryOwnerContact' = $_.PrimaryOwnerContact; 'PrimaryOwnerName' = $_.PrimaryOwnerName; 'ResetCapability' = $_.ResetCapability; 'ResetCount' = $_.ResetCount; 'ResetLimit' = $_.ResetLimit; 'Status' = $_.Status; 'SystemFamily' = $_.SystemFamily; 'SystemSKUNumber' = $_.SystemSKUNumber; 'SystemStartupDelay' = $_.SystemStartupDelay; 'SystemStartupSetting' = $_.SystemStartupSetting; 'SystemType' = $_.SystemType; 'ThermalState' = $_.ThermalState; 'TotalPhysicalMemory' = $_.TotalPhysicalMemory; 'UserName' = $_.UserName; 'WakeUpType' = $_.WakeUpType; 'Workgroup' = $_.Workgroup; }
                                }
                            } else {
                                $returnInfo += New-Object -TypeName PSObject -Property @{'ReturnType' = 2; 'ConnectionType'='WMI (root\cimv2) Computer';'Error'=''; 'ServerName' = $RemoteComputer; 'AdminPasswordStatus' = 0; 'AutomaticManagedPagefile' = $false; 'AutomaticResetBootOption' = $false; 'AutomaticResetCapability' = $false; 'BootOptionOnLimit' = 0; 'BootOptionOnWatchDog' = 0; 'BootROMSupported' = $false; 'BootupState' = ''; 'Caption' = ''; 'ChassisBootupState' = 0; 'ChassisSKUNumber' = ''; 'CreationClassName' = ''; 'CurrentTimeZone' = 0; 'DaylightInEffect' = $false; 'Description' = ''; 'DNSHostName' = ''; 'Domain' = ''; 'DomainRole' = 0; 'EnableDaylightSavingsTime' = $false; 'FrontPanelResetStatus' = 0; 'HypervisorPresent' = $false; 'InfraredSupported' = $false; 'InstallDate' = (Get-Date); 'KeyboardPasswordStatus' = 0; 'LastLoadInfo' = ''; 'Manufacturer' = ''; 'Model' = ''; 'Name' = ''; 'NameFormat' = ''; 'NetworkServerModeEnabled' = $false; 'NumberOfLogicalProcessors' = 0; 'NumberOfProcessors' = 0; 'PartOfDomain' = $false; 'PauseAfterReset' = 0; 'PCSystemType' = 0; 'PCSystemTypeEx' = 0; 'PowerManagementSupported' = $false; 'PowerOnPasswordStatus' = 0; 'PowerState' = 0; 'PowerSupplyState' = 0; 'PrimaryOwnerContact' = ''; 'PrimaryOwnerName' = ''; 'ResetCapability' = 0; 'ResetCount' = 0; 'ResetLimit' = 0; 'Status' = ''; 'SystemFamily' = ''; 'SystemSKUNumber' = ''; 'SystemStartupDelay' = 0; 'SystemStartupSetting' = 0; 'SystemType' = ''; 'ThermalState' = 0; 'TotalPhysicalMemory' = 0; 'UserName' = ''; 'WakeUpType' = 0; 'Workgroup' = ''; }
                            }
                        } catch {
                            $Global:ErrorCapture += $_
                            $returnInfo += New-Object -TypeName PSObject -Property @{'ReturnType' = 3; 'ConnectionType'='WMI (root\cimv2) Computer';'Error'=$_; 'ServerName' = $RemoteComputer; 'AdminPasswordStatus' = 0; 'AutomaticManagedPagefile' = $false; 'AutomaticResetBootOption' = $false; 'AutomaticResetCapability' = $false; 'BootOptionOnLimit' = 0; 'BootOptionOnWatchDog' = 0; 'BootROMSupported' = $false; 'BootupState' = ''; 'Caption' = ''; 'ChassisBootupState' = 0; 'ChassisSKUNumber' = ''; 'CreationClassName' = ''; 'CurrentTimeZone' = 0; 'DaylightInEffect' = $false; 'Description' = ''; 'DNSHostName' = ''; 'Domain' = ''; 'DomainRole' = 0; 'EnableDaylightSavingsTime' = $false; 'FrontPanelResetStatus' = 0; 'HypervisorPresent' = $false; 'InfraredSupported' = $false; 'InstallDate' = (Get-Date); 'KeyboardPasswordStatus' = 0; 'LastLoadInfo' = ''; 'Manufacturer' = ''; 'Model' = ''; 'Name' = ''; 'NameFormat' = ''; 'NetworkServerModeEnabled' = $false; 'NumberOfLogicalProcessors' = 0; 'NumberOfProcessors' = 0; 'PartOfDomain' = $false; 'PauseAfterReset' = 0; 'PCSystemType' = 0; 'PCSystemTypeEx' = 0; 'PowerManagementSupported' = $false; 'PowerOnPasswordStatus' = 0; 'PowerState' = 0; 'PowerSupplyState' = 0; 'PrimaryOwnerContact' = ''; 'PrimaryOwnerName' = ''; 'ResetCapability' = 0; 'ResetCount' = 0; 'ResetLimit' = 0; 'Status' = ''; 'SystemFamily' = ''; 'SystemSKUNumber' = ''; 'SystemStartupDelay' = 0; 'SystemStartupSetting' = 0; 'SystemType' = ''; 'ThermalState' = 0; 'TotalPhysicalMemory' = 0; 'UserName' = ''; 'WakeUpType' = 0; 'Workgroup' = ''; }
                        }
                        $returnInfo
                    }
                    Start-Job -ScriptBlock $Scriptblock -ArgumentList @($RemoteComputer) | out-null
                }
                While (@(Get-Job | where-object { $_.State -eq "Running" }).Count -ge 1) {  
                    Start-Sleep -Seconds 3
                }
                
                $returnInfo = ForEach ($Job in (Get-Job)) {
                    Receive-Job $Job
                    Remove-Job $Job
                }
                $ComputerInformationList += $returnInfo | where-object {$_.ReturnType -eq 1}

                $returnInfo | where-object {$_.ReturnType -eq 2} | ForEach-Object {
                    $Script:ServerDown += New-Object -TypeName PSObject -Property @{'ServerName' = $_.ServerName; 'ConnectionType' = $_.ConnectionType }
                }

                $returnInfo | where-object {$_.ReturnType -eq 3} | ForEach-Object {
                    Write-RFLLog -logtype "EXCEPTION" -logmessage "Server '$($_.ServerName)' generated Error. Error Message: '$($_.Error)'"
                    $Script:ServerDown += New-Object -TypeName PSObject -Property @{'ServerName' = $_.ServerName; 'ConnectionType' = $_.ConnectionType }
                }
                Export-RFLXMLFile -VariableName 'ComputerInformationList' -ClearVariable
            }
        }
        #endregion
        
        #region sub-Rules
        $arrRuleID = @(350)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            $FileToImport = "$($SaveToFolder)\FolderInformationList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "FolderInformationList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $FolderInformationList += (Get-WmiObject -computer $SMSProviderServer -Namespace "root\sms\site_$($MainSiteCode)" -Query "SELECT * FROM SMS_ObjectContainerNode")
                Export-RFLXMLFile -VariableName 'FolderInformationList' -ClearVariable
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(353)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\AdvertisementList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "AdvertisementList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $AdvertisementList += (Get-WmiObject -computer $SMSProviderServer -Namespace "root\sms\site_$($MainSiteCode)" -Query "SELECT * FROM SMS_Advertisement")
                Export-RFLXMLFile -VariableName 'AdvertisementList' -ClearVariable
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(354,355,356,357,358,359,360,361)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\BaselineList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "BaselineList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $BaselineList += Get-CMBaseline
                Export-RFLXMLFile -VariableName 'BaselineList' -ClearVariable
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(361)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\BaselineDeploymentList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "BaselineDeploymentList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $BaselineDeploymentList += Get-CMBaselineDeployment 
                Export-RFLXMLFile -VariableName 'BaselineDeploymentList' -ClearVariable
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(364,365,366,367,368,369,370,371,372,373,374,375,376,377,378)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\IISList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "IISList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $IISList += $SiteRoleListWOCDP | Where-Object {$_.RoleName -in $Script:IISRoles}
                Export-RFLXMLFile -VariableName 'IISList'
            }
        }
        #endregion         

        #region sub-Rules
        $arrRuleID = @(364,365)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\IISClientWebService.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "IISClientWebService" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $IISList | Select-Object NetworkOSPath | Get-Unique -AsString | ForEach-Object {
                    $item = $_ 
                    $RemoteComputer = ($item.NetworkOSPath.Replace('\\',''))
                    Write-RFLLog -logtype "Info" -logmessage "Getting Registry information ('IIS Client Web Service') for '$($RemoteComputer)'"
                    $code = {
                        Param (
                            $RemoteComputer
                        )
                        try {
                            if (Test-Path -LiteralPath "filesystem::\\$($RemoteComputer)\C$\Program Files\Update Services\WebServices\ClientWebService\web.config" -ErrorAction SilentlyContinue) {
                                [xml]$webConfigFile = Get-Content "filesystem::\\$($RemoteComputer)\C$\Program Files\Update Services\WebServices\ClientWebService\web.config"
                                New-Object -TypeName PSObject -Property @{'ReturnType' = 1; 'ConnectionType'='';'Error'=''; 'ServerName' = $RemoteComputer; 'ClientWebServiceExist' = $true; 'ExecutionTimeout' = [int]$webConfigFile.configuration.'system.web'.httpRuntime.executionTimeout; 'maxRequestLength' = [int]$webConfigFile.configuration.'system.web'.httpRuntime.maxRequestLength }
                            } else {
                                New-Object -TypeName PSObject -Property @{'ReturnType' = 2; 'ConnectionType'='Folder Access (WSUS) (SMB)';'Error'=''; 'ServerName' = $RemoteComputer; 'ClientWebServiceExist' = $false; 'ExecutionTimeout' = -1; 'maxRequestLength' = -1 }
                            }
                         } catch {
                            $Global:ErrorCapture += $_
                            New-Object -TypeName PSObject -Property @{'ReturnType' = 3; 'ConnectionType'='Folder Access (WSUS) (SMB)';'Error'=$_; 'ServerName' = $RemoteComputer; 'ClientWebServiceExist' = $false; 'ExecutionTimeout' = -1; 'maxRequestLength' = -1 }
                        }
                    }
                    $returninfo = Execute-RFLRunSpace -code $Code -ParameterList @($RemoteComputer)
                    $IISClientWebService += $returninfo | where-object {$_.ReturnType -in (1,2)}
                    $returninfo | where-object {$_.ReturnType -eq 3} | ForEach-Object {
                        Write-RFLLog -logtype "EXCEPTION" -logmessage "Server '$($_.ServerName)' generated Error. Error Message: '$($_.Error)'"
                        $Script:ServerDown += New-Object -TypeName PSObject -Property @{'ServerName' = $_.ServerName; 'ConnectionType' = $_.ConnectionType }
                    }
                }
                Export-RFLXMLFile -VariableName 'IISClientWebService' -ClearVariable
            }
        }
        #endregion
        
        #region sub-Rules
        $arrRuleID = @(366,367,368,369,370,371,372,373,374,375,376,377,378)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\IISWebServerSetting.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "IISWebServerSetting" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $IISList | Select-Object NetworkOSPath | Get-Unique -AsString | ForEach-Object {
                    $item = $_ 
                    $RemoteComputer = ($item.NetworkOSPath.Replace('\\',''))
                    While (@(Get-Job | where-object { $_.State -eq "Running" }).Count -ge $Script:MaxThreads) {  
                        Start-Sleep -Seconds 3
                    }
                    Write-RFLLog -logtype "Info" -logmessage "Getting Registry information (''IIS Web Server Settings') for '$($RemoteComputer)'"
                    $Scriptblock = {
                        Param (
                            $RemoteComputer
                        )
                        try {
                            $returnInfo = @()
                            $itemReturn = (Get-WmiObject -ComputerName $RemoteComputer -namespace "root\MicrosoftIISv2" -class "IIsWebServerSetting" -ErrorAction SilentlyContinue)
                            if ($null -ne $itemReturn) {
                                $itemreturn | foreach-object {
                                    $returnInfo += New-Object -TypeName PSObject -Property @{'ReturnType' = 1; 'ServerName' = $RemoteComputer; 'ConnectionType' = ''; 'Error' = ''; 'AccessExecute' = $_.AccessExecute; 'AccessFlags' = $_.AccessFlags; 'AccessNoRemoteExecute' = $_.AccessNoRemoteExecute; 'AccessNoRemoteRead' = $_.AccessNoRemoteRead; 'AccessNoRemoteScript' = $_.AccessNoRemoteScript; 'AccessNoRemoteWrite' = $_.AccessNoRemoteWrite; 'AccessRead' = $_.AccessRead; 'AccessScript' = $_.AccessScript; 'AccessSource' = $_.AccessSource; 'AccessSSL' = $_.AccessSSL; 'AccessSSL128' = $_.AccessSSL128; 'AccessSSLFlags' = $_.AccessSSLFlags; 'AccessSSLMapCert' = $_.AccessSSLMapCert; 'AccessSSLNegotiateCert' = $_.AccessSSLNegotiateCert; 'AccessSSLRequireCert' = $_.AccessSSLRequireCert; 'AccessWrite' = $_.AccessWrite; 'AllowKeepAlive' = $_.AllowKeepAlive; 'AllowPathInfoForScriptMappings' = $_.AllowPathInfoForScriptMappings; 'AnonymousPasswordSync' = $_.AnonymousPasswordSync; 'AnonymousUserName' = $_.AnonymousUserName; 'AnonymousUserPass' = $_.AnonymousUserPass; 'AppAllowClientDebug' = $_.AppAllowClientDebug; 'AppAllowDebugging' = $_.AppAllowDebugging; 'AppFriendlyName' = $_.AppFriendlyName; 'AppOopRecoverLimit' = $_.AppOopRecoverLimit; 'AppPoolId' = $_.AppPoolId; 'AppWamClsid' = $_.AppWamClsid; 'AspAllowOutOfProcComponents' = $_.AspAllowOutOfProcComponents; 'AspAllowSessionState' = $_.AspAllowSessionState; 'AspAppServiceFlags' = $_.AspAppServiceFlags; 'AspBufferingLimit' = $_.AspBufferingLimit; 'AspBufferingOn' = $_.AspBufferingOn; 'AspCalcLineNumber' = $_.AspCalcLineNumber; 'AspCodepage' = $_.AspCodepage; 'AspDiskTemplateCacheDirectory' = $_.AspDiskTemplateCacheDirectory; 'AspEnableApplicationRestart' = $_.AspEnableApplicationRestart; 'AspEnableAspHtmlFallback' = $_.AspEnableAspHtmlFallback; 'AspEnableChunkedEncoding' = $_.AspEnableChunkedEncoding; 'AspEnableParentPaths' = $_.AspEnableParentPaths; 'AspEnableSxs' = $_.AspEnableSxs; 'AspEnableTracker' = $_.AspEnableTracker; 'AspEnableTypelibCache' = $_.AspEnableTypelibCache; 'AspErrorsToNTLog' = $_.AspErrorsToNTLog; 'AspExceptionCatchEnable' = $_.AspExceptionCatchEnable; 'AspExecuteInMTA' = $_.AspExecuteInMTA; 'AspKeepSessionIDSecure' = $_.AspKeepSessionIDSecure; 'AspLCID' = $_.AspLCID; 'AspLogErrorRequests' = $_.AspLogErrorRequests; 'AspMaxDiskTemplateCacheFiles' = $_.AspMaxDiskTemplateCacheFiles; 'AspMaxRequestEntityAllowed' = $_.AspMaxRequestEntityAllowed; 'AspPartitionID' = $_.AspPartitionID; 'AspProcessorThreadMax' = $_.AspProcessorThreadMax; 'AspQueueConnectionTestTime' = $_.AspQueueConnectionTestTime; 'AspQueueTimeout' = $_.AspQueueTimeout; 'AspRequestQueueMax' = $_.AspRequestQueueMax; 'AspRunOnEndAnonymously' = $_.AspRunOnEndAnonymously; 'AspScriptEngineCacheMax' = $_.AspScriptEngineCacheMax; 'AspScriptErrorMessage' = $_.AspScriptErrorMessage; 'AspScriptErrorSentToBrowser' = $_.AspScriptErrorSentToBrowser; 'AspScriptFileCacheSize' = $_.AspScriptFileCacheSize; 'AspScriptLanguage' = $_.AspScriptLanguage; 'AspScriptTimeout' = $_.AspScriptTimeout; 'AspSessionMax' = $_.AspSessionMax; 'AspSessionTimeout' = $_.AspSessionTimeout; 'AspSxsName' = $_.AspSxsName; 'AspTrackThreadingModel' = $_.AspTrackThreadingModel; 'AspUsePartition' = $_.AspUsePartition; 'AuthAdvNotifyDisable' = $_.AuthAdvNotifyDisable; 'AuthAnonymous' = $_.AuthAnonymous; 'AuthBasic' = $_.AuthBasic; 'AuthChangeDisable' = $_.AuthChangeDisable; 'AuthChangeUnsecure' = $_.AuthChangeUnsecure; 'AuthFlags' = $_.AuthFlags; 'AuthMD5' = $_.AuthMD5; 'AuthNTLM' = $_.AuthNTLM; 'AuthPassport' = $_.AuthPassport; 'AuthPersistence' = $_.AuthPersistence; 'AuthPersistSingleRequest' = $_.AuthPersistSingleRequest; 'AzEnable' = $_.AzEnable; 'AzImpersonationLevel' = $_.AzImpersonationLevel; 'AzScopeName' = $_.AzScopeName; 'AzStoreName' = $_.AzStoreName; 'CacheControlCustom' = $_.CacheControlCustom; 'CacheControlMaxAge' = $_.CacheControlMaxAge; 'CacheControlNoCache' = $_.CacheControlNoCache; 'CacheISAPI' = $_.CacheISAPI; 'CertCheckMode' = $_.CertCheckMode; 'CGITimeout' = $_.CGITimeout; 'ClusterEnabled' = $_.ClusterEnabled; 'ConnectionTimeout' = $_.ConnectionTimeout; 'ContentIndexed' = $_.ContentIndexed; 'CPUResetInterval' = $_.CPUResetInterval; 'CreateCGIWithNewConsole' = $_.CreateCGIWithNewConsole; 'CreateProcessAsUser' = $_.CreateProcessAsUser; 'DefaultDoc' = $_.DefaultDoc; 'DefaultDocFooter' = $_.DefaultDocFooter; 'DefaultLogonDomain' = $_.DefaultLogonDomain; 'DirBrowseFlags' = $_.DirBrowseFlags; 'DirBrowseShowDate' = $_.DirBrowseShowDate; 'DirBrowseShowExtension' = $_.DirBrowseShowExtension; 'DirBrowseShowLongDate' = $_.DirBrowseShowLongDate; 'DirBrowseShowSize' = $_.DirBrowseShowSize; 'DirBrowseShowTime' = $_.DirBrowseShowTime; 'DisableSocketPooling' = $_.DisableSocketPooling; 'DoDynamicCompression' = $_.DoDynamicCompression; 'DontLog' = $_.DontLog; 'DoStaticCompression' = $_.DoStaticCompression; 'EnableDefaultDoc' = $_.EnableDefaultDoc; 'EnableDirBrowsing' = $_.EnableDirBrowsing; 'EnableDocFooter' = $_.EnableDocFooter; 'EnableReverseDns' = $_.EnableReverseDns; 'FrontPageWeb' = $_.FrontPageWeb; 'HttpExpires' = $_.HttpExpires; 'LogExtFileBytesRecv' = $_.LogExtFileBytesRecv; 'LogExtFileBytesSent' = $_.LogExtFileBytesSent; 'LogExtFileClientIp' = $_.LogExtFileClientIp; 'LogExtFileComputerName' = $_.LogExtFileComputerName; 'LogExtFileCookie' = $_.LogExtFileCookie; 'LogExtFileDate' = $_.LogExtFileDate; 'LogExtFileFlags' = $_.LogExtFileFlags; 'LogExtFileHost' = $_.LogExtFileHost; 'LogExtFileHttpStatus' = $_.LogExtFileHttpStatus; 'LogExtFileMethod' = $_.LogExtFileMethod; 'LogExtFileProtocolVersion' = $_.LogExtFileProtocolVersion; 'LogExtFileReferer' = $_.LogExtFileReferer; 'LogExtFileServerIp' = $_.LogExtFileServerIp; 'LogExtFileServerPort' = $_.LogExtFileServerPort; 'LogExtFileSiteName' = $_.LogExtFileSiteName; 'LogExtFileTime' = $_.LogExtFileTime; 'LogExtFileTimeTaken' = $_.LogExtFileTimeTaken; 'LogExtFileUriQuery' = $_.LogExtFileUriQuery; 'LogExtFileUriStem' = $_.LogExtFileUriStem; 'LogExtFileUserAgent' = $_.LogExtFileUserAgent; 'LogExtFileUserName' = $_.LogExtFileUserName; 'LogExtFileWin32Status' = $_.LogExtFileWin32Status; 'LogFileDirectory' = $_.LogFileDirectory; 'LogFileLocaltimeRollover' = $_.LogFileLocaltimeRollover; 'LogFilePeriod' = $_.LogFilePeriod; 'LogFileTruncateSize' = $_.LogFileTruncateSize; 'LogOdbcDataSource' = $_.LogOdbcDataSource; 'LogOdbcPassword' = $_.LogOdbcPassword; 'LogOdbcTableName' = $_.LogOdbcTableName; 'LogOdbcUserName' = $_.LogOdbcUserName; 'LogonMethod' = $_.LogonMethod; 'LogPluginClsid' = $_.LogPluginClsid; 'LogType' = $_.LogType; 'MaxBandwidth' = $_.MaxBandwidth; 'MaxBandwidthBlocked' = $_.MaxBandwidthBlocked; 'MaxConnections' = $_.MaxConnections; 'MaxEndpointConnections' = $_.MaxEndpointConnections; 'MaxRequestEntityAllowed' = $_.MaxRequestEntityAllowed; 'Name' = $_.Name; 'NotDeletable' = $_.NotDeletable; 'NTAuthenticationProviders' = $_.NTAuthenticationProviders; 'PasswordCacheTTL' = $_.PasswordCacheTTL; 'PasswordChangeFlags' = $_.PasswordChangeFlags; 'PasswordExpirePrenotifyDays' = $_.PasswordExpirePrenotifyDays; 'PoolIdcTimeout' = $_.PoolIdcTimeout; 'ProcessNTCRIfLoggedOn' = $_.ProcessNTCRIfLoggedOn; 'Realm' = $_.Realm; 'RedirectHeaders' = $_.RedirectHeaders; 'RevocationFreshnessTime' = $_.RevocationFreshnessTime; 'RevocationURLRetrievalTimeout' = $_.RevocationURLRetrievalTimeout; 'ServerAutoStart' = $_.ServerAutoStart; 'ServerCommand' = $_.ServerCommand; 'ServerComment' = $_.ServerComment; 'ServerListenBacklog' = $_.ServerListenBacklog; 'ServerListenTimeout' = $_.ServerListenTimeout; 'ServerSize' = $_.ServerSize; 'ShutdownTimeLimit' = $_.ShutdownTimeLimit; 'SSIExecDisable' = $_.SSIExecDisable; 'SSLStoreName' = $_.SSLStoreName; 'UploadReadAheadSize' = $_.UploadReadAheadSize; 'UseDigestSSP' = $_.UseDigestSSP; 'Win32Error' = $_.Win32Error;  }
                                }
                            } else {
                                $returnInfo += New-Object -TypeName PSObject -Property @{'ReturnType' = 2; 'ServerName' = $RemoteComputer; 'ConnectionType' = 'WMI (root\MicrosoftIISv2) IISWebServerSetting'; 'Error' = ''; 'AccessExecute' = $false; 'AccessFlags' = 0; 'AccessNoRemoteExecute' = $false; 'AccessNoRemoteRead' = $false; 'AccessNoRemoteScript' = $false; 'AccessNoRemoteWrite' = $false; 'AccessRead' = $false; 'AccessScript' = $false; 'AccessSource' = $false; 'AccessSSL' = $false; 'AccessSSL128' = $false; 'AccessSSLFlags' = 0; 'AccessSSLMapCert' = $false; 'AccessSSLNegotiateCert' = $false; 'AccessSSLRequireCert' = $false; 'AccessWrite' = $false; 'AllowKeepAlive' = $false; 'AllowPathInfoForScriptMappings' = $false; 'AnonymousPasswordSync' = $false; 'AnonymousUserName' = ''; 'AnonymousUserPass' = ''; 'AppAllowClientDebug' = $false; 'AppAllowDebugging' = $false; 'AppFriendlyName' = ''; 'AppOopRecoverLimit' = 0; 'AppPoolId' = ''; 'AppWamClsid' = ''; 'AspAllowOutOfProcComponents' = $false; 'AspAllowSessionState' = $false; 'AspAppServiceFlags' = 0; 'AspBufferingLimit' = 0; 'AspBufferingOn' = $false; 'AspCalcLineNumber' = $false; 'AspCodepage' = 0; 'AspDiskTemplateCacheDirectory' = ''; 'AspEnableApplicationRestart' = $false; 'AspEnableAspHtmlFallback' = $false; 'AspEnableChunkedEncoding' = $false; 'AspEnableParentPaths' = $false; 'AspEnableSxs' = $false; 'AspEnableTracker' = $false; 'AspEnableTypelibCache' = $false; 'AspErrorsToNTLog' = $false; 'AspExceptionCatchEnable' = $false; 'AspExecuteInMTA' = 0; 'AspKeepSessionIDSecure' = 0; 'AspLCID' = 0; 'AspLogErrorRequests' = $false; 'AspMaxDiskTemplateCacheFiles' = 0; 'AspMaxRequestEntityAllowed' = 0; 'AspPartitionID' = ''; 'AspProcessorThreadMax' = 0; 'AspQueueConnectionTestTime' = 0; 'AspQueueTimeout' = 0; 'AspRequestQueueMax' = 0; 'AspRunOnEndAnonymously' = $false; 'AspScriptEngineCacheMax' = 0; 'AspScriptErrorMessage' = ''; 'AspScriptErrorSentToBrowser' = $false; 'AspScriptFileCacheSize' = 0; 'AspScriptLanguage' = ''; 'AspScriptTimeout' = 0; 'AspSessionMax' = 0; 'AspSessionTimeout' = 0; 'AspSxsName' = ''; 'AspTrackThreadingModel' = $false; 'AspUsePartition' = $false; 'AuthAdvNotifyDisable' = $false; 'AuthAnonymous' = $false; 'AuthBasic' = $false; 'AuthChangeDisable' = $false; 'AuthChangeUnsecure' = $false; 'AuthFlags' = 0; 'AuthMD5' = $false; 'AuthNTLM' = $false; 'AuthPassport' = $false; 'AuthPersistence' = 0; 'AuthPersistSingleRequest' = $false; 'AzEnable' = $false; 'AzImpersonationLevel' = 0; 'AzScopeName' = ''; 'AzStoreName' = ''; 'CacheControlCustom' = ''; 'CacheControlMaxAge' = 0; 'CacheControlNoCache' = $false; 'CacheISAPI' = $false; 'CertCheckMode' = 0; 'CGITimeout' = 0; 'ClusterEnabled' = $false; 'ConnectionTimeout' = 0; 'ContentIndexed' = $false; 'CPUResetInterval' = 0; 'CreateCGIWithNewConsole' = $false; 'CreateProcessAsUser' = $false; 'DefaultDoc' = ''; 'DefaultDocFooter' = ''; 'DefaultLogonDomain' = ''; 'DirBrowseFlags' = 0; 'DirBrowseShowDate' = $false; 'DirBrowseShowExtension' = $false; 'DirBrowseShowLongDate' = $false; 'DirBrowseShowSize' = $false; 'DirBrowseShowTime' = $false; 'DisableSocketPooling' = $false; 'DoDynamicCompression' = $false; 'DontLog' = $false; 'DoStaticCompression' = $false; 'EnableDefaultDoc' = $false; 'EnableDirBrowsing' = $false; 'EnableDocFooter' = $false; 'EnableReverseDns' = $false; 'FrontPageWeb' = $false; 'HttpExpires' = ''; 'LogExtFileBytesRecv' = $false; 'LogExtFileBytesSent' = $false; 'LogExtFileClientIp' = $false; 'LogExtFileComputerName' = $false; 'LogExtFileCookie' = $false; 'LogExtFileDate' = $false; 'LogExtFileFlags' = 0; 'LogExtFileHost' = $false; 'LogExtFileHttpStatus' = $false; 'LogExtFileMethod' = $false; 'LogExtFileProtocolVersion' = $false; 'LogExtFileReferer' = $false; 'LogExtFileServerIp' = $false; 'LogExtFileServerPort' = $false; 'LogExtFileSiteName' = $false; 'LogExtFileTime' = $false; 'LogExtFileTimeTaken' = $false; 'LogExtFileUriQuery' = $false; 'LogExtFileUriStem' = $false; 'LogExtFileUserAgent' = $false; 'LogExtFileUserName' = $false; 'LogExtFileWin32Status' = $false; 'LogFileDirectory' = ''; 'LogFileLocaltimeRollover' = $false; 'LogFilePeriod' = 0; 'LogFileTruncateSize' = 0; 'LogOdbcDataSource' = ''; 'LogOdbcPassword' = ''; 'LogOdbcTableName' = ''; 'LogOdbcUserName' = ''; 'LogonMethod' = 0; 'LogPluginClsid' = ''; 'LogType' = 0; 'MaxBandwidth' = 0; 'MaxBandwidthBlocked' = 0; 'MaxConnections' = 0; 'MaxEndpointConnections' = 0; 'MaxRequestEntityAllowed' = 0; 'Name' = ''; 'NotDeletable' = $false; 'NTAuthenticationProviders' = ''; 'PasswordCacheTTL' = 0; 'PasswordChangeFlags' = 0; 'PasswordExpirePrenotifyDays' = 0; 'PoolIdcTimeout' = 0; 'ProcessNTCRIfLoggedOn' = $false; 'Realm' = ''; 'RedirectHeaders' = ''; 'RevocationFreshnessTime' = 0; 'RevocationURLRetrievalTimeout' = 0; 'ServerAutoStart' = $false; 'ServerCommand' = 0; 'ServerComment' = ''; 'ServerListenBacklog' = 0; 'ServerListenTimeout' = 0; 'ServerSize' = 0; 'ShutdownTimeLimit' = 0; 'SSIExecDisable' = $false; 'SSLStoreName' = ''; 'UploadReadAheadSize' = 0; 'UseDigestSSP' = $false; 'Win32Error' = 0;  }
                            }
                        } catch {
                            $Global:ErrorCapture += $_
                            $returnInfo += New-Object -TypeName PSObject -Property @{'ReturnType' = 3; 'ServerName' = $RemoteComputer; 'ConnectionType' = 'WMI (root\MicrosoftIISv2) IISWebServerSetting'; 'Error' = $_; 'AccessExecute' = $false; 'AccessFlags' = 0; 'AccessNoRemoteExecute' = $false; 'AccessNoRemoteRead' = $false; 'AccessNoRemoteScript' = $false; 'AccessNoRemoteWrite' = $false; 'AccessRead' = $false; 'AccessScript' = $false; 'AccessSource' = $false; 'AccessSSL' = $false; 'AccessSSL128' = $false; 'AccessSSLFlags' = 0; 'AccessSSLMapCert' = $false; 'AccessSSLNegotiateCert' = $false; 'AccessSSLRequireCert' = $false; 'AccessWrite' = $false; 'AllowKeepAlive' = $false; 'AllowPathInfoForScriptMappings' = $false; 'AnonymousPasswordSync' = $false; 'AnonymousUserName' = ''; 'AnonymousUserPass' = ''; 'AppAllowClientDebug' = $false; 'AppAllowDebugging' = $false; 'AppFriendlyName' = ''; 'AppOopRecoverLimit' = 0; 'AppPoolId' = ''; 'AppWamClsid' = ''; 'AspAllowOutOfProcComponents' = $false; 'AspAllowSessionState' = $false; 'AspAppServiceFlags' = 0; 'AspBufferingLimit' = 0; 'AspBufferingOn' = $false; 'AspCalcLineNumber' = $false; 'AspCodepage' = 0; 'AspDiskTemplateCacheDirectory' = ''; 'AspEnableApplicationRestart' = $false; 'AspEnableAspHtmlFallback' = $false; 'AspEnableChunkedEncoding' = $false; 'AspEnableParentPaths' = $false; 'AspEnableSxs' = $false; 'AspEnableTracker' = $false; 'AspEnableTypelibCache' = $false; 'AspErrorsToNTLog' = $false; 'AspExceptionCatchEnable' = $false; 'AspExecuteInMTA' = 0; 'AspKeepSessionIDSecure' = 0; 'AspLCID' = 0; 'AspLogErrorRequests' = $false; 'AspMaxDiskTemplateCacheFiles' = 0; 'AspMaxRequestEntityAllowed' = 0; 'AspPartitionID' = ''; 'AspProcessorThreadMax' = 0; 'AspQueueConnectionTestTime' = 0; 'AspQueueTimeout' = 0; 'AspRequestQueueMax' = 0; 'AspRunOnEndAnonymously' = $false; 'AspScriptEngineCacheMax' = 0; 'AspScriptErrorMessage' = ''; 'AspScriptErrorSentToBrowser' = $false; 'AspScriptFileCacheSize' = 0; 'AspScriptLanguage' = ''; 'AspScriptTimeout' = 0; 'AspSessionMax' = 0; 'AspSessionTimeout' = 0; 'AspSxsName' = ''; 'AspTrackThreadingModel' = $false; 'AspUsePartition' = $false; 'AuthAdvNotifyDisable' = $false; 'AuthAnonymous' = $false; 'AuthBasic' = $false; 'AuthChangeDisable' = $false; 'AuthChangeUnsecure' = $false; 'AuthFlags' = 0; 'AuthMD5' = $false; 'AuthNTLM' = $false; 'AuthPassport' = $false; 'AuthPersistence' = 0; 'AuthPersistSingleRequest' = $false; 'AzEnable' = $false; 'AzImpersonationLevel' = 0; 'AzScopeName' = ''; 'AzStoreName' = ''; 'CacheControlCustom' = ''; 'CacheControlMaxAge' = 0; 'CacheControlNoCache' = $false; 'CacheISAPI' = $false; 'CertCheckMode' = 0; 'CGITimeout' = 0; 'ClusterEnabled' = $false; 'ConnectionTimeout' = 0; 'ContentIndexed' = $false; 'CPUResetInterval' = 0; 'CreateCGIWithNewConsole' = $false; 'CreateProcessAsUser' = $false; 'DefaultDoc' = ''; 'DefaultDocFooter' = ''; 'DefaultLogonDomain' = ''; 'DirBrowseFlags' = 0; 'DirBrowseShowDate' = $false; 'DirBrowseShowExtension' = $false; 'DirBrowseShowLongDate' = $false; 'DirBrowseShowSize' = $false; 'DirBrowseShowTime' = $false; 'DisableSocketPooling' = $false; 'DoDynamicCompression' = $false; 'DontLog' = $false; 'DoStaticCompression' = $false; 'EnableDefaultDoc' = $false; 'EnableDirBrowsing' = $false; 'EnableDocFooter' = $false; 'EnableReverseDns' = $false; 'FrontPageWeb' = $false; 'HttpExpires' = ''; 'LogExtFileBytesRecv' = $false; 'LogExtFileBytesSent' = $false; 'LogExtFileClientIp' = $false; 'LogExtFileComputerName' = $false; 'LogExtFileCookie' = $false; 'LogExtFileDate' = $false; 'LogExtFileFlags' = 0; 'LogExtFileHost' = $false; 'LogExtFileHttpStatus' = $false; 'LogExtFileMethod' = $false; 'LogExtFileProtocolVersion' = $false; 'LogExtFileReferer' = $false; 'LogExtFileServerIp' = $false; 'LogExtFileServerPort' = $false; 'LogExtFileSiteName' = $false; 'LogExtFileTime' = $false; 'LogExtFileTimeTaken' = $false; 'LogExtFileUriQuery' = $false; 'LogExtFileUriStem' = $false; 'LogExtFileUserAgent' = $false; 'LogExtFileUserName' = $false; 'LogExtFileWin32Status' = $false; 'LogFileDirectory' = ''; 'LogFileLocaltimeRollover' = $false; 'LogFilePeriod' = 0; 'LogFileTruncateSize' = 0; 'LogOdbcDataSource' = ''; 'LogOdbcPassword' = ''; 'LogOdbcTableName' = ''; 'LogOdbcUserName' = ''; 'LogonMethod' = 0; 'LogPluginClsid' = ''; 'LogType' = 0; 'MaxBandwidth' = 0; 'MaxBandwidthBlocked' = 0; 'MaxConnections' = 0; 'MaxEndpointConnections' = 0; 'MaxRequestEntityAllowed' = 0; 'Name' = ''; 'NotDeletable' = $false; 'NTAuthenticationProviders' = ''; 'PasswordCacheTTL' = 0; 'PasswordChangeFlags' = 0; 'PasswordExpirePrenotifyDays' = 0; 'PoolIdcTimeout' = 0; 'ProcessNTCRIfLoggedOn' = $false; 'Realm' = ''; 'RedirectHeaders' = ''; 'RevocationFreshnessTime' = 0; 'RevocationURLRetrievalTimeout' = 0; 'ServerAutoStart' = $false; 'ServerCommand' = 0; 'ServerComment' = ''; 'ServerListenBacklog' = 0; 'ServerListenTimeout' = 0; 'ServerSize' = 0; 'ShutdownTimeLimit' = 0; 'SSIExecDisable' = $false; 'SSLStoreName' = ''; 'UploadReadAheadSize' = 0; 'UseDigestSSP' = $false; 'Win32Error' = 0;  }
                        }
                        $returnInfo
                    }                        
                    Start-Job -ScriptBlock $Scriptblock -ArgumentList @($RemoteComputer) | out-null
                }
                While (@(Get-Job | where-object { $_.State -eq "Running" }).Count -ge 1) {  
                    Start-Sleep -Seconds 3
                }
                
                $returnInfo = ForEach ($Job in (Get-Job)) {
                    Receive-Job $Job
                    Remove-Job $Job
                }

                $IISWebServerSetting += $returninfo | where-object {$_.ReturnType -in (1)}
                $returninfo | where-object {$_.ReturnType -eq 2} | ForEach-Object {
                    $Script:ServerDown += New-Object -TypeName PSObject -Property @{'ServerName' = $_.ServerName; 'ConnectionType' = $_.ConnectionType }
                }
                $returninfo | where-object {$_.ReturnType -eq 3} | ForEach-Object {
                    Write-RFLLog -logtype "EXCEPTION" -logmessage "Server '$($_.ServerName)' generated Error. Error Message: '$($_.Error)'"
                    $Script:ServerDown += New-Object -TypeName PSObject -Property @{'ServerName' = $_.ServerName; 'ConnectionType' = $_.ConnectionType }
                }
                Export-RFLXMLFile -VariableName 'IISWebServerSetting'
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(366,367,368)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\IISLogs.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "IISLogs" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {                
                $IISWebServerSetting | Where-Object {($_.LogType -eq 1) -and ($null -ne $_.LogFileDirectory)} | ForEach-Object {
                    $item = $_ 
                    $RemoteComputer = $item.ServerName

                    if ($item.LogFileDirectory.ToString()[0] -eq '\') {
                        $LogFolder = "{0}\{1}" -f $item.LogFileDirectory, $item.Name.Replace('/','')
                        $LogRemoteFolder = $LogFolder
                    } else {
                        $LogFolder = "{0}\{1}" -f $item.LogFileDirectory, $item.Name.Replace('/','')
                        $LogRemoteFolder = "\\$($RemoteComputer)\$($LogFolder.Replace(':\', '$\'))" 
                    }
                    While (@(Get-Job | where-object { $_.State -eq "Running" }).Count -ge $Script:MaxThreads) {  
                        Start-Sleep -Seconds 3
                    }
                    Write-RFLLog -logtype "Info" -logmessage "Getting WSUS Log Files '$($item.Name)' Information for Site '$($RemoteComputer)'"
                    $Scriptblock = {
                        Param (
                            $LogRemoteFolder,
                            $RemoteComputer,
                            $SiteID,
                            $SiteName,
                            $LogFolder
                        )
                        try {
                            $returnInfo = @()
                            if (Test-Path -LiteralPath "filesystem::$($LogRemoteFolder)") {
                                Get-ChildItem "filesystem::$($LogRemoteFolder)" | Where-Object {!$_.PSIsContainer} | ForEach-Object {
                                    $subitem = $_
                                    $returnInfo += New-Object -TypeName PSObject -Property @{'ReturnType' = 1; 'ServerName' = $RemoteComputer; 'ConnectionType' = ''; 'Error' = ''; 'LogFolder' = $subitem.FullName.ToString().Replace($LogRemoteFolder, $LogFolder).Replace("\\$($RemoteComputer)\", '').Replace("\$($subitem.Name)", ''); 'IIS Site ID' = $SiteID; 'IIS Site Name' = $SiteName; 'LogFile' = $subitem.Name; 'LogFileCompletePath' = $subitem.FullName; 'LogSize' = $subitem.Length; 'LogCreationTime' = $subitem.CreationTime }
                                }
                            } else {
                                $returnInfo += New-Object -TypeName PSObject -Property @{'ReturnType' = 2; 'ServerName' = $RemoteComputer; 'ConnectionType' = 'Folder Access (IIS logs) (SMB)'; 'Error' = ''; 'LogFolder' = $LogRemoteFolder; 'IIS Site ID' = ''; 'IIS Site Name' = ''; 'LogFile' = ''; 'LogFileCompletePath' = ''; 'LogSize' = ''; 'LogCreationTime' = ''; }
                            }
                        } catch {
                            $Global:ErrorCapture += $_
                            $returnInfo += New-Object -TypeName PSObject -Property @{'ReturnType' = 3; 'ServerName' = $RemoteComputer; 'ConnectionType' = 'Folder Access (IIS logs) (SMB)'; 'Error' = $_; 'LogFolder' = $LogRemoteFolder; 'IIS Site ID' = ''; 'IIS Site Name' = ''; 'LogFile' = ''; 'LogFileCompletePath' = ''; 'LogSize' = ''; 'LogCreationTime' = ''; }
                        }
                        $returnInfo
                    }                        
                    Start-Job -ScriptBlock $Scriptblock -ArgumentList @($LogRemoteFolder, $RemoteComputer, $item.Name, $item.ServerComment, $LogFolder) | out-null
                }

                While (@(Get-Job | where-object { $_.State -eq "Running" }).Count -ge 1) {  
                    Start-Sleep -Seconds 3
                }
                
                $returnInfo = ForEach ($Job in (Get-Job)) {
                    Receive-Job $Job
                    Remove-Job $Job
                }

                $IISLogs += $returninfo | where-object {$_.ReturnType -in (1)}
                $returninfo | where-object {$_.ReturnType -eq 2} | ForEach-Object {
                    Write-RFLLog -logtype "ERROR" -logmessage "Folder '$($_.LogFolder)' does not exist"
                    $Script:ServerDown += New-Object -TypeName PSObject -Property @{'ServerName' = ($_.ServerName); 'ConnectionType' = $_.ConnectionType }
                }
                $returninfo | where-object {$_.ReturnType -eq 3} | ForEach-Object {
                    Write-RFLLog -logtype "EXCEPTION" -logmessage "Server '$($_.ServerName)' generated Error. Error Message: '$($_.Error)'"                    
                    $Script:ServerDown += New-Object -TypeName PSObject -Property @{'ServerName' = $_.ServerName; 'ConnectionType' = $_.ConnectionType }
                }
                Export-RFLXMLFile -VariableName 'IISLogs' -ClearVariable
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(372,373,374,375,376,377,378)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\IisWebVirtualDirSetting.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "IisWebVirtualDirSetting" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $IISList | Select-Object NetworkOSPath | Get-Unique -AsString | ForEach-Object {
                    $item = $_ 
                    $RemoteComputer = ($item.NetworkOSPath.Replace('\\',''))
                    While (@(Get-Job | where-object { $_.State -eq "Running" }).Count -ge $Script:MaxThreads) {  
                        Start-Sleep -Seconds 3
                    }
                    Write-RFLLog -logtype "Info" -logmessage "Getting Registry information ('IIS Virtual Directory') for '$($RemoteComputer)'"
                    $Scriptblock = {
                        Param (
                            $RemoteComputer
                        )
                        try {
                            $returnInfo = @()
                            $itemReturn = (Get-WmiObject -ComputerName $RemoteComputer -namespace "root\MicrosoftIISv2" -class "IisWebVirtualDirSetting" -ErrorAction SilentlyContinue)
                            if ($null -ne $itemReturn) {
                                $itemreturn | foreach-object {
                                    $returnInfo += New-Object -TypeName PSObject -Property @{'ReturnType' = 1; 'ServerName' = $RemoteComputer; 'ConnectionType' = ''; 'Error' = ''; 'AccessExecute' = $_.AccessExecute; 'AccessFlags' = $_.AccessFlags; 'AccessNoRemoteExecute' = $_.AccessNoRemoteExecute; 'AccessNoRemoteRead' = $_.AccessNoRemoteRead; 'AccessNoRemoteScript' = $_.AccessNoRemoteScript; 'AccessNoRemoteWrite' = $_.AccessNoRemoteWrite; 'AccessRead' = $_.AccessRead; 'AccessScript' = $_.AccessScript; 'AccessSource' = $_.AccessSource; 'AccessSSL' = $_.AccessSSL; 'AccessSSL128' = $_.AccessSSL128; 'AccessSSLFlags' = $_.AccessSSLFlags; 'AccessSSLMapCert' = $_.AccessSSLMapCert; 'AccessSSLNegotiateCert' = $_.AccessSSLNegotiateCert; 'AccessSSLRequireCert' = $_.AccessSSLRequireCert; 'AccessWrite' = $_.AccessWrite; 'AnonymousPasswordSync' = $_.AnonymousPasswordSync; 'AnonymousUserName' = $_.AnonymousUserName; 'AnonymousUserPass' = $_.AnonymousUserPass; 'AppAllowClientDebug' = $_.AppAllowClientDebug; 'AppAllowDebugging' = $_.AppAllowDebugging; 'AppFriendlyName' = $_.AppFriendlyName; 'AppOopRecoverLimit' = $_.AppOopRecoverLimit; 'AppPoolId' = $_.AppPoolId; 'AppWamClsid' = $_.AppWamClsid; 'AspAllowOutOfProcComponents' = $_.AspAllowOutOfProcComponents; 'AspAllowSessionState' = $_.AspAllowSessionState; 'AspAppServiceFlags' = $_.AspAppServiceFlags; 'AspBufferingLimit' = $_.AspBufferingLimit; 'AspBufferingOn' = $_.AspBufferingOn; 'AspCalcLineNumber' = $_.AspCalcLineNumber; 'AspCodepage' = $_.AspCodepage; 'AspDiskTemplateCacheDirectory' = $_.AspDiskTemplateCacheDirectory; 'AspEnableApplicationRestart' = $_.AspEnableApplicationRestart; 'AspEnableAspHtmlFallback' = $_.AspEnableAspHtmlFallback; 'AspEnableChunkedEncoding' = $_.AspEnableChunkedEncoding; 'AspEnableParentPaths' = $_.AspEnableParentPaths; 'AspEnableSxs' = $_.AspEnableSxs; 'AspEnableTracker' = $_.AspEnableTracker; 'AspEnableTypelibCache' = $_.AspEnableTypelibCache; 'AspErrorsToNTLog' = $_.AspErrorsToNTLog; 'AspExceptionCatchEnable' = $_.AspExceptionCatchEnable; 'AspExecuteInMTA' = $_.AspExecuteInMTA; 'AspKeepSessionIDSecure' = $_.AspKeepSessionIDSecure; 'AspLCID' = $_.AspLCID; 'AspLogErrorRequests' = $_.AspLogErrorRequests; 'AspMaxDiskTemplateCacheFiles' = $_.AspMaxDiskTemplateCacheFiles; 'AspMaxRequestEntityAllowed' = $_.AspMaxRequestEntityAllowed; 'AspPartitionID' = $_.AspPartitionID; 'AspProcessorThreadMax' = $_.AspProcessorThreadMax; 'AspQueueConnectionTestTime' = $_.AspQueueConnectionTestTime; 'AspQueueTimeout' = $_.AspQueueTimeout; 'AspRequestQueueMax' = $_.AspRequestQueueMax; 'AspRunOnEndAnonymously' = $_.AspRunOnEndAnonymously; 'AspScriptEngineCacheMax' = $_.AspScriptEngineCacheMax; 'AspScriptErrorMessage' = $_.AspScriptErrorMessage; 'AspScriptErrorSentToBrowser' = $_.AspScriptErrorSentToBrowser; 'AspScriptFileCacheSize' = $_.AspScriptFileCacheSize; 'AspScriptLanguage' = $_.AspScriptLanguage; 'AspScriptTimeout' = $_.AspScriptTimeout; 'AspSessionMax' = $_.AspSessionMax; 'AspSessionTimeout' = $_.AspSessionTimeout; 'AspSxsName' = $_.AspSxsName; 'AspTrackThreadingModel' = $_.AspTrackThreadingModel; 'AspUsePartition' = $_.AspUsePartition; 'AuthAnonymous' = $_.AuthAnonymous; 'AuthBasic' = $_.AuthBasic; 'AuthFlags' = $_.AuthFlags; 'AuthMD5' = $_.AuthMD5; 'AuthNTLM' = $_.AuthNTLM; 'AuthPassport' = $_.AuthPassport; 'AuthPersistence' = $_.AuthPersistence; 'AuthPersistSingleRequest' = $_.AuthPersistSingleRequest; 'AzEnable' = $_.AzEnable; 'AzImpersonationLevel' = $_.AzImpersonationLevel; 'AzScopeName' = $_.AzScopeName; 'AzStoreName' = $_.AzStoreName; 'CacheControlCustom' = $_.CacheControlCustom; 'CacheControlMaxAge' = $_.CacheControlMaxAge; 'CacheControlNoCache' = $_.CacheControlNoCache; 'CacheISAPI' = $_.CacheISAPI; 'CGITimeout' = $_.CGITimeout; 'ContentIndexed' = $_.ContentIndexed; 'CreateCGIWithNewConsole' = $_.CreateCGIWithNewConsole; 'CreateProcessAsUser' = $_.CreateProcessAsUser; 'DefaultDoc' = $_.DefaultDoc; 'DefaultDocFooter' = $_.DefaultDocFooter; 'DefaultLogonDomain' = $_.DefaultLogonDomain; 'DirBrowseFlags' = $_.DirBrowseFlags; 'DirBrowseShowDate' = $_.DirBrowseShowDate; 'DirBrowseShowExtension' = $_.DirBrowseShowExtension; 'DirBrowseShowLongDate' = $_.DirBrowseShowLongDate; 'DirBrowseShowSize' = $_.DirBrowseShowSize; 'DirBrowseShowTime' = $_.DirBrowseShowTime; 'DoDynamicCompression' = $_.DoDynamicCompression; 'DontLog' = $_.DontLog; 'DoStaticCompression' = $_.DoStaticCompression; 'EnableDefaultDoc' = $_.EnableDefaultDoc; 'EnableDirBrowsing' = $_.EnableDirBrowsing; 'EnableDocFooter' = $_.EnableDocFooter; 'EnableReverseDns' = $_.EnableReverseDns; 'FrontPageWeb' = $_.FrontPageWeb; 'HttpExpires' = $_.HttpExpires; 'HttpRedirect' = $_.HttpRedirect; 'LogonMethod' = $_.LogonMethod; 'MaxRequestEntityAllowed' = $_.MaxRequestEntityAllowed; 'Name' = $_.Name; 'PoolIdcTimeout' = $_.PoolIdcTimeout; 'Realm' = $_.Realm; 'RedirectHeaders' = $_.RedirectHeaders; 'ShutdownTimeLimit' = $_.ShutdownTimeLimit; 'SSIExecDisable' = $_.SSIExecDisable; 'UploadReadAheadSize' = $_.UploadReadAheadSize; 'UseDigestSSP' = $_.UseDigestSSP; }
                                }
                            } else {
                                $returnInfo += New-Object -TypeName PSObject -Property @{'ReturnType' = 2; 'ServerName' = $RemoteComputer; 'ConnectionType' = 'WMI (root\MicrosoftIISv2) IisWebVirtualDirSetting'; 'Error' = ''; 'AccessExecute' = $false; 'AccessFlags' = 0; 'AccessNoRemoteExecute' = $false; 'AccessNoRemoteRead' = $false; 'AccessNoRemoteScript' = $false; 'AccessNoRemoteWrite' = $false; 'AccessRead' = $false; 'AccessScript' = $false; 'AccessSource' = $false; 'AccessSSL' = $false; 'AccessSSL128' = $false; 'AccessSSLFlags' = 0; 'AccessSSLMapCert' = $false; 'AccessSSLNegotiateCert' = $false; 'AccessSSLRequireCert' = $false; 'AccessWrite' = $false; 'AnonymousPasswordSync' = $false; 'AnonymousUserName' = ''; 'AnonymousUserPass' = ''; 'AppAllowClientDebug' = $false; 'AppAllowDebugging' = $false; 'AppFriendlyName' = ''; 'AppOopRecoverLimit' = 0; 'AppPoolId' = ''; 'AppWamClsid' = ''; 'AspAllowOutOfProcComponents' = $false; 'AspAllowSessionState' = $false; 'AspAppServiceFlags' = 0; 'AspBufferingLimit' = 0; 'AspBufferingOn' = $false; 'AspCalcLineNumber' = $false; 'AspCodepage' = 0; 'AspDiskTemplateCacheDirectory' = ''; 'AspEnableApplicationRestart' = $false; 'AspEnableAspHtmlFallback' = $false; 'AspEnableChunkedEncoding' = $false; 'AspEnableParentPaths' = $false; 'AspEnableSxs' = $false; 'AspEnableTracker' = $false; 'AspEnableTypelibCache' = $false; 'AspErrorsToNTLog' = $false; 'AspExceptionCatchEnable' = $false; 'AspExecuteInMTA' = 0; 'AspKeepSessionIDSecure' = 0; 'AspLCID' = 0; 'AspLogErrorRequests' = $false; 'AspMaxDiskTemplateCacheFiles' = 0; 'AspMaxRequestEntityAllowed' = 0; 'AspPartitionID' = ''; 'AspProcessorThreadMax' = 0; 'AspQueueConnectionTestTime' = 0; 'AspQueueTimeout' = 0; 'AspRequestQueueMax' = 0; 'AspRunOnEndAnonymously' = $false; 'AspScriptEngineCacheMax' = 0; 'AspScriptErrorMessage' = ''; 'AspScriptErrorSentToBrowser' = $false; 'AspScriptFileCacheSize' = 0; 'AspScriptLanguage' = ''; 'AspScriptTimeout' = 0; 'AspSessionMax' = 0; 'AspSessionTimeout' = 0; 'AspSxsName' = ''; 'AspTrackThreadingModel' = $false; 'AspUsePartition' = $false; 'AuthAnonymous' = $false; 'AuthBasic' = $false; 'AuthFlags' = 0; 'AuthMD5' = $false; 'AuthNTLM' = $false; 'AuthPassport' = $false; 'AuthPersistence' = 0; 'AuthPersistSingleRequest' = $false; 'AzEnable' = $false; 'AzImpersonationLevel' = 0; 'AzScopeName' = ''; 'AzStoreName' = ''; 'CacheControlCustom' = ''; 'CacheControlMaxAge' = 0; 'CacheControlNoCache' = $false; 'CacheISAPI' = $false; 'CGITimeout' = 0; 'ContentIndexed' = $false; 'CreateCGIWithNewConsole' = $false; 'CreateProcessAsUser' = $false; 'DefaultDoc' = ''; 'DefaultDocFooter' = ''; 'DefaultLogonDomain' = ''; 'DirBrowseFlags' = 0; 'DirBrowseShowDate' = $false; 'DirBrowseShowExtension' = $false; 'DirBrowseShowLongDate' = $false; 'DirBrowseShowSize' = $false; 'DirBrowseShowTime' = $false; 'DoDynamicCompression' = $false; 'DontLog' = $false; 'DoStaticCompression' = $false; 'EnableDefaultDoc' = $false; 'EnableDirBrowsing' = $false; 'EnableDocFooter' = $false; 'EnableReverseDns' = $false; 'FrontPageWeb' = $false; 'HttpExpires' = ''; 'HttpRedirect' = ''; 'LogonMethod' = 0; 'MaxRequestEntityAllowed' = 0; 'Name' = ''; 'PoolIdcTimeout' = 0; 'Realm' = ''; 'RedirectHeaders' = ''; 'ShutdownTimeLimit' = 0; 'SSIExecDisable' = $false; 'UploadReadAheadSize' = 0; 'UseDigestSSP' = $false; }
                            }
                        } catch {
                            $Global:ErrorCapture += $_
                            $returnInfo += New-Object -TypeName PSObject -Property @{'ReturnType' = 2; 'ServerName' = $RemoteComputer; 'ConnectionType' = 'WMI (root\MicrosoftIISv2) IisWebVirtualDirSetting'; 'Error' = $_; 'AccessExecute' = $false; 'AccessFlags' = 0; 'AccessNoRemoteExecute' = $false; 'AccessNoRemoteRead' = $false; 'AccessNoRemoteScript' = $false; 'AccessNoRemoteWrite' = $false; 'AccessRead' = $false; 'AccessScript' = $false; 'AccessSource' = $false; 'AccessSSL' = $false; 'AccessSSL128' = $false; 'AccessSSLFlags' = 0; 'AccessSSLMapCert' = $false; 'AccessSSLNegotiateCert' = $false; 'AccessSSLRequireCert' = $false; 'AccessWrite' = $false; 'AnonymousPasswordSync' = $false; 'AnonymousUserName' = ''; 'AnonymousUserPass' = ''; 'AppAllowClientDebug' = $false; 'AppAllowDebugging' = $false; 'AppFriendlyName' = ''; 'AppOopRecoverLimit' = 0; 'AppPoolId' = ''; 'AppWamClsid' = ''; 'AspAllowOutOfProcComponents' = $false; 'AspAllowSessionState' = $false; 'AspAppServiceFlags' = 0; 'AspBufferingLimit' = 0; 'AspBufferingOn' = $false; 'AspCalcLineNumber' = $false; 'AspCodepage' = 0; 'AspDiskTemplateCacheDirectory' = ''; 'AspEnableApplicationRestart' = $false; 'AspEnableAspHtmlFallback' = $false; 'AspEnableChunkedEncoding' = $false; 'AspEnableParentPaths' = $false; 'AspEnableSxs' = $false; 'AspEnableTracker' = $false; 'AspEnableTypelibCache' = $false; 'AspErrorsToNTLog' = $false; 'AspExceptionCatchEnable' = $false; 'AspExecuteInMTA' = 0; 'AspKeepSessionIDSecure' = 0; 'AspLCID' = 0; 'AspLogErrorRequests' = $false; 'AspMaxDiskTemplateCacheFiles' = 0; 'AspMaxRequestEntityAllowed' = 0; 'AspPartitionID' = ''; 'AspProcessorThreadMax' = 0; 'AspQueueConnectionTestTime' = 0; 'AspQueueTimeout' = 0; 'AspRequestQueueMax' = 0; 'AspRunOnEndAnonymously' = $false; 'AspScriptEngineCacheMax' = 0; 'AspScriptErrorMessage' = ''; 'AspScriptErrorSentToBrowser' = $false; 'AspScriptFileCacheSize' = 0; 'AspScriptLanguage' = ''; 'AspScriptTimeout' = 0; 'AspSessionMax' = 0; 'AspSessionTimeout' = 0; 'AspSxsName' = ''; 'AspTrackThreadingModel' = $false; 'AspUsePartition' = $false; 'AuthAnonymous' = $false; 'AuthBasic' = $false; 'AuthFlags' = 0; 'AuthMD5' = $false; 'AuthNTLM' = $false; 'AuthPassport' = $false; 'AuthPersistence' = 0; 'AuthPersistSingleRequest' = $false; 'AzEnable' = $false; 'AzImpersonationLevel' = 0; 'AzScopeName' = ''; 'AzStoreName' = ''; 'CacheControlCustom' = ''; 'CacheControlMaxAge' = 0; 'CacheControlNoCache' = $false; 'CacheISAPI' = $false; 'CGITimeout' = 0; 'ContentIndexed' = $false; 'CreateCGIWithNewConsole' = $false; 'CreateProcessAsUser' = $false; 'DefaultDoc' = ''; 'DefaultDocFooter' = ''; 'DefaultLogonDomain' = ''; 'DirBrowseFlags' = 0; 'DirBrowseShowDate' = $false; 'DirBrowseShowExtension' = $false; 'DirBrowseShowLongDate' = $false; 'DirBrowseShowSize' = $false; 'DirBrowseShowTime' = $false; 'DoDynamicCompression' = $false; 'DontLog' = $false; 'DoStaticCompression' = $false; 'EnableDefaultDoc' = $false; 'EnableDirBrowsing' = $false; 'EnableDocFooter' = $false; 'EnableReverseDns' = $false; 'FrontPageWeb' = $false; 'HttpExpires' = ''; 'HttpRedirect' = ''; 'LogonMethod' = 0; 'MaxRequestEntityAllowed' = 0; 'Name' = ''; 'PoolIdcTimeout' = 0; 'Realm' = ''; 'RedirectHeaders' = ''; 'ShutdownTimeLimit' = 0; 'SSIExecDisable' = $false; 'UploadReadAheadSize' = 0; 'UseDigestSSP' = $false; }
                        }
                        $returnInfo
                    }
                    Start-Job -ScriptBlock $Scriptblock -ArgumentList @($RemoteComputer) | out-null
                }
                While (@(Get-Job | where-object { $_.State -eq "Running" }).Count -ge 1) {  
                    Start-Sleep -Seconds 3
                }
                $returninfo = ForEach ($Job in (Get-Job)) {
                    Receive-Job $Job
                    Remove-Job $Job
                }
                $IisWebVirtualDirSetting += $returninfo | where-object {$_.ReturnType -in (1)}
                $returninfo | where-object {$_.ReturnType -eq 2} | ForEach-Object {
                    $Script:ServerDown += New-Object -TypeName PSObject -Property @{'ServerName' = $_.ServerName; 'ConnectionType' = $_.ConnectionType }
                }
                $returninfo | where-object {$_.ReturnType -eq 3} | ForEach-Object {
                    Write-RFLLog -logtype "EXCEPTION" -logmessage "Server '$($_.ServerName)' generated Error. Error Message: '$($_.Error)'"
                    $Script:ServerDown += New-Object -TypeName PSObject -Property @{'ServerName' = $_.ServerName; 'ConnectionType' = $_.ConnectionType }
                }
                Export-RFLXMLFile -VariableName 'IisWebVirtualDirSetting' -ClearVariable
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(372,373,374,375,376,377,378)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\IIsApplicationPoolSetting.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "IIsApplicationPoolSetting" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $IISList | Select-Object NetworkOSPath | Get-Unique -AsString | ForEach-Object {
                    $item = $_ 
                    $RemoteComputer = ($item.NetworkOSPath.Replace('\\',''))
                    While (@(Get-Job | where-object { $_.State -eq "Running" }).Count -ge $Script:MaxThreads) {  
                        Start-Sleep -Seconds 3
                    }
                    Write-RFLLog -logtype "Info" -logmessage "Getting Registry information ('IIS Application Pool') for '$($RemoteComputer)'"
                    $Scriptblock = {
                        Param (
                            $RemoteComputer
                        )
                        try {
                            $returnInfo = @()
                            $itemReturn = (Get-WmiObject -ComputerName $RemoteComputer -namespace "root\MicrosoftIISv2" -class "IIsApplicationPoolSetting" -ErrorAction SilentlyContinue)
                            if ($null -ne $itemReturn) {
                                $itemreturn | foreach-object {
                                    $returnInfo += New-Object -TypeName PSObject -Property @{'ReturnType' = 1; 'ServerName' = $RemoteComputer; 'ConnectionType' = ''; 'Error' = ''; 'AppPoolAutoStart' = $_.AppPoolAutoStart; 'AppPoolCommand' = $_.AppPoolCommand; 'AppPoolIdentityType' = $_.AppPoolIdentityType; 'AppPoolQueueLength' = $_.AppPoolQueueLength; 'AppPoolRecycleConfigChange' = $_.AppPoolRecycleConfigChange; 'AppPoolRecycleIsapiUnhealthy' = $_.AppPoolRecycleIsapiUnhealthy; 'AppPoolRecycleMemory' = $_.AppPoolRecycleMemory; 'AppPoolRecycleOnDemand' = $_.AppPoolRecycleOnDemand; 'AppPoolRecyclePrivateMemory' = $_.AppPoolRecyclePrivateMemory; 'AppPoolRecycleRequests' = $_.AppPoolRecycleRequests; 'AppPoolRecycleSchedule' = $_.AppPoolRecycleSchedule; 'AppPoolRecycleTime' = $_.AppPoolRecycleTime; 'AppPoolState' = $_.AppPoolState; 'AutoShutdownAppPoolExe' = $_.AutoShutdownAppPoolExe; 'AutoShutdownAppPoolParams' = $_.AutoShutdownAppPoolParams; 'CPUAction' = $_.CPUAction; 'CPULimit' = $_.CPULimit; 'CPUResetInterval' = $_.CPUResetInterval; 'DisallowOverlappingRotation' = $_.DisallowOverlappingRotation; 'DisallowRotationOnConfigChange' = $_.DisallowRotationOnConfigChange; 'IdleTimeout' = $_.IdleTimeout; 'LoadBalancerCapabilities' = $_.LoadBalancerCapabilities; 'LogEventOnRecycle' = $_.LogEventOnRecycle; 'LogonMethod' = $_.LogonMethod; 'MaxProcesses' = $_.MaxProcesses; 'Name' = $_.Name; 'OrphanActionExe' = $_.OrphanActionExe; 'OrphanActionParams' = $_.OrphanActionParams; 'OrphanWorkerProcess' = $_.OrphanWorkerProcess; 'PeriodicRestartMemory' = $_.PeriodicRestartMemory; 'PeriodicRestartPrivateMemory' = $_.PeriodicRestartPrivateMemory; 'PeriodicRestartRequests' = $_.PeriodicRestartRequests; 'PeriodicRestartTime' = $_.PeriodicRestartTime; 'PingingEnabled' = $_.PingingEnabled; 'PingInterval' = $_.PingInterval; 'PingResponseTime' = $_.PingResponseTime; 'RapidFailProtection' = $_.RapidFailProtection; 'RapidFailProtectionInterval' = $_.RapidFailProtectionInterval; 'RapidFailProtectionMaxCrashes' = $_.RapidFailProtectionMaxCrashes; 'ShutdownTimeLimit' = $_.ShutdownTimeLimit; 'SMPAffinitized' = $_.SMPAffinitized; 'SMPProcessorAffinityMask' = $_.SMPProcessorAffinityMask; 'StartupTimeLimit' = $_.StartupTimeLimit; 'WAMUserName' = $_.WAMUserName; 'WAMUserPass' = $_.WAMUserPass; 'Win32Error' = $_.Win32Error; }
                                }
                            } else {
                                $returnInfo += New-Object -TypeName PSObject -Property @{'ReturnType' = 2; 'ServerName' = $RemoteComputer; 'ConnectionType' = 'WMI (root\MicrosoftIISv2) IIsApplicationPoolSetting'; 'Error' = ''; 'AppPoolAutoStart' = $false; 'AppPoolCommand' = 0; 'AppPoolIdentityType' = 0; 'AppPoolQueueLength' = 0; 'AppPoolRecycleConfigChange' = $false; 'AppPoolRecycleIsapiUnhealthy' = $false; 'AppPoolRecycleMemory' = $false; 'AppPoolRecycleOnDemand' = $false; 'AppPoolRecyclePrivateMemory' = $false; 'AppPoolRecycleRequests' = $false; 'AppPoolRecycleSchedule' = $false; 'AppPoolRecycleTime' = $false; 'AppPoolState' = 0; 'AutoShutdownAppPoolExe' = ''; 'AutoShutdownAppPoolParams' = ''; 'CPUAction' = 0; 'CPULimit' = 0; 'CPUResetInterval' = 0; 'DisallowOverlappingRotation' = $false; 'DisallowRotationOnConfigChange' = $false; 'IdleTimeout' = 0; 'LoadBalancerCapabilities' = 0; 'LogEventOnRecycle' = 0; 'LogonMethod' = 0; 'MaxProcesses' = 0; 'Name' = ''; 'OrphanActionExe' = ''; 'OrphanActionParams' = ''; 'OrphanWorkerProcess' = $false; 'PeriodicRestartMemory' = 0; 'PeriodicRestartPrivateMemory' = 0; 'PeriodicRestartRequests' = 0; 'PeriodicRestartTime' = 0; 'PingingEnabled' = $false; 'PingInterval' = 0; 'PingResponseTime' = 0; 'RapidFailProtection' = $false; 'RapidFailProtectionInterval' = 0; 'RapidFailProtectionMaxCrashes' = 0; 'ShutdownTimeLimit' = 0; 'SMPAffinitized' = $false; 'SMPProcessorAffinityMask' = 0; 'StartupTimeLimit' = 0; 'WAMUserName' = ''; 'WAMUserPass' = ''; 'Win32Error' = 0; }
                            }
                        } catch {
                            $Global:ErrorCapture += $_
                            $returnInfo += New-Object -TypeName PSObject -Property @{'ReturnType' = 2; 'ServerName' = $RemoteComputer; 'ConnectionType' = 'WMI (root\MicrosoftIISv2) IIsApplicationPoolSetting'; 'Error' = $_; 'AppPoolAutoStart' = $false; 'AppPoolCommand' = 0; 'AppPoolIdentityType' = 0; 'AppPoolQueueLength' = 0; 'AppPoolRecycleConfigChange' = $false; 'AppPoolRecycleIsapiUnhealthy' = $false; 'AppPoolRecycleMemory' = $false; 'AppPoolRecycleOnDemand' = $false; 'AppPoolRecyclePrivateMemory' = $false; 'AppPoolRecycleRequests' = $false; 'AppPoolRecycleSchedule' = $false; 'AppPoolRecycleTime' = $false; 'AppPoolState' = 0; 'AutoShutdownAppPoolExe' = ''; 'AutoShutdownAppPoolParams' = ''; 'CPUAction' = 0; 'CPULimit' = 0; 'CPUResetInterval' = 0; 'DisallowOverlappingRotation' = $false; 'DisallowRotationOnConfigChange' = $false; 'IdleTimeout' = 0; 'LoadBalancerCapabilities' = 0; 'LogEventOnRecycle' = 0; 'LogonMethod' = 0; 'MaxProcesses' = 0; 'Name' = ''; 'OrphanActionExe' = ''; 'OrphanActionParams' = ''; 'OrphanWorkerProcess' = $false; 'PeriodicRestartMemory' = 0; 'PeriodicRestartPrivateMemory' = 0; 'PeriodicRestartRequests' = 0; 'PeriodicRestartTime' = 0; 'PingingEnabled' = $false; 'PingInterval' = 0; 'PingResponseTime' = 0; 'RapidFailProtection' = $false; 'RapidFailProtectionInterval' = 0; 'RapidFailProtectionMaxCrashes' = 0; 'ShutdownTimeLimit' = 0; 'SMPAffinitized' = $false; 'SMPProcessorAffinityMask' = 0; 'StartupTimeLimit' = 0; 'WAMUserName' = ''; 'WAMUserPass' = ''; 'Win32Error' = 0; }
                        }
                        $returnInfo
                    }                        
                    Start-Job -ScriptBlock $Scriptblock -ArgumentList @($RemoteComputer) | out-null
                }
                While (@(Get-Job | where-object { $_.State -eq "Running" }).Count -ge 1) {  
                    Start-Sleep -Seconds 3
                }
                $returninfo = ForEach ($Job in (Get-Job)) {
                    Receive-Job $Job
                    Remove-Job $Job
                }

                $IIsApplicationPoolSetting += $returninfo | where-object {$_.ReturnType -in (1)}
                $returninfo | where-object {$_.ReturnType -eq 2} | ForEach-Object {
                    $Script:ServerDown += New-Object -TypeName PSObject -Property @{'ServerName' = $_.ServerName; 'ConnectionType' = $_.ConnectionType }
                }
                $returninfo | where-object {$_.ReturnType -eq 3} | ForEach-Object {
                    Write-RFLLog -logtype "EXCEPTION" -logmessage "Server '$($_.ServerName)' generated Error. Error Message: '$($_.Error)'"
                    $Script:ServerDown += New-Object -TypeName PSObject -Property @{'ServerName' = $_.ServerName; 'ConnectionType' = $_.ConnectionType }
                }
                Export-RFLXMLFile -VariableName 'IIsApplicationPoolSetting' -ClearVariable
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(383)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\CMUpdates.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "CMUpdates" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $CMSiteUpdates += Get-CMSiteUpdate
                Export-RFLXMLFile -VariableName 'CMSiteUpdates' -ClearVariable
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(386,387)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\OptionalFeaturesList.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "OptionalFeaturesList" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $SiteRoleListWOCDP | select-Object SiteCode, @{Name='NetworkOSPath';Expression={$_.NetworkOSPath.Tolower().Trim()}} -Unique | ForEach-Object {
                    $item = $_
                    $RemoteComputer = ($item.NetworkOSPath.Replace('\\',''))
                    While (@(Get-Job | where-object { $_.State -eq "Running" }).Count -ge $Script:MaxThreads) {  
                        Start-Sleep -Seconds 3
                    }
                    Write-RFLLog -logtype "Info" -logmessage "Getting 'Windows Features' information for '$($RemoteComputer)'"
                    $Scriptblock = {
                        Param (
                            $RemoteComputer
                        )
                        try {
                            $returnInfo = @()
                            $itemReturn = (Get-WmiObject -ComputerName $RemoteComputer -namespace "root\cimv2" -class "Win32_OptionalFeature" -ErrorAction SilentlyContinue)
                            if ($null -ne $itemReturn) {
                                $itemreturn | foreach-object {
                                    $returnInfo += New-Object -TypeName PSObject -Property @{'ReturnType' = 1; 'ServerName' = $RemoteComputer; 'ConnectionType' = ''; 'Error' = ''; 'Description' = $_.Description; 'InstallDate' = $_.InstallDate; 'Status' = $_.Status; 'Caption' = $_.Caption; 'Name' = $_.Name; 'InstallState' = $_.InstallState;  }
                                }
                            } else {
                                $returnInfo += New-Object -TypeName PSObject -Property @{'ReturnType' = 2; 'ServerName' = $RemoteComputer; 'ConnectionType' = 'WMI (root\cimv2) OptionalFeature'; 'Error' = ''; 'Description' = ''; 'InstallDate' = (Get-Date); 'Status' = ''; 'Caption' = ''; 'Name' = ''; 'InstallState' = 0;  }
                            }
                        } catch {
                            $Global:ErrorCapture += $_
                            $returnInfo += New-Object -TypeName PSObject -Property @{'ReturnType' = 2; 'ServerName' = $RemoteComputer; 'ConnectionType' = 'WMI (root\cimv2) OptionalFeature'; 'Error' = $_; 'Description' = ''; 'InstallDate' = (Get-Date); 'Status' = ''; 'Caption' = ''; 'Name' = ''; 'InstallState' = 0;  }
                        }
                        $returnInfo
                    }                        
                    Start-Job -ScriptBlock $Scriptblock -ArgumentList @($RemoteComputer) | out-null
                }
                While (@(Get-Job | where-object { $_.State -eq "Running" }).Count -ge 1) {  
                    Start-Sleep -Seconds 3
                }

                $returninfo = ForEach ($Job in (Get-Job)) {
                    Receive-Job $Job
                    Remove-Job $Job
                }
                
                $OptionalFeaturesList += $returninfo | where-object {$_.ReturnType -in (1)}
                $returninfo | where-object {$_.ReturnType -eq 2} | ForEach-Object {
                    $Script:ServerDown += New-Object -TypeName PSObject -Property @{'ServerName' = $_.ServerName; 'ConnectionType' = $_.ConnectionType }
                }
                $returninfo | where-object {$_.ReturnType -eq 3} | ForEach-Object {
                    Write-RFLLog -logtype "EXCEPTION" -logmessage "Server '$($_.ServerName)' generated Error. Error Message: '$($_.Error)'"
                    $Script:ServerDown += New-Object -TypeName PSObject -Property @{'ServerName' = $_.ServerName; 'ConnectionType' = $_.ConnectionType }
                }
                Export-RFLXMLFile -VariableName 'OptionalFeaturesList' -ClearVariable
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(388,389)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\SoftwareUpdateDeploymentPackage.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "SoftwareUpdateDeploymentPackage" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $SoftwareUpdateDeploymentPackage += Get-CMSoftwareUpdateDeploymentPackage
                Export-RFLXMLFile -VariableName 'SoftwareUpdateDeploymentPackage' -ClearVariable
            }
        }
        #endregion

        #region sub-Rules 
        $arrRuleID = @(390,391,392)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\SQLJobs.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "SQLJobs" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $SQLJobs = @()
                $SQLServerPrimarySiteList | ForEach-Object { 
                    $item = $_

                    $arrPropList = $item.PropLists[0].values.split(',').Trim()
                    $ServerName = $item.NetworkOSPath.Replace('\\','')
                    $DbName = $arrPropList[2]

                    if ($arrPropList[2].IndexOf('\') -ge 0) {
                        $ServerName += "\{0}" -f $arrPropList[2].split('\')[0]
                        $DbName = $arrPropList[2].split('\')[1]
                    }

                    Write-RFLLog -logtype "Info" -logmessage "Getting SQL Server $($ServerName) Information"
                    $code = {
                        Param (
                            $servername,
                            $databasename
                        )
                        $ReturnInfo = @()
                        #connect to SQL
                        $SQLOpen = $false
                        $conn = New-Object System.Data.SqlClient.SqlConnection
                        try {
                            $conn.ConnectionString = "Data Source=$($servername);Initial Catalog=$($databasename);trusted_connection = true;"
                            $conn.Open()
                            $SQLOpen = $true
                        } catch {
                            $Global:ErrorCapture += $_
                            $ReturnInfo += New-Object -TypeName PSObject -Property @{'Success' = $false; 'ServerName' = $ServerName; 'Total' = 0; 'Name' = ''; 'Description' = ''; 'Enabled' = 0; 'Owner' = ''; 'Scheduled' = 0; 'lastrunstatus' = 0; 'ConnectionType' = 'SQL Server (SQL TCP)' ; 'Error'= $_}
                        }

                        if ($SQLOpen -eq $true) {
                            try {
                                $SqlCommand = $Conn.CreateCommand()
                                $SqlCommand.CommandTimeOut = 0
                                $SqlCommand.CommandText = "select s.name,s.Description,s.Enabled,l.name as Owner, isnull((select top 1 SJH.run_status from msdb..sysjobhistory SJH where s.job_id = sjh.job_id and SJH.run_date = (SELECT MAX(SJH1.run_date) FROM msdb..sysjobhistory SJH1 WHERE SJH.job_id = SJH1.job_id)), 2) as lastrunstatus, CASE WHEN EXISTS (SELECT 1 FROM msdb..sysjobschedules ss WITh(NOLOCK) WHERE s.job_id = ss.job_id) THEN 1 else 0 END as Scheduled from  msdb..sysjobs s left join master.sys.syslogins l on s.owner_sid = l.sid"
                                $DataAdapter = new-object System.Data.SqlClient.SqlDataAdapter $SqlCommand
                                $dataset = new-object System.Data.Dataset
                                $DataAdapter.Fill($dataset) | Out-Null

                                if ($dataset.Tables[0].Rows.Count -eq 0) {
                                    $ReturnInfo += New-Object -TypeName PSObject -Property @{'Success' = $true; 'ServerName' = $ServerName; 'Total' = 0; 'Name' = ''; 'Description' = ''; 'Enabled' = 0; 'Owner' = ''; 'Scheduled' = 0; 'lastrunstatus' = 0; 'ConnectionType' = 'SQL Server (SQL TCP)' ; 'Error'= ''}
                                } else {
                                    $rowCount = $dataSet.Tables[0].Rows.Count
                                    $dataset.Tables[0].Rows | ForEach-Object {
                                        $ReturnInfo += New-Object -TypeName PSObject -Property @{'Success' = $true; 'ServerName' = $ServerName; 'Total' = $rowCount; 'Name' = $_.Name; 'Description' = $_.Description; 'Enabled' = $_.Enabled; 'Owner' = $_.Owner; 'Scheduled' = $_.Scheduled; 'lastrunstatus' = $_.lastrunstatus; 'ConnectionType' = 'SQL Server (SQL TCP)' ; 'Error'= ''}
                                    }
                                }
                            } catch {
                                $Global:ErrorCapture += $_
                                $ReturnInfo += New-Object -TypeName PSObject -Property @{'Success' = $false; 'ServerName' = $ServerName; 'Total' = 0; 'Name' = ''; 'Description' = ''; 'Enabled' = 0; 'Owner' = ''; 'Scheduled' = 0; 'lastrunstatus' = 0; 'ConnectionType' = 'SQL Server (SQL TCP)' ; 'Error'= $_}
                            } finally {
                                $conn.Close()
                            }
                        }
                        $ReturnInfo
                    }
                    $returninfo = Execute-RFLRunSpace -code $Code -ParameterList @($ServerName, $DbName)

                    $returninfo | where-object {$_.Success -eq $true} | foreach-object {
                        $SQLJobs += New-Object -TypeName PSObject -Property @{'ServerName' = $_.ServerName; 'Total' = $_.Total; 'Name' = $_.Name; 'Description' = $_.Description; 'Enabled' = $_.Enabled; 'Owner' = $_.Owner; 'Scheduled' = $_.Scheduled; 'lastrunstatus' = $_.lastrunstatus; }
                    }

                    $returninfo | where-object {$_.Success -eq $false} | foreach-object {
                        Write-RFLLog -logtype "EXCEPTION" -logmessage "Error Message: '$($_.Error)'"
                        $Script:ServerDown += New-Object -TypeName PSObject -Property @{'ServerName' =$_.ServerName; 'ConnectionType' = $_.ConnectionType }
                    }
                }
                Export-RFLXMLFile -VariableName 'SQLJobs' -ClearVariable
            }
        }
        #endregion

        #region sub-Rules 
        $arrRuleID = @(393)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\SQLDBWaits.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "SQLDBWaits" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $SQLDBWaits = @()
                $SQLServerPrimarySiteList | ForEach-Object { 
                    $item = $_

                    $arrPropList = $item.PropLists[0].values.split(',').Trim()
                    $ServerName = $item.NetworkOSPath.Replace('\\','')
                    $DbName = $arrPropList[2]

                    if ($arrPropList[2].IndexOf('\') -ge 0) {
                        $ServerName += "\{0}" -f $arrPropList[2].split('\')[0]
                        $DbName = $arrPropList[2].split('\')[1]
                    }

                    Write-RFLLog -logtype "Info" -logmessage "Getting SQL Server $($ServerName) Information"
                    $code = {
                        Param (
                            $servername,
                            $databasename
                        )
                        $ReturnInfo = @()
                        #connect to SQL
                        $SQLOpen = $false
                        $conn = New-Object System.Data.SqlClient.SqlConnection
                        try {
                            $conn.ConnectionString = "Data Source=$($servername);Initial Catalog=$($databasename);trusted_connection = true;"
                            $conn.Open()
                            $SQLOpen = $true
                        } catch {
                            $Global:ErrorCapture += $_
                            $ReturnInfo += New-Object -TypeName PSObject -Property @{'Success' = $false; 'ServerName' = $ServerName; 'cpuwaits' = 0; 'resourcewaits' = 0; 'ConnectionType' = 'SQL Server (SQL TCP)' ; 'Error'= $_}
                        }

                        if ($SQLOpen -eq $true) {
                            try {
                                $SqlCommand = $Conn.CreateCommand()
                                $SqlCommand.CommandTimeOut = 0
                                $SqlCommand.CommandText = "SELECT CAST(100.0 * SUM(signal_wait_time_ms) / SUM (wait_time_ms) AS NUMERIC(20,2)) AS [cpuwaits],CAST(100.0 * SUM(wait_time_ms - signal_wait_time_ms) / SUM (wait_time_ms) AS NUMERIC(20,2)) AS [resourcewaits] FROM sys.dm_os_wait_stats OPTION (RECOMPILE);"
                                $DataAdapter = new-object System.Data.SqlClient.SqlDataAdapter $SqlCommand
                                $dataset = new-object System.Data.Dataset
                                $DataAdapter.Fill($dataset) | Out-Null

                                if ($dataset.Tables[0].Rows.Count -eq 0) {
                                    $ReturnInfo += New-Object -TypeName PSObject -Property @{'Success' = $true; 'ServerName' = $ServerName; 'cpuwaits' = 0; 'resourcewaits' = 0; 'ConnectionType' = 'SQL Server (SQL TCP)' ; 'Error'= ''}
                                } else {
                                    $rowCount = $dataSet.Tables[0].Rows.Count
                                    $dataset.Tables[0].Rows | ForEach-Object {
                                        $ReturnInfo += New-Object -TypeName PSObject -Property @{'Success' = $true; 'ServerName' = $ServerName; 'cpuwaits' = $_.cpuwaits; 'resourcewaits' = $_.resourcewaits; 'ConnectionType' = 'SQL Server (SQL TCP)' ; 'Error'= ''}
                                    }
                                }
                            } catch {
                                $Global:ErrorCapture += $_
                                $ReturnInfo += New-Object -TypeName PSObject -Property @{'Success' = $false; 'ServerName' = $ServerName; 'cpuwaits' = 0; 'resourcewaits' = 0; 'ConnectionType' = 'SQL Server (SQL TCP)' ; 'Error'= $_}
                            } finally {
                                $conn.Close()
                            }
                        }
                        $ReturnInfo
                    }
                    $returninfo = Execute-RFLRunSpace -code $Code -ParameterList @($ServerName, $DbName)

                    $returninfo | where-object {$_.Success -eq $true} | foreach-object {
                        $SQLDBWaits += New-Object -TypeName PSObject -Property @{'ServerName' = $_.ServerName; 'cpuwaits' = $_.cpuwaits; 'resourcewaits' = $_.resourcewaits; }
                    }

                    $returninfo | where-object {$_.Success -eq $false} | foreach-object {
                        Write-RFLLog -logtype "EXCEPTION" -logmessage "Error Message: '$($_.Error)'"
                        $Script:ServerDown += New-Object -TypeName PSObject -Property @{'ServerName' =$_.ServerName; 'ConnectionType' = $_.ConnectionType }
                    }
                }
                Export-RFLXMLFile -VariableName 'SQLDBWaits' -ClearVariable
            }
        }
        #endregion

        #region sub-Rules 
        $arrRuleID = @(394,395,396,397)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\SQLDBInfo.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "SQLDBInfo" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $SQLDBInfo = @()
                $SQLServerPrimarySiteList | ForEach-Object { 
                    $item = $_

                    $arrPropList = $item.PropLists[0].values.split(',').Trim()
                    $ServerName = $item.NetworkOSPath.Replace('\\','')
                    $DbName = $arrPropList[2]

                    if ($arrPropList[2].IndexOf('\') -ge 0) {
                        $ServerName += "\{0}" -f $arrPropList[2].split('\')[0]
                        $DbName = $arrPropList[2].split('\')[1]
                    }

                    Write-RFLLog -logtype "Info" -logmessage "Getting SQL Server $($ServerName) Information"
                    $code = {
                        Param (
                            $servername,
                            $databasename
                        )
                        $ReturnInfo = @()
                        #connect to SQL
                        $SQLOpen = $false
                        $conn = New-Object System.Data.SqlClient.SqlConnection
                        try {
                            $conn.ConnectionString = "Data Source=$($servername);Initial Catalog=$($databasename);trusted_connection = true;"
                            $conn.Open()
                            $SQLOpen = $true
                        } catch {
                            $Global:ErrorCapture += $_
                            $ReturnInfo += New-Object -TypeName PSObject -Property @{'Success' = $false; 'ServerName' = $ServerName; 'DBName' = ''; 'recovery_model_desc' = ''; 'type_desc' = ''; 'physical_name' = ''; 'size' = 0; 'max_size' = 0; 'FreeSpace' = 0; 'is_percent_growth' = 0; 'growth' = 0; 'CountDataFile' = 0; 'CountLogFile' = 0; 'ConnectionType' = 'SQL Server (SQL TCP)' ; 'Error'= $_}
                        }

                        if ($SQLOpen -eq $true) {
                            try {
                                $SqlCommand = $Conn.CreateCommand()
                                $SqlCommand.CommandTimeOut = 0
                                $SqlCommand.CommandText = @"
Create Table ##temp_DatabaseAnalysis (DatabaseName sysname, Name sysname, physical_name nvarchar(500), size decimal (18,2), FreeSpace decimal (18,2) ) -- #text
Exec sp_msforeachdb '
Use [?];
Insert Into ##temp_DatabaseAnalysis (DatabaseName, Name, physical_name, Size, FreeSpace) -- #text
Select DB_NAME() AS [DatabaseName], Name,  physical_name,
Cast(Cast(Round(cast(size as decimal) * 8.0/1024.0,2) as decimal(18,2)) as nvarchar) Size,
Cast(Cast(Round(cast(size as decimal) * 8.0/1024.0,2) as decimal(18,2)) - Cast(FILEPROPERTY(name, ''SpaceUsed'') * 8.0/1024.0 as decimal(18,2)) as nvarchar) As FreeSpace
From sys.database_files
'

select db.name, db.recovery_model_desc, mf.type_desc, mf.physical_name, mf.size, mf.max_size, tmp.FreeSpace, mf.is_percent_growth, mf.growth, 
(select count(1) FROM sys.master_files mf1 where mf1.type_desc = 'ROWS' and db.database_id = mf1.database_id ) as CountDataFile,
(select count(1) FROM sys.master_files mf1 where mf1.type_desc = 'LOG' and db.database_id = mf1.database_id ) as CountLogFile
from sys.master_files mf inner join sys.databases db on db.database_id = mf.database_id
inner join ##temp_DatabaseAnalysis tmp on mf.physical_name = tmp.physical_name -- #text

drop table ##temp_DatabaseAnalysis -- #text
"@
                                $DataAdapter = new-object System.Data.SqlClient.SqlDataAdapter $SqlCommand
                                $dataset = new-object System.Data.Dataset
                                $DataAdapter.Fill($dataset) | Out-Null

                                if ($dataset.Tables[0].Rows.Count -eq 0) {
                                    $ReturnInfo += New-Object -TypeName PSObject -Property @{'Success' = $true; 'ServerName' = $ServerName; 'DBName' = ''; 'recovery_model_desc' = ''; 'type_desc' = ''; 'physical_name' = ''; 'size' = 0; 'max_size' = 0; 'FreeSpace' = 0; 'is_percent_growth' = 0; 'growth' = 0; 'CountDataFile' = 0; 'CountLogFile' = 0; 'ConnectionType' = 'SQL Server (SQL TCP)' ; 'Error'= ''}
                                } else {
                                    $rowCount = $dataSet.Tables[0].Rows.Count
                                    $dataset.Tables[0].Rows | ForEach-Object {
                                        $ReturnInfo += New-Object -TypeName PSObject -Property @{'Success' = $true; 'ServerName' = $ServerName; 'DBName' = $_.Name; 'recovery_model_desc' = $_.recovery_model_desc; 'type_desc' = $_.type_desc; 'physical_name' = $_.physical_name; 'size' = $_.size; 'max_size' = $_.max_size; 'FreeSpace' = $_.FreeSpace; 'is_percent_growth' = $_.is_percent_growth; 'growth' = $_.growth; 'CountDataFile' = $_.CountDataFile; 'CountLogFile' = $_.CountLogFile; 'ConnectionType' = 'SQL Server (SQL TCP)' ; 'Error'= ''}
                                    }
                                }
                            } catch {
                                $Global:ErrorCapture += $_
                                $ReturnInfo += New-Object -TypeName PSObject -Property @{'Success' = $false; 'ServerName' = $ServerName; 'DBName' = ''; 'recovery_model_desc' = ''; 'type_desc' = ''; 'physical_name' = ''; 'size' = 0; 'max_size' = 0; 'FreeSpace' = 0; 'is_percent_growth' = 0; 'growth' = 0; 'CountDataFile' = 0; 'CountLogFile' = 0; 'ConnectionType' = 'SQL Server (SQL TCP)' ; 'Error'= $_}
                            } finally {
                                $conn.Close()
                            }
                        }
                        $ReturnInfo
                    }
                    $returninfo = Execute-RFLRunSpace -code $Code -ParameterList @($ServerName, $databasename)

                    $returninfo | where-object {$_.Success -eq $true} | foreach-object {
                        $SQLDBInfo += New-Object -TypeName PSObject -Property @{'ServerName' = $_.ServerName; 'DBName' = $_.DBName; 'recovery_model_desc' = $_.recovery_model_desc; 'type_desc' = $_.type_desc; 'physical_name' = $_.physical_name; 'size' = $_.size; 'max_size' = $_.max_size; 'FreeSpace' = $_.FreeSpace; 'is_percent_growth' = $_.is_percent_growth; 'growth' = $_.growth; 'CountDataFile' = $_.CountDataFile; 'CountLogFile' = $_.CountLogFile; }
                    }

                    $returninfo | where-object {$_.Success -eq $false} | foreach-object {
                        Write-RFLLog -logtype "EXCEPTION" -logmessage "Error Message: '$($_.Error)'"
                        $Script:ServerDown += New-Object -TypeName PSObject -Property @{'ServerName' =$_.ServerName; 'ConnectionType' = $_.ConnectionType }
                    }
                }
                Export-RFLXMLFile -VariableName 'SQLDBInfo' -ClearVariable
            }
        }
        #endregion

        #region sub-Rules 
        $arrRuleID = @(398)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\SQLDBGrowth.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "SQLDBGrowth" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $SQLDBGrowth = @()
                $SQLServerPrimarySiteList | ForEach-Object { 
                    $item = $_

                    $arrPropList = $item.PropLists[0].values.split(',').Trim()
                    $ServerName = $item.NetworkOSPath.Replace('\\','')
                    $DbName = $arrPropList[2]

                    if ($arrPropList[2].IndexOf('\') -ge 0) {
                        $ServerName += "\{0}" -f $arrPropList[2].split('\')[0]
                        $DbName = $arrPropList[2].split('\')[1]
                    }

                    Write-RFLLog -logtype "Info" -logmessage "Getting SQL Server $($ServerName) Information"
                    $code = {
                        Param (
                            $servername,
                            $databasename,
                            $AutoGrowthDateOld
                        )
                        $ReturnInfo = @()
                        #connect to SQL
                        $SQLOpen = $false
                        $conn = New-Object System.Data.SqlClient.SqlConnection
                        try {
                            $conn.ConnectionString = "Data Source=$($servername);Initial Catalog=$($databasename);trusted_connection = true;"
                            $conn.Open()
                            $SQLOpen = $true
                        } catch {
                            $Global:ErrorCapture += $_
                            $ReturnInfo += New-Object -TypeName PSObject -Property @{'Success' = $false; 'ServerName' = $ServerName; 'database_name' = ''; 'backup_start_date' = ''; 'backup_finish_date' = ''; 'ConnectionType' = 'SQL Server (SQL TCP)' ; 'Error'= $_}
                        }

                        if ($SQLOpen -eq $true) {
                            try {
                                $SqlCommand = $Conn.CreateCommand()
                                $SqlCommand.CommandTimeOut = 0
                                $SqlCommand.CommandText = "SELECT s.database_name, s.backup_size, s.backup_start_date, s.backup_finish_date FROM msdb.dbo.backupset s INNER JOIN msdb.dbo.backupmediafamily m ON s.media_set_id = m.media_set_id WHERE s.backup_start_date >= DATEADD(dd,-convert(int,$($AutoGrowthDateOld)),GetDate())"
                                $DataAdapter = new-object System.Data.SqlClient.SqlDataAdapter $SqlCommand
                                $dataset = new-object System.Data.Dataset
                                $DataAdapter.Fill($dataset) | Out-Null

                                if ($dataset.Tables[0].Rows.Count -eq 0) {
                                    $ReturnInfo += New-Object -TypeName PSObject -Property @{'Success' = $true; 'ServerName' = $ServerName; 'database_name' = ''; 'backup_start_date' = ''; 'backup_finish_date' = ''; 'ConnectionType' = 'SQL Server (SQL TCP)' ; 'Error'= ''}
                                } else {
                                    $rowCount = $dataSet.Tables[0].Rows.Count
                                    $dataset.Tables[0].Rows | ForEach-Object {
                                        $ReturnInfo += New-Object -TypeName PSObject -Property @{'Success' = $true; 'ServerName' = $ServerName; 'database_name' = $_.database_name; 'backup_start_date' = $_.backup_start_date; 'backup_finish_date' = $_.backup_finish_date; 'ConnectionType' = 'SQL Server (SQL TCP)' ; 'Error'= ''}
                                    }
                                }
                            } catch {
                                $Global:ErrorCapture += $_
                                $ReturnInfo += New-Object -TypeName PSObject -Property @{'Success' = $false; 'ServerName' = $ServerName; 'database_name' = ''; 'backup_start_date' = ''; 'backup_finish_date' = ''; 'ConnectionType' = 'SQL Server (SQL TCP)' ; 'Error'= $_}
                            } finally {
                                $conn.Close()
                            }
                        }
                        $ReturnInfo
                    }
                    $returninfo = Execute-RFLRunSpace -code $Code -ParameterList @($ServerName, $DbName, $Script:AutoGrowthDateOld)

                    $returninfo | where-object {$_.Success -eq $true} | foreach-object {
                        $SQLDBGrowth += New-Object -TypeName PSObject -Property @{'ServerName' = $ServerName; 'database_name' = $_.database_name; 'backup_start_date' = $_.backup_start_date; 'backup_finish_date' = $_.backup_finish_date; }
                    }

                    $returninfo | where-object {$_.Success -eq $false} | foreach-object {
                        Write-RFLLog -logtype "EXCEPTION" -logmessage "Error Message: '$($_.Error)'"
                        $Script:ServerDown += New-Object -TypeName PSObject -Property @{'ServerName' =$_.ServerName; 'ConnectionType' = $_.ConnectionType }
                    }
                }
                Export-RFLXMLFile -VariableName 'SQLDBGrowth' -ClearVariable
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(399,400)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\sitesummarytask.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "sitesummarytask" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $sitesummarytask += get-cmsitesummarytask
                Export-RFLXMLFile -VariableName 'sitesummarytask'
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(401)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\ManagementInsights.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "ManagementInsights" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $ManagementInsights += Get-WmiObject -computer $SMSProviderServer -Namespace "root\sms\site_$($MainSiteCode)" -Query 'SELECT * FROM SMS_ManagementInsights'
                Export-RFLXMLFile -VariableName 'ManagementInsights'
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(402)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\SiteFeature.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "SiteFeature" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                $SiteFeature += Get-CMSiteFeature
                Export-RFLXMLFile -VariableName 'SiteFeature'
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(407)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"

            $FileToImport = "$($SaveToFolder)\InventoryDataLoader.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "InventoryDataLoader" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {                
                $SiteList | select-Object SiteCode, @{Name='ServerName';Expression={$_.ServerName.Tolower().Trim()}} -Unique | ForEach-Object {
                    $item = $_
                    $RemoteComputer = ($item.ServerName.Replace('\\',''))
                    Write-RFLLog -logtype "Info" -logmessage "Getting Registry information ('Max MIF Size') for '$($RemoteComputer)'"
                    $code = {
                        Param (
                            $RemoteComputer,
                            $SiteCode
                        )
                        try {
                            $Reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey('LocalMachine', $RemoteComputer)
                            $RegKey= $Reg.OpenSubKey("Software\Microsoft\SMS\Components\SMS_INVENTORY_DATA_LOADER")
                            if ($null -eq $RegKey) {
                                $RegKey= $Reg.OpenSubKey("Software\Microsoft\SMS\Components\SMS_INVENTORY_DATA_LOADER") #2008 format
                            }

                            $MaxMifSize = $RegKey.GetValue("Max MIF Size")

                            $ReturnInfo = New-Object -TypeName PSObject -Property @{'Success' = $true; 'SiteCode' = $SiteCode; 'ServerName' = $RemoteComputer; 'MaxMifSize' = $MaxMifSize; 'ConnectionType' = ''; 'Error'='' }
                        } catch {
                            $Global:ErrorCapture += $_
                            $ReturnInfo = New-Object -TypeName PSObject -Property @{'Success' = $false; 'SiteCode' = $SiteCode; 'ServerName' = $RemoteComputer; 'MaxMifSize' = ''; 'ConnectionType' = 'Max MIF Size Remote Registry (RRP/RPC)'; 'Error'=$_ }
                        }
                        $ReturnInfo
                    }
                    $ReturnInfo = Execute-RFLRunSpace -code $Code -ParameterList @($RemoteComputer, $item.SiteCode)

                    $InventoryDataLoader += $ReturnInfo | where-object {$_.Success -eq $true}

                    $ReturnInfo | where-object {$_.Success -eq $false} | ForEach-Object {
                        Write-RFLLog -logtype "EXCEPTION" -logmessage "Error Message: '$($_.Error)'"
                        $Script:ServerDown += New-Object -TypeName PSObject -Property @{'ServerName' =$_.ServerName; 'ConnectionType' = $_.ConnectionType }
                    }
                }
                Export-RFLXMLFile -VariableName 'InventoryDataLoader' -ClearVariable
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(408,409)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\AADTenant.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "AADTenant" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                Write-RFLLog -logtype "Info" -logmessage "Getting 'AAD Tenant' List Information"
                $AADTenant += (Get-WmiObject -computer $SMSProviderServer -Namespace "root\sms\site_$($MainSiteCode)" -Class "SMS_AAD_Tenant_Ex")
                Export-RFLXMLFile -VariableName 'AADTenant' -ClearVariable
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(408,409)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\AADApplication.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "AADApplication" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                Write-RFLLog -logtype "Info" -logmessage "Getting 'AAD Application' List Information"
                $AADApplication += Get-CMAADApplication
                Export-RFLXMLFile -VariableName 'AADApplication' -ClearVariable
            }
        }
        #endregion

        #region sub-Rules
        $arrRuleID = @(410,411,412)
        if (-not (Test-RFLHealthCheckCollectData -Rules $arrRuleID)) {
            Write-RFLLog -logtype "WARNING" -logmessage "Rule(s) $($arrRuleID) is/are disabled. Collecting Data ignored"
        } else {
            Write-RFLLog -logtype "INFO" -logmessage "At least one rule ($($arrRuleID)) is enabled. Collecting Data"
            $FileToImport = "$($SaveToFolder)\CloudManagementGateway.xml"
            if (Test-Path -LiteralPath $FileToImport) {
                Write-RFLLog -logtype "WARNING" -logmessage "File $($FileToImport) already exist, using existing file"
                New-Variable -Name "CloudManagementGateway" -Value (Import-Clixml -Path "$($FileToImport)") -Force -Option AllScope -Scope Script
            } else {
                Write-RFLLog -logtype "Info" -logmessage "Getting 'Cloud Management Gateway' List Information"
                $CloudManagementGateway += Get-CMCloudManagementGateway
                Export-RFLXMLFile -VariableName 'CloudManagementGateway' -ClearVariable
            }
        }
        #endregion

        Export-RFLXMLFile -VariableName 'ServerDown' -ClearVariable
        Export-RFLXMLFile -VariableName 'ServerHTTPAccessInformation' -ClearVariable
        #endregion

        $Script:EndCollectingDateTime = get-date
        Write-RFLLog -logtype "Info" -logmessage "Successfully exported Data"
        #endregion
    } finally {
        Set-Location -Path "$($CurrentDriveLetter):"
        #Write-RFLLog -logtype "Info" -logmessage "Removing Folder $($SaveToFolder)"
        #Remove-Item -Path $SaveToFolder -Force -Recurse
    }
    #endregion
} catch {
    $Global:ErrorCapture += $_
    Write-RFLLog -logtype "EXCEPTION" -logmessage "Error Message: '$($_)'"
    if ($Verbose) {
        Write-RFLLog -logtype "EXCEPTION" -logmessage "$($_.InvocationInfo.ScriptName)($($_.InvocationInfo.ScriptLineNumber)): $($_.InvocationInfo.Line)"
    }
} finally {
    #region export error information
    $Global:ErrorCapture += $Error
    $Global:ErrorCapture | Export-Clixml -Path "$($SaveToFolder)\ErrorCapture.xml"
    #endregion

    #region Create Zip File on Desktop
    if ($CreateZipFiles) {
        $ZipFileName = "$([System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Desktop))\ConfigMgrHealthCheck-$((Get-Date).ToString('yyyy-MM-dd HH-mm-ss')).zip"
        Write-RFLZipFiles -zipfilename $ZipFileName -sourcedir $SaveToFolder
        Write-RFLLog -logtype "Info" -logmessage "Successfully created ZIP file '$($ZipFileName)'"
    }
    #endregion

    $Script:EndDateTime = get-date
    $FullScriptTimeSpan = New-TimeSpan -Start $Script:StartDateTime -End $Script:EndDateTime
    if (($null -ne $Script:StartCollectingDateTime) -and ($null -ne $Script:EndCollectingDateTime)) {
        $CollectingScriptTimeSpan = New-TimeSpan -Start $Script:StartCollectingDateTime -End $Script:EndCollectingDateTime
        Write-RFLLog -logtype "Info" -logmessage "'Collection Data Stats' '$('{0:dd} days, {0:hh} hours, {0:mm} minutes, {0:ss} seconds' -f $CollectingScriptTimeSpan)'"
    }
    Write-RFLLog -logtype "Info" -logmessage "'Full Script Stats' '$(('{0:dd} days, {0:hh} hours, {0:mm} minutes, {0:ss} seconds' -f $FullScriptTimeSpan))'"

    Write-RFLLog -logtype "Info" -logmessage "Cleaning up memory allocation"
}
#endregion