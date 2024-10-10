<# This script was developed to resolve an issue with the WAM Cache where users were being prompted to sign in to activate Windows Enterprise but once entering their 
credentials the sign in process never completed and just stayed on a blank page.

A Reboot is required after running the script
#>
#Requires -RunAsAdministrator

[CmdletBinding()]
Param()

# Set execution policy to Bypass for the current process
Set-ExecutionPolicy -ExecutionPolicy 'ByPass' -Scope 'Process' -Force

function DisplayHeader {
    Write-Host ""
    Write-Host "This script detects and fixes the AAD WAM WebAccount duplication issue usually caused by UPN change."
    Write-Host ""
}

function StopWAMService {
    # Stop WAM service
    Write-Host "Stopping WAM Service."
    Stop-Service -Name "tokenbroker" -Force -ErrorAction SilentlyContinue

    Get-Process -Name "Microsoft.AAD.BrokerPlugin" -ErrorAction SilentlyContinue | Stop-Process -Force
}

function StartWAMService {
    # Start WAM service
    Write-Host "Re-starting WAM Service."
    Start-Service -Name "tokenbroker" -ErrorAction SilentlyContinue
}

function ResetWAMStateForUser($userProfilePath, $userSID) {
    Write-Host "Fixing duplicate WebAccounts for user profile: $userProfilePath."

    $pluginLocation = "$userProfilePath\AppData\Local\Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy"
    $webaccountsPath = "$pluginLocation\AC\TokenBroker\Accounts\*"
    $settingsPath = "$pluginLocation\Settings\settings.dat"

    # Delete files
    Remove-Item -Path $webaccountsPath -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $settingsPath -Force -ErrorAction SilentlyContinue

    # Determine registry hive key
    if ($userSID -and (Test-Path "HKU:\$userSID")) {
        # User hive is already loaded
        $hiveKey = "HKU:\$userSID"
        Write-Host "User registry hive is already loaded under HKEY_USERS\$userSID."
    } else {
        # Load the user's registry hive
        $userHivePath = "$userProfilePath\NTUSER.DAT"
        $hiveKey = "HKU\Temp_$([Guid]::NewGuid())" # Use a unique key to avoid conflicts

        if (Test-Path $userHivePath) {
            try {
                Load-RegistryHive -File $userHivePath -Key $hiveKey
                $hiveLoaded = $true
            } catch {
                Write-Host "Failed to load registry hive for $userProfilePath $_"
                return
            }
        } else {
            Write-Host "No registry hive found for user profile: $userProfilePath."
            return
        }
    }

    # Move DefaultAccount registry for the user
    $defaultAccountPath = "$hiveKey\Software\Microsoft\IdentityCRL\TokenBroker\DefaultAccount"
    $backupAccountPath = "$hiveKey\Software\Microsoft\IdentityCRL\TokenBroker\DefaultAccount_backup"

    if (Test-Path $defaultAccountPath) {
        Move-Item -Path $defaultAccountPath -Destination $backupAccountPath -Force -ErrorAction SilentlyContinue
    } else {
        Write-Host "DefaultAccount registry key not found for $userProfilePath."
    }

    # Unload the user's registry hive if it was loaded by the script
    if ($hiveLoaded) {
        Unload-RegistryHive -Key $hiveKey
    }
}
Function Load-RegistryHive {
    [CmdletBinding()]
    Param(
        [String][Parameter(Mandatory = $true)]$File,
        [String][Parameter(Mandatory = $true)]$Key
    )

    $Process = Start-Process -FilePath "$env:WINDIR\system32\reg.exe" -ArgumentList "load `"$Key`" `"$File`"" -WindowStyle Hidden -PassThru -Wait

    if ($Process.ExitCode) {
        throw [Management.Automation.PSInvalidOperationException] "The registry hive '$File' failed to load."
    }
}

Function Unload-RegistryHive {
    [CmdletBinding()]
    Param(
        [String][Parameter(Mandatory = $true)]$Key
    )

    [gc]::Collect()
    [gc]::WaitForPendingFinalizers()

    $Process = Start-Process -FilePath "$env:WINDIR\system32\reg.exe" -ArgumentList "unload `"$Key`"" -WindowStyle Hidden -PassThru -Wait
    if ($Process.ExitCode) {
        Write-Host "Unable to unload registry hive: $Key"
    }
}
function WriteSettingsDatToRegFile($settingsDatPath) {
    $tempFileGUID = "1ca6ba83-b806-447b-9498-055599c8de4c"
    $originalSettingsPath = $settingsDatPath
    $originalSettingsHash = (Get-FileHash -Path $originalSettingsPath).Hash
    $tempSettingsPath = Join-Path $env:TEMP "settings-$tempFileGUID-$originalSettingsHash.dat"
    $tempRegfilePath = Join-Path $env:TEMP "settings-$tempFileGUID-$originalSettingsHash.reg"

    Write-Host "Copying $settingsDatPath to $tempRegfilePath file."

    Unload-RegistryHive -Key "HKLM\$originalSettingsHash" -ErrorAction SilentlyContinue
    Copy-Item -Path $originalSettingsPath -Destination $tempSettingsPath -Force
    Load-RegistryHive -File $tempSettingsPath -Key "HKLM\$originalSettingsHash"

    $Process = Start-Process -FilePath "$env:WINDIR\system32\reg.exe" -ArgumentList "export `HKLM\$originalSettingsHash` `"$tempRegfilePath`" /y" -WindowStyle Hidden -PassThru -Wait
    if ($Process.ExitCode) {
        Write-Host "Unable to export settings.dat to a .reg file."
    }

    Unload-RegistryHive -Key "HKLM\$originalSettingsHash" -ErrorAction SilentlyContinue
    Remove-Item -Path $tempSettingsPath -Recurse -Force -ErrorAction SilentlyContinue
}

function EnumerateRegistryKey($registryFileContents, $path) {
    $path = $path -replace 'HKLM:', 'HKEY_LOCAL_MACHINE'
    $EnumeratedProperties = New-Object System.Collections.Generic.List[String]
    $keyFound = $false
    foreach ($registryLine in $registryFileContents) {
        if (-not $keyFound) {
            $keyFound = $registryLine.Contains($path)
        } else {
            if ($registryLine.StartsWith("[")) {
                $keyFound = $registryLine.Contains($path)
            } elseif ($registryLine.Length -gt 0) {
                $EnumeratedProperties.Add($registryLine.Split("=")[0].Trim('"'))
            }
        }
    }
    return $EnumeratedProperties
}

function GetRegistryValue($registryFileContents, $path, $property) {
    $path = $path -replace 'HKLM:', 'HKEY_LOCAL_MACHINE'
    $keyFound = $false
    foreach ($registryLine in $registryFileContents) {
        if (-not $keyFound) {
            $keyFound = $registryLine.Contains($path)
        } else {
            if ($registryLine.StartsWith("[")) {
                $keyFound = $registryLine.Contains($path)
            } elseif ($registryLine.Contains($property)) {
                $valueBytes = (($registryLine -split ':')[-1]) -split ',' | ForEach-Object { [byte]"0x$_" }
                $valueString = [Text.Encoding]::Unicode.GetString($valueBytes[0..($valueBytes.Length - 11)])
                return $valueString
            }
        }
    }
    return ""
}

function CheckForDuplicateWebAccount($Result, $settingsDatPath) {
    $tempFileGUID = "1ca6ba83-b806-447b-9498-055599c8de4c"
    $pluginLocation = Split-Path -Parent $settingsDatPath
    $webaccountsPath = "$pluginLocation\..\AC\TokenBroker\Accounts"
    $originalSettingsPath = $settingsDatPath
    $originalSettingsHash = (Get-FileHash -Path $originalSettingsPath).Hash
    $tempRegfilePath = Join-Path $env:TEMP "settings-$tempFileGUID-$originalSettingsHash.reg"

    Write-Host "AAD Plugin Location: $pluginLocation"

    $WebAccounts = New-Object System.Collections.ArrayList($null)
    $webAccountFiles = Get-ChildItem -Path $webaccountsPath -Filter *.tbacct
    foreach($currentWebAccountFile IN $webAccountFiles)
    {
        $WebAccountsTemp =  Get-Content $currentWebAccountFile.FullName -Encoding Unicode| Out-String | ForEach-Object{ConvertFrom-Json -InputObject $_.Substring(0, $_.Length-3)} |
                                    ForEach-Object{New-Object psobject -Property @{
                                                "Id"=$_.TBDataStoreObject.ObjectData.SystemDefinedProperties.Id.Value;
                                                "perUserAccount"=$_.TBDataStoreObject.ObjectData.SystemDefinedProperties.PerUserAccountId.Value;
                                                "accountType" = $_.TBDataStoreObject.ObjectData.SystemDefinedProperties.Scope.Value;
                                                "OID" = $_.TBDataStoreObject.ObjectData.ProviderDefinedProperties | Where-Object{$_.Name -match "OID"} | ForEach-Object{$_.Value};
                                                "UPN" = $_.TBDataStoreObject.ObjectData.ProviderDefinedProperties | Where-Object{$_.Name -match "UPN"} | ForEach-Object{$_.Value};
                                                "fileName" = $currentWebAccountFile.Name.split('.')[0]
                                    }}
            [void]$WebAccounts.Add($WebAccountsTemp)
    }

    # Check for duplicates. Same OID but different WebAccountIDs
    $duplicatesExist = $false
    $perUserWebAccounts = $WebAccounts | Where-Object{$_.accountType -eq "Scope_PerUser"}



    # Case 1: Multiple WAM perUser accounts with same objectID
    $duplicateOIDs = $perUserWebAccounts | Group-Object -Property OID | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name }
    if ($duplicateOIDs) {
        Write-Host "Detected duplicates based on Case 1 criteria."
        $duplicatesExist = $true
    }

    # Case 2: Multiple perApp accounts with same UserName referencing different perUser accounts
    $perAppWebAccounts = $WebAccounts | Where-Object { $_.accountType -eq "Scope_PerApp" }
    $upnWithDuplicates = $perAppWebAccounts | Group-Object -Property @{ Expression = { $_.UPN } } | Where-Object { $_.Count -gt 1 } | ForEach-Object { $_.Name }
    if ($upnWithDuplicates) {
        Write-Host "Detected duplicates based on Case 2 criteria."
        $duplicatesExist = $true
    }

    # Load the registry file contents
    $registryFileContents = Get-Content $tempRegfilePath -ErrorAction SilentlyContinue
    if (!$registryFileContents) {
        Write-Host "Failed to read registry file."
        return
    }
    $registryFileContents = ($registryFileContents -join "`n") -replace '\\\r?\n', '' -replace ',\s+', ',' -split [Environment]::NewLine

    # Case 3: Conflict between OldNewUserIdMapping and UniversalToAccountID
    $oldNewAccountMapping = EnumerateRegistryKey -registryFileContents $registryFileContents -Path "HKLM:\$originalSettingsHash\LocalState\OldNewUserIdMapping" |
    ForEach-Object {
        [pscustomobject]@{
            "OldId" = $_
            "NewId" = GetRegistryValue -registryFileContents $registryFileContents -path "HKLM:\$originalSettingsHash\LocalState\OldNewUserIdMapping" -property $_
        }
    }

    $universalToAccountIDMapping = EnumerateRegistryKey -registryFileContents $registryFileContents -Path "HKLM:\$originalSettingsHash\LocalState\UniversalToAccountID" |
    ForEach-Object {
        [pscustomobject]@{
            "UniversalId" = $_
            "UPNId"       = GetRegistryValue -registryFileContents $registryFileContents -path "HKLM:\$originalSettingsHash\LocalState\UniversalToAccountID" -property $_
        }
    }

    foreach ($universalID in $universalToAccountIDMapping) {
        if ($universalID.UniversalId -eq $universalID.UPNId) {
            foreach ($oldAccountId in $oldNewAccountMapping) {
                if ($oldAccountId.NewId -eq $universalID.UniversalId) {
                    Write-Host "Detected duplicates based on Case 3 criteria."
                    $duplicatesExist = $true
                }
            }
        }
    }

    # Case 4: OldNewUserIdMapping contains old account IDs that no longer exist
    foreach ($oldAccountId in $oldNewAccountMapping) {
        if (-not ($perUserWebAccounts | Where-Object { $_.Id -eq $oldAccountId.OldId })) {
            Write-Host "Detected duplicates based on Case 4 criteria."
            $duplicatesExist = $true
        }
    }

    # Case 5: WAM and container accounts referring to different perUser accounts for same perApp account
    $containerAccounts = EnumerateRegistryKey -registryFileContents $registryFileContents -Path "HKLM:\$originalSettingsHash\LocalState\AccountID" |
    ForEach-Object {
        [pscustomobject]@{
            "Id"            = $_
            "perUserAccount"= GetRegistryValue -registryFileContents $registryFileContents -path "HKLM:\$originalSettingsHash\LocalState\AccountID" -property $_
        }
    }

    foreach ($currentContainerAcc in $containerAccounts) {
        foreach ($currentWebAccount in $WebAccounts) {
            if (($currentContainerAcc.Id -eq $currentWebAccount.Id) -and ($currentContainerAcc.perUserAccount -ne $currentWebAccount.perUserAccount)) {
                Write-Host "Detected duplicates based on Case 5 criteria."
                $duplicatesExist = $true
            }
        }
    }

    # Cleanup temp files
    Write-Host "Removing $tempRegfilePath"
    Remove-Item -Path $tempRegfilePath -Force -ErrorAction SilentlyContinue

    # Set Return variables and exit
    $Result.duplicateExists = $duplicatesExist
}

function Get-UserSID($userProfilePath) {
    $userSID = Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList" |
        Where-Object {
            (Get-ItemProperty -Path $_.PSPath).ProfileImagePath -eq $userProfilePath
        } |
        Select-Object -ExpandProperty PSChildName

    return $userSID
}


function Main {
    $tempFileGUID = "1ca6ba83-b806-447b-9498-055599c8de4c"
    DisplayHeader

    $isVibraniumAndLater = ([System.Environment]::OSVersion.Version).Build -ge 19041
    if ($isVibraniumAndLater) {
        # Stop WAM service
        StopWAMService

        # Process settings.dat from all user profiles
        $userProfiles = Get-ChildItem -Path "$Env:SystemDrive\Users" -Directory | Where-Object {
            $_.Name -notin @('Default', 'Default User', 'Public', 'All Users')
        }

       foreach ($userProfile in $userProfiles) {
    $settingsDatPath = Join-Path $userProfile.FullName "AppData\Local\Packages\Microsoft.AAD.BrokerPlugin_cw5n1h2txyewy\Settings\settings.dat"
    if (Test-Path $settingsDatPath) {
        Write-Host "Processing user profile: $($userProfile.FullName)"

        # Get user SID
        $userSID = Get-UserSID -userProfilePath $userProfile.FullName

        if ($userSID) {
            # Write settings.dat to reg file
            WriteSettingsDatToRegFile -settingsDatPath $settingsDatPath

            # Detection
            $detectionResult = @{ duplicateExists = $false }
            CheckForDuplicateWebAccount -Result $detectionResult -settingsDatPath $settingsDatPath

            if ($detectionResult.duplicateExists) {
                Write-Host "Duplicate WebAccounts detected."
                ResetWAMStateForUser -userProfilePath $userProfile.FullName -userSID $userSID
            } else {
                Write-Host "No duplicate WebAccounts detected."
            }
        } else {
            Write-Host "Could not find SID for user profile: $($userProfile.FullName)"
        }
    } else {
        Write-Host "No AAD WAM WebAccounts found for user profile: $($userProfile.FullName)"
    }
}

        # Cleanup temp files
        $tempFilePath = $env:TEMP
        Remove-Item -Path "$tempFilePath\settings-$tempFileGUID-*" -Force -ErrorAction SilentlyContinue

        # Start WAM service
        StartWAMService
    } else {
        Write-Host "This version of Windows is not affected by the issue addressed by the script."
    }
}

Main @args
