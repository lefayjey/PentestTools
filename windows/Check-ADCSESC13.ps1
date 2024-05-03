<#
Prints OIDs and certificate templates that may be used in an ADCS ESC13 abuse

The script will check for:
1. OIDs with non-default ownership
2. OIDs with non-default ACE
3. OIDs linked to a group
4. Certificate templates configured with OID linked to a group
#>

Import-Module ActiveDirectory

# Get OIDs and certificate templates with msPKI-Certificate-Policy
$ADRootDSE = Get-ADRootDSE
$ConfigurationNC = $ADRootDSE.configurationNamingContext
$OIDContainer = "CN=OID,CN=Public Key Services,CN=Services,$ConfigurationNC"
$TemplateContainer = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigurationNC"
$OIDs = Get-ADObject -Filter * -SearchBase $OIDContainer -Properties DisplayName,Name,msPKI-Cert-Template-OID,msDS-OIDToGroupLink,nTSecurityDescriptor
$Templates = Get-ADObject -Filter * -SearchBase $TemplateContainer -Properties msPKI-Certificate-Policy | ? {$_."msPKI-Certificate-Policy"} | select name,msPKI-Certificate-Policy

if ($OIDs) {

    Write-Host "Enumerating OIDs"
    Write-Host "------------------------"

    # Iterate through each OID
    foreach ($OID in $OIDs) {

        if ($OID."msDS-OIDToGroupLink") {
            Write-Host "OID $($OID.Name) links to group: $($OID."msDS-OIDToGroupLink")`r`n"
            Write-Host "OID DisplayName: $($OID."msPKI-Cert-Template-OID")"
            Write-Host "OID DistinguishedName: $($OID."DistinguishedName")"
            Write-Host "OID msPKI-Cert-Template-OID: $($OID."msPKI-Cert-Template-OID")"
            Write-Host "OID msDS-OIDToGroupLink: $($OID."msDS-OIDToGroupLink")"
            Write-Host "------------------------"
        }

        if ($OID.nTSecurityDescriptor.Owner -notlike "*\Enterprise Admins") {
            Write-Host "OID $($OID.Name) has non-default owner: $($OID.nTSecurityDescriptor.Owner)`r`n"
            Write-Host "OID DisplayName: $($OID."msPKI-Cert-Template-OID")"
            Write-Host "OID DistinguishedName: $($OID."DistinguishedName")"
            Write-Host "OID msPKI-Cert-Template-OID: $($OID."msPKI-Cert-Template-OID")"
            Write-Host "------------------------"        
        }

        $ACEs = $OID.nTSecurityDescriptor.Access
        foreach ($ACE in $ACEs) {
            if ($ACE.IdentityReference -like "*\Domain Admins" -or $ACE.IdentityReference -like "*\Enterprise Admins" -or $ACE.IdentityReference -like "*\SYSTEM") {
                continue
            } elseif ($ACE.IdentityReference -like "*\Authenticated Users" -and $ACE.ActiveDirectoryRights -eq "GenericRead") {
                continue
            } else {
                Write-Host "OID $($OID.Name) has non-default ACE:"
                Write-Output $ACE
                Write-Host "OID DisplayName: $($OID."msPKI-Cert-Template-OID")"
                Write-Host "OID DistinguishedName: $($OID."DistinguishedName")"
                Write-Host "OID msPKI-Cert-Template-OID: $($OID."msPKI-Cert-Template-OID")"
                Write-Host "------------------------"        
            }
        }
    }

    Write-Host "Enumerating certificate templates"
    Write-Host "------------------------"

    # Iterate through each template
    foreach ($Template in $Templates) {

        # Check if the Template OID matches any OID in the list
        $MatchingOID = $OIDs | ? { $_."msDS-OIDToGroupLink" -and $Template."msPKI-Certificate-Policy" -contains $_."msPKI-Cert-Template-OID" }

        if ($MatchingOID) {
            Write-Host "Certificate template $($Template.Name) may be used to obtain membership of $($MatchingOID."msDS-OIDToGroupLink")`r`n"
            Write-Host "Certificate template Name: $($Template.Name)"
            Write-Host "OID DisplayName: $($MatchingOID."msPKI-Cert-Template-OID")"
            Write-Host "OID DistinguishedName: $($MatchingOID."DistinguishedName")"
            Write-Host "OID msPKI-Cert-Template-OID: $($MatchingOID."msPKI-Cert-Template-OID")"
            Write-Host "OID msDS-OIDToGroupLink: $($MatchingOID."msDS-OIDToGroupLink")"
            Write-Host "------------------------"
        }
    }
    Write-Host "Done"
} else {
    Write-Host "Error: No OIDs were found."
}
