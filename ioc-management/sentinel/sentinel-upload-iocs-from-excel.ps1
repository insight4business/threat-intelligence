# Problem solved : IOCs from intel reports must reach Sentinel.
# What it does    : Reads IOC Excel and creates indicators with expirations.
# Requires        : ImportExcel, Az; Sentinel Contributor
# Effect          : changes-state (review and test before use)
# Known issues    : Variables empty; expiration values like 90d are not valid PowerShell timespans: fix
# Origin          : adapted from field work; replace every ENTRE_AQUI_COM_SEU_* marker with your own value

# Environment variables
$subscriptionId = ""
$resourceGroupName = ""
$workspaceName = ""
$path = "ENTRE_AQUI_COM_SEU_CAMINHO"

# Get table values
$excelTable = Import-Excel -Path $path -StartRow 2 -EndColumn 18

# Standard IOC expiration times
$iocExpiration = [PSCustomObject]@{
    Hash   = 90d
    IPv4   = 90d
    IPv6   = 180d
    URL    = 365d
    Domain = ''
}

# Rest URI
$uriCreateIndicator = "https://management.azure.com/subscriptions/$subscriptionId/resourceGroups/$resourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$workspaceName/providers/Microsoft.SecurityInsights/threatIntelligence/main/createIndicator?api-version=2022-07-01-preview"

foreach ($row in $excelTable) {
    $iocObject = [PSCustomObject]@{
        incidentNumber = if ($null -ne $row.'Incident number') { @(([string]($row.'Incident number')).Split(';')) } else { @("") }
        source         = if ($null -ne $row.'Source') { $row.'Source' } else { @("") }
        name           = if ($null -ne $row.'IOC Name' ) { $row.'IOC Name' } else { @("") }
        type           = if ($null -ne $row.'IOC Type') { $row.'IOC Type' } else { @("") }
        confidence     = if ($null -ne $row.'Score') { $row.'Score' } else { 0 }
        IOC            = if ($null -ne $row.'IOC') { $row.'IOC' } else { @("") }
        relatedEmail   = if ($null -ne $row.'Relations - Email') { $row.'Relations - Email' } else { @("") }
        relatedIp      = if ($null -ne $row.'Relations - IP') { $row.'Relations - IP' } else { @("") }
        relatedDomain  = if ($null -ne $row.'Relations - Domain') { $row.'Relations - Domain' } else { @("") }
        date           = if ($null -ne $row.'Date') { $row.'Date' } else { @("") }
        category       = if ($null -ne $row.'Category') { @(($row.'Category').Split(';')) } else { @("") }
    }

    # Write-Host $iocObject # -ForegroundColor Cyan

    # # Get user context and authorization
    # $azContext = Get-AzContext
    # $azProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    # $profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($azProfile)
    # $token = $profileClient.AcquireAccessToken($azContext.Subscription.TenantId)
    # $authHeader = @{
    #     'Content-Type'  = 'application/json'
    #     'Authorization' = 'Bearer ' + $token.AccessToken
    # }

    # Define start and end date for the IOC
    $validFrom = if ("" -ne $iocObject.date) { $iocObject.date } else { "" }
    $validUntil = if ("" -ne $validFrom ) { $validFrom.AddDays($iocExpiration.$($iocObject.type)) } else { "" }

    # URI Request body
    $requestBody = @{
        kind       = "indicator"
        properties = @{
            source                 = $iocObject.source
            threatIntelligenceTags = $iocObject.category
            displayName            = $iocObject.name
            confidence             = $iocObject.confidence
            createdByRef           = ""
            description            = ""
            # threatTypes = ["compromised"]
            patternType            = $iocObject.type
            pattern                = "[$($iocObject.type):value = '$($iocObject.IOC)']"
            # 'RelatedEmail' = $iocObject.relatedEmail
            # 'RelatedIp' = $iocObject.relatedIp
            # 'RelatedDomain' = $iocObject.relatedDomain
            validFrom              = $validFrom
            validUntil             = $validUntil
        }
    }

    # Write-Output "$($requestBody.properties)"
    $requestBody.properties | Out-String
    
    # # Invoke the REST API
    # $response = Invoke-RestMethod -Uri $uriCreateIndicator -Method Post -Headers $authHeader -Body $requestBody
}