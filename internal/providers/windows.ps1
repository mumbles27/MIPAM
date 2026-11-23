$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Console]::InputEncoding = [Text.UTF8Encoding]::new($false)
[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)
try {
    $envelope = [Console]::In.ReadToEnd() | ConvertFrom-Json
    $r = $envelope.request
    $server = [string]$envelope.server
    function Read-Objects {
        switch ($r.kind) {
            'dns' {
                $items = @(Get-DnsServerResourceRecord -ComputerName $server -ZoneName $r.zone)
                if ($r.name) { $items = @($items | Where-Object { $_.HostName -eq $r.name }) }
                if ($r.type) { $items = @($items | Where-Object { $_.RecordType -eq $r.type }) }
                return @($items | Sort-Object HostName,RecordType | ForEach-Object {
                    $content = switch ($_.RecordType) {
                        'A' { $_.RecordData.IPv4Address.IPAddressToString }
                        'AAAA' { $_.RecordData.IPv6Address.IPAddressToString }
                        'CNAME' { $_.RecordData.HostNameAlias }
                        'PTR' { $_.RecordData.PtrDomainName }
                        default { $_.RecordData | ConvertTo-Json -Compress -Depth 5 }
                    }
                    [pscustomobject]@{ name=$_.HostName; type=$_.RecordType; content=$content; ttl=[int]$_.TimeToLive.TotalSeconds }
                })
            }
            'scope' {
                $items = @(Get-DhcpServerv4Scope -ComputerName $server)
                if ($r.scope_id) { $items = @($items | Where-Object { $_.ScopeId.IPAddressToString -eq $r.scope_id }) }
                return @($items | Sort-Object ScopeId | ForEach-Object {
                    [pscustomobject]@{ scope_id=$_.ScopeId.IPAddressToString; name=$_.Name; mask=$_.SubnetMask.IPAddressToString; start=$_.StartRange.IPAddressToString; end=$_.EndRange.IPAddressToString; state=[string]$_.State }
                })
            }
            'reservation' {
                $items = @(Get-DhcpServerv4Reservation -ComputerName $server -ScopeId $r.scope_id)
                if ($r.ip) { $items = @($items | Where-Object { $_.IPAddress.IPAddressToString -eq $r.ip }) }
                return @($items | Sort-Object IPAddress | ForEach-Object {
                    [pscustomobject]@{ ip=$_.IPAddress.IPAddressToString; mac=$_.ClientId; name=$_.Name; scope_id=$r.scope_id; state='reserved' }
                })
            }
            'lease' {
                return @(Get-DhcpServerv4Lease -ComputerName $server -ScopeId $r.scope_id | Sort-Object IPAddress | ForEach-Object {
                    [pscustomobject]@{ ip=$_.IPAddress.IPAddressToString; mac=$_.ClientId; hostname=$_.HostName; state=[string]$_.AddressState; expires=$_.LeaseExpiryTime.ToUniversalTime().ToString('o'); scope_id=$r.scope_id }
                })
            }
            'ad-computer' {
                return @(Get-ADComputer -Server $server -Filter * -ResultSetSize 1000 -Properties DNSHostName,OperatingSystem,LastLogonDate |
                    Select-Object Name,DNSHostName,OperatingSystem,LastLogonDate,Enabled,DistinguishedName)
            }
            default { throw 'Unsupported kind' }
        }
    }
    switch ($r.kind) {
        'dns' { Import-Module DnsServer }
        'ad-computer' { Import-Module ActiveDirectory }
        default { Import-Module DhcpServer }
    }
    $before = @(Read-Objects)
    if ($r.action -ne 'read') {
        switch ($r.kind) {
            'dns' {
                if ($r.type -notin @('A','AAAA','CNAME','PTR')) { throw 'Unsupported Windows DNS write type' }
                if ($r.action -eq 'create' -and $before.Count -ne 0) { throw 'Record exists' }
                if ($r.action -ne 'create' -and $before.Count -ne 1) { throw 'Exactly one record required' }
                $common = @{ ComputerName=$server; ZoneName=$r.zone; Name=$r.name; TimeToLive=[TimeSpan]::FromSeconds($r.ttl) }
                switch ($r.action) {
                    'create' {
                        switch ($r.type) {
                            'A' { Add-DnsServerResourceRecordA @common -IPv4Address $r.content }
                            'AAAA' { Add-DnsServerResourceRecordAAAA @common -IPv6Address $r.content }
                            'CNAME' { Add-DnsServerResourceRecordCName @common -HostNameAlias $r.content }
                            'PTR' { Add-DnsServerResourceRecordPtr @common -PtrDomainName $r.content }
                        }
                    }
                    'update' {
                        $old = Get-DnsServerResourceRecord -ComputerName $server -ZoneName $r.zone -Name $r.name -RRType $r.type
                        $new = [ciminstance]::new($old)
                        $new.TimeToLive = [TimeSpan]::FromSeconds($r.ttl)
                        switch ($r.type) {
                            'A' { $new.RecordData.IPv4Address = [Net.IPAddress]::Parse($r.content) }
                            'AAAA' { $new.RecordData.IPv6Address = [Net.IPAddress]::Parse($r.content) }
                            'CNAME' { $new.RecordData.HostNameAlias = $r.content }
                            'PTR' { $new.RecordData.PtrDomainName = $r.content }
                        }
                        Set-DnsServerResourceRecord -ComputerName $server -ZoneName $r.zone -OldInputObject $old -NewInputObject $new
                    }
                    'delete' {
                        $old = Get-DnsServerResourceRecord -ComputerName $server -ZoneName $r.zone -Name $r.name -RRType $r.type
                        Remove-DnsServerResourceRecord -ComputerName $server -ZoneName $r.zone -InputObject $old -Force
                    }
                    default { throw 'Unsupported action' }
                }
            }
            'scope' {
                if ($r.action -ne 'create' -and $before.Count -ne 1) { throw 'Exactly one in-scope object required' }
                switch ($r.action) {
                    'create' {
                        if ($before.Count -ne 0) { throw 'Scope exists; scope_id must identify new scope' }
                        Add-DhcpServerv4Scope -ComputerName $server -Name $r.name -StartRange $r.start -EndRange $r.end -SubnetMask $envelope.mask -State InActive
                    }
                    'update' { Set-DhcpServerv4Scope -ComputerName $server -ScopeId $r.scope_id -Name $r.name }
                    'delete' { Remove-DhcpServerv4Scope -ComputerName $server -ScopeId $r.scope_id -Force }
                    default { throw 'Unsupported action' }
                }
            }
            'reservation' {
                if ($r.action -ne 'create' -and $before.Count -ne 1) { throw 'Exactly one in-scope reservation required' }
                switch ($r.action) {
                    'create' {
                        if ($before.Count -ne 0) { throw 'Reservation exists' }
                        Add-DhcpServerv4Reservation -ComputerName $server -ScopeId $r.scope_id -IPAddress $r.ip -ClientId $r.mac -Name $r.name
                    }
                    'update' { Set-DhcpServerv4Reservation -ComputerName $server -IPAddress $r.ip -ClientId $r.mac -Name $r.name }
                    'delete' { Remove-DhcpServerv4Reservation -ComputerName $server -IPAddress $r.ip }
                    default { throw 'Unsupported action' }
                }
            }
            default { throw 'Resource is read-only' }
        }
        $after = @(Read-Objects)
        if ($r.action -eq 'delete') {
            if ($after.Count -ne 0) { throw 'Delete verification failed' }
        } else {
            if ($after.Count -ne 1) { throw 'Write verification failed' }
            if ($r.kind -eq 'dns' -and ($after[0].content.TrimEnd('.') -ne $r.content.TrimEnd('.') -or $after[0].ttl -ne $r.ttl)) { throw 'DNS verification mismatch' }
            if ($r.kind -eq 'reservation' -and (($after[0].mac -replace '[:-]','') -ne ($r.mac -replace '[:-]',''))) { throw 'Reservation verification mismatch' }
            if ($r.kind -eq 'scope' -and $after[0].name -ne $r.name) { throw 'Scope verification mismatch' }
        }
        ConvertTo-Json -InputObject @($after) -Depth 8 -Compress
    } else {
        ConvertTo-Json -InputObject @($before) -Depth 8 -Compress
    }
} catch {
    [Console]::Error.WriteLine('MIPAM management operation failed: ' + $_.Exception.GetType().Name)
    exit 1
}
