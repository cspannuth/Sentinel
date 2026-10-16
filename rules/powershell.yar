// Original Sentinel heuristics, CC0-1.0. Matches require a command at byte zero.
rule Sentinel_PowerShell_Download_And_Execute {
    meta:
        category = "suspicious"
        description = "PowerShell command combines DownloadString with expression execution; review context"
        version = "1"
        author = "Sentinel"
        license = "CC0-1.0"
    strings:
        $command = /powershell(\.exe)?[ \t]/ nocase
        $download = "DownloadString" nocase
        $execute_short = "IEX" nocase fullword
        $execute_long = "Invoke-Expression" nocase
    condition:
        $command at 0 and $download and any of ($execute_*)
}

rule Sentinel_PowerShell_Encoded_Command {
    meta:
        category = "suspicious"
        description = "PowerShell command uses EncodedCommand; legitimate administration can also match"
        version = "1"
        author = "Sentinel"
        license = "CC0-1.0"
    strings:
        $command = /powershell(\.exe)?[ \t]/ nocase
        $encoded = "-EncodedCommand" nocase fullword
    condition:
        $command at 0 and $encoded
}
