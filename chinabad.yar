rule APT41_ShadowPad_Loader
{
    meta:
        description = "Detects ShadowPad loader used by APT41"
        author = "Ju$tC4llM3Fr3d"
        reference = "https://www.mandiant.com"
        actor = "APT41"
        date = "2025-05-22"

    strings:
        $str1 = "ShadowPad" ascii wide
        $str2 = ".key" ascii
        $str3 = { 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? E8 ?? ?? ?? ?? }
        $c2 = /[a-z0-9]{10,15}\.com/

    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule APT27_Gh0stRAT
{
    meta:
        description = "Detects Gh0stRAT variant used by APT27"
        author = "Ju$tC4llM3Fr3d"
        actor = "APT27"
        date = "2025-05-22"

    strings:
        $gh0st1 = "gh0st" ascii
        $gh0st2 = "njrat" ascii
        $mutex = "Gh0stRAT-Mutex"
        $cfg = { 47 68 30 73 74 }

    condition:
        uint16(0) == 0x5A4D and 2 of ($gh0st*)
}

rule VoltTyphoon_LOLBins
{
    meta:
        description = "Volt Typhoon living-off-the-land binaries usage"
        author = "Ju$tC4llM3Fr3d"
        actor = "Volt Typhoon"
        date = "2025-05-22"

    strings:
        $s1 = "netsh advfirewall"
        $s2 = "sc config"
        $s3 = "reg add"
        $s4 = "cmd /c whoami"
        $s5 = "ping -n" ascii

    condition:
        2 of them
}

rule Encoded_PowerShell
{
    meta:
        description = "Detects encoded PowerShell payloads"
        author = "Ju$tC4llM3Fr3d"
        date = "2025-05-22"

    strings:
        $b64 = /powershell.*-EncodedCommand/i
        $enc = /[A-Za-z0-9+/]{200,}/

    condition:
        $b64 and $enc
}

rule Persistence_AppInit_DLLs
{
    meta:
        description = "Detects usage of AppInit_DLLs for persistence"
        author = "Ju$tC4llM3Fr3d"
        date = "2025-05-22"

    strings:
        $dll = "AppInit_DLLs" ascii wide
        $regpath = "Software\Microsoft\Windows NT\CurrentVersion\Windows"

    condition:
        all of them
}
