// Selected rule excerpts copied from Neo23x0/signature-base public source pages.
// Retrieved on 2026-10-15. Formatting normalized; detection logic unchanged.
// Source URLs, scope and licensing are documented in ../THIRD_PARTY.md.
// Licensed under Detection Rule License 1.1: ../licenses/DRL-1.1.txt.
// This reference file is not loaded at runtime.

// https://github.com/Neo23x0/signature-base/blob/master/yara/crime_wannacry.yar
rule WannaCry_Ransomware_Gen {
    meta:
        description = "Detects WannaCry Ransomware"
        author = "Florian Roth (Nextron Systems) (based on rule by US CERT)"
        reference = "https://www.us-cert.gov/ncas/alerts/TA17-132A"
        date = "2017-05-12"
        hash1 = "9fe91d542952e145f2244572f314632d93eb1e8657621087b2ca7f7df2b0cb05"
        hash2 = "8e5b5841a3fe81cade259ce2a678ccb4451725bba71f6662d0cc1f08148da8df"
        hash3 = "4384bf4530fb2e35449a8e01c7e0ad94e3a25811ba94f7847c1e6612bbb45359"
        id = "d28d3d76-9c24-5476-9a0c-936c17477d6a"
    strings:
        $s1 = "__TREEID__PLACEHOLDER__" ascii
        $s2 = "__USERID__PLACEHOLDER__" ascii
        $s3 = "Windows for Workgroups 3.1a" fullword ascii
        $s4 = "PC NETWORK PROGRAM 1.0" fullword ascii
        $s5 = "LANMAN1.0" fullword ascii
    condition:
        uint16(0) == 0x5a4d and filesize < 5000KB and all of them
}

rule WannCry_m_vbs {
    meta:
        description = "Detects WannaCry Ransomware VBS"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Florian Roth (Nextron Systems)"
        reference = "https://goo.gl/HG2j5T"
        date = "2017-05-12"
        hash1 = "51432d3196d9b78bdc9867a77d601caffd4adaa66dcac944a5ba0b3112bbea3b"
        id = "a8f13bd2-984d-5c8c-ac53-7d442e222850"
    strings:
        $x1 = ".TargetPath = \"C:\\@" ascii
        $x2 = ".CreateShortcut(\"C:\\@" ascii
        $s3 = " = WScript.CreateObject(\"WScript.Shell\")" ascii
    condition:
        ( uint16(0) == 0x4553 and filesize < 1KB and all of them )
}

rule WannCry_BAT {
    meta:
        description = "Detects WannaCry Ransomware BATCH File"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Florian Roth (Nextron Systems)"
        reference = "https://goo.gl/HG2j5T"
        date = "2017-05-12"
        hash1 = "f01b7f52e3cb64f01ddc248eb6ae871775ef7cb4297eba5d230d0345af9a5077"
        id = "0929f0de-28ac-5534-a6fd-7b131abda011"
    strings:
        $s1 = "@.exe\">> m.vbs" ascii
        $s2 = "cscript.exe //nologo m.vbs" fullword ascii
        $s3 = "echo SET ow = WScript.CreateObject(\"WScript.Shell\")> " ascii
        $s4 = "echo om.Save>> m.vbs" fullword ascii
    condition:
        ( uint16(0) == 0x6540 and filesize < 1KB and 1 of them )
}

rule WannaCry_RansomNote {
    meta:
        description = "Detects WannaCry Ransomware Note"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Florian Roth (Nextron Systems)"
        reference = "https://goo.gl/HG2j5T"
        date = "2017-05-12"
        hash1 = "4a25d98c121bb3bd5b54e0b6a5348f7b09966bffeec30776e5a731813f05d49e"
        id = "65ce8faf-0981-5382-bc15-f094ccaa9f54"
    strings:
        $s1 = "A: Don't worry about decryption." fullword ascii
        $s2 = "Q: What's wrong with my files?" fullword ascii
    condition:
        ( uint16(0) == 0x3a51 and filesize < 2KB and all of them )
}

// https://github.com/Neo23x0/signature-base/blob/master/yara/apt_apt27_hyperbro.yar
rule HvS_APT27_HyperBro_Stage3 {
    meta:
        description = "HyperBro Stage 3 detection - also tested in memory"
        license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
        author = "Markus Poelloth"
        reference = "https://www.hvs-consulting.de/en/threat-intelligence-report-emissary-panda-apt27"
        date = "2022-02-07"
        modified = "2023-01-07"
        hash1 = "624e85bd669b97bc55ed5c5ea5f6082a1d4900d235a5d2e2a5683a04e36213e8"
        id = "b4002777-f129-5177-a8f1-690012a207fa"
    strings:
        $s1 = "\\cmd.exe /A" wide
        $s2 = "vftrace.dll" fullword wide
        $s3 = "msmpeng.exe" fullword wide
        $s4 = "\\\\.\\pipe\\testpipe" fullword wide
        $s5 = "thumb.dat" fullword wide
        $g1 = "%s\\%d.exe" fullword wide
        $g2 = "https://%s:%d/api/v2/ajax" fullword wide
        $g3 = " -k networkservice" fullword wide
        $g4 = " -k localservice" fullword wide
    condition:
        uint16(0) == 0x5a4d and filesize < 300KB and (( 4 of ($s*) ) or (4 of ($g*)))
}

// https://github.com/Neo23x0/signature-base/blob/master/yara/apt_alienspy_rat.yar
rule crime_win_rat_AlienSpy {
    meta:
        description = "Alien Spy Remote Access Trojan"
        author = "General Dynamics Fidelis Cybersecurity Solutions - Threat Research Team"
        reference_1 = "www.fidelissecurity.com/sites/default/files/FTA_1015_Alienspy_FINAL.pdf"
        reference_2 = "www.fidelissecurity.com/sites/default/files/AlienSpy-Configs2_1_2.csv"
        date = "04-Apr-15"
        filetype = "Java"
        hash_1 = "075fa0567d3415fbab3514b8aa64cfcb"
        hash_2 = "818afea3040a887f191ee9d0579ac6ed"
        hash_3 = "973de705f2f01e82c00db92eaa27912c"
        hash_4 = "7f838907f9cc8305544bd0ad4cfd278e"
        hash_5 = "071e12454731161d47a12a8c4b3adfea"
        hash_6 = "a7d50760d49faff3656903c1130fd20b"
        hash_7 = "f399afb901fcdf436a1b2a135da3ee39"
        hash_8 = "3698a3630f80a632c0c7c12e929184fb"
        hash_9 = "fdb674cadfa038ff9d931e376f89f1b6"
        id = "a79789cd-9b16-58f5-ab51-48bb900583d1"
    strings:
        $sa_1 = "META-INF/MANIFEST.MF"
        $sa_2 = "Main.classPK"
        $sa_3 = "plugins/Server.classPK"
        $sa_4 = "IDPK"
        $sb_1 = "config.iniPK"
        $sb_2 = "password.iniPK"
        $sb_3 = "plugins/Server.classPK"
        $sb_4 = "LoadStub.classPK"
        $sb_5 = "LoadStubDecrypted.classPK"
        $sb_7 = "LoadPassword.classPK"
        $sb_8 = "DecryptStub.classPK"
        $sb_9 = "ClassLoaders.classPK"
        $sc_1 = "config.xml"
        $sc_2 = "options"
        $sc_3 = "plugins"
        /* $sc_4 = "util" */
        $sc_5 = "util/OSHelper"
        $sc_6 = "Start.class"
        $sc_7 = "AlienSpy"
        /* $sc_8 = "PK" */ /* too short atom - disabled for performance reasons */
    condition:
        uint16(0) == 0x4B50 and filesize < 800KB and ( (all of ($sa_*)) or (all of ($sb_*)) or (all of ($sc_*)) )
}
