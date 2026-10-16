// Harmless pipeline check, not a malware indicator. Original Sentinel, CC0-1.0.
rule Sentinel_Benign_Test {
    meta:
        category = "test"
        description = "Exact harmless Sentinel test marker; this is not a malware detection"
        version = "1"
        author = "Sentinel"
        license = "CC0-1.0"
    strings:
        $marker = "SENTINEL_TEST_SIGNATURE"
    condition:
        filesize == 23 and $marker at 0
}
