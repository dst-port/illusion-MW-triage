/* Simple YARA placeholder for high-entropy sections or UPX packer markers */
rule Possibly_Upx_packed
{
    meta:
        author = "illusion-sandbox"
        description = "Detect UPX markers or high-entropy section signatures"
        date = "2026-06-08"
    strings:
        $upx1 = "UPX0" nocase
        $upx2 = "UPX1" nocase
        $upx3 = "UPX" wide
    condition:
        any of them
}

rule HighEntropySection
{
    meta:
        author = "illusion-sandbox"
        description = "Placeholder: use real entropy checks in analyzer"
    condition:
        uint16(0) == 0x5A4D /* PE MZ header example - placeholder */
}
