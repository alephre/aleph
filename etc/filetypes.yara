rule is_pe
{
    meta:
        file_type = "exe"
        file_desc = "winpe"
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 
}

rule is_pdf
{
    meta:
        file_type = "pdf"
        file_desc = "annoying documents"
    strings:
        $a = "%PDF-"
    condition:
        $a in (0..60)
}

rule is_apk
{
  meta:
    file_type = "application/vnd.android.package-archive"
    file_desc = "Android Application (APK)"

  strings:
    $zip_head = "PK"
    $manifest = "AndroidManifest.xml"

  condition:
    $zip_head at 0 and $manifest and #manifest >= 2
}
