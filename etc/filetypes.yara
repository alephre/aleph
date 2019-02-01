/* Android APK & Related **/
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

rule is_dex
{
  meta:
    file_meta = "application/vnd.android.dalvik-executable"
    file_desc = "Compiled Android application code file (DEX/ODEX)"

  strings:
    $dex = { 64 65 78 0A 30 33 ?? 00 }
    $odex = { 64 65 79 0A 30 33 ?? 00 }

  condition:
    $dex at 0 or
    $odex at 0
}
