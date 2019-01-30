rule is_pe
{
  meta:
    file_type = "exe"
    file_desc = "winpe"
  condition:
    uint16(0) == 0x5A4D and uint32(0x3C) == 0x4550
}

rule contains_pe
{
  meta:
    file_type = "exe"
    file_desc = "winpe"
  strings:
    $a = "MZ"
  condition:
    for any i in (1..#a):
      (uint32(@a[i] + uint32(@a[i] + 0x3C)) == 0x00004550)
}

rule is_pdf
{
  meta:
    file_type = "pdf"
    file_desc = "annoying documents"
  strings:
    $a = "%PDF"
  condition:
    $a in (0..1024)
}

rule is_apk
{
  meta:
    file_type = "application/vnd.android.package-archive"
    file_desc = "Android Application (APK)"

  strings:
    $manifest = "AndroidManifest.xml"

  condition:
    (uint16(0) == 0x4B50 and $manifest and #manifest >= 2)
}

rule is_zip
{
  meta:
    file_type = ""
    file_desc = ""
  condition:
    uint16(0) == 0x4B50
}

rule is_chm
{
  meta:
    /* Microsoft Windows Compiled Help File */
    file_type = ""
    file_desc = ""
  strings:
    $magic = "ITSF"
  condition:
    $magic at 0
}

rule is_7zip
{
  meta:
    file_type = ""
    file_desc = ""
  condition:
    (uint32be(0x0) == 0x377abcaf and uint16be(0x4) == 0x271c)
}

rule is_java
{
  meta:
    file_type = ""
    file_desc = ""
  strings:
    $magic = /^\x50\x4b\x03\x04/
    $meta = "META-INF/" ascii
    $class = ".class" ascii
  condition:
    ($magic at 0 and ($meta or $class))
}

rule is_flash
{
  meta:
    file_type = ""
    file_desc = ""
  condition:
    (uint16be(0x0) == 0x4357 and uint8(0x2) == 0x53)
    or
    (uint16be(0x0) == 0x4657 and uint8(0x2) == 0x53)
    or
    (uint16be(0x0) == 0x5a57 and uint8(0x2) == 0x53)
}

rule is_macho
{
  meta:
    file_type = ""
    file_desc = ""
  strings:
    $page = "__PAGEZERO" ascii
    $text = "__TEXT" ascii
  condition:
    (
      uint32(0) == 0xfeedface or
      uint32(0) == 0xcefaedfe or
      uint32(0) == 0xfeedfacf or
      uint32(0) == 0xcffaedfe or
      uint32(0) == 0xbebafeca
     ) and $page and $text
}

rule is_elf
{
  meta:
    file_type = ""
    file_desc = ""
  condition:
    uint32(0) == 0x464C457F
}

rule is_lnk
{
  meta:
    file_type = ""
    file_desc = ""
  condition:
    (uint32be(0x0) == 0x4c000000 and uint32be(0x4) == 0x1140200)
}

rule is_lzip
{
  meta:
    file_type = ""
    file_desc = ""
  condition:
    (uint32be(0x0) == 0x4c5a4950)
}

rule is_ole
{
  meta:
    file_type = ""
    file_desc = ""

  strings:
      $magic = { D0 CF 11 E0 A1 B1 1A E1 00 00 00 }
  condition:
    (
      (uint32be(0x0) == 0x504b0304 and uint32be(0x4) == 0x14000600)
    ) or ($magic in (0..1024))
}

rule is_postscript
{
  meta:
    file_type = ""
    file_desc = ""
  condition:
    /* %!PS at 0 */
    (uint32be(0x0) == 0x25215053)
}

rule is_rar
{
  meta:
    file_type = ""
    file_desc = ""
  condition:
    (uint32be(0x0) == 0x52617221 and uint16be(0x4) == 0x1a07)
}

rule is_rtf
{
  meta:
    file_type = ""
    file_desc = ""
  strings:
    $magic = /^\s*{\\rt/
  condition:
    $magic in (0..30)
}

rule is_shellscript
{
  meta:
    file_type = ""
    file_desc = ""
  strings:
    $magic = "#!"
  condition:
    $magic at 0
}

rule is_html
{
  meta:
    file_type = ""
    file_desc = ""
  strings:
    $header0 = /<html\s?(>)?/ nocase
    $header1 = "<!doctype html>" ascii nocase
    $end = /</html\s?(>)?/ nocase
  condition:
    ($header1 in (0..256) or $header2 in (0..256))
    or
    (
      (
        $header1 in (0..256) or $header2 in (0..256)
      )
      and $end
    )
}

rule is_gif
{
  meta:
    file_type = ""
    file_desc = ""
  strings:
    $a = { 47 49 46 }
    $b = { 47 49 46 38 37 61 }
    $c = { 47 49 46 38 39 61 }
  condition:
    ($a at 0 or $b at 0 or $c at 0)
}

rule is_email
{
  meta:
    file_type = ""
    file_desc = ""
  strings:
    $from = "From "
    $recv = "\x0aReceived:"
    $return = "\x0aReturn-Path:"
  condition:
    (
      $from at 0 or
      $recv in (0..2048) or
      $return in (0..2048)
    )
}

rule is_email_with_attachment
{
  meta:
    file_type = ""
    file_desc = ""
  strings:
    $from = "From "
    $recv = "\x0aReceived:"
    $return = "\x0aReturn-Path:"
    $attach = "Content-Disposition: attachment"
  condition:
    (
      $from at 0 or
      $recv in (0..2048) or
      $return in (0..2048)
    ) and $attach
}

rule is_x509
{
  meta:
    file_type = ""
    file_desc = ""
  strings:
    $bytes = {30 82 ?? ?? 30 82 ?? ??}
  condition:
    $bytes
}

