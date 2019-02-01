import "pe"

/* Android APK & Related **/
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


/* Microsoft Executables & Related Windows files */
rule is_pe
{
  meta:
    file_type = "exe"
    file_desc = "winpe"

  condition:
    uint16(0) == 0x5A4D and uint32(0x3C) == 0x4550
}

rule is_upx_packed_pe
{
  meta:
    file_type = "exe"
    file_type = "winpe"

  condition:
    (pe.sections[0].name == "UPX0" and pe.sections[1].name == "UPX1")

}


rule is_signed_pe
{
  meta:
    file_type = "exe"
    file_desc = "winpe"

  condition:
    /* Triggers if an authenicode signature exists in PE file */
    pe.number_of_signatures > 0
}


rule is_pyinstaller_pe
{
  meta:
    file_type = "pe"
    file_desc = "winpe"

  strings:
    $a = "pyi-windows-manifest-filename"

  condition:
    pe.number_of_resources > 0 and $a
}


rule is_embedded_pe
{
  meta:
    file_type = "exe"
    file_desc = "winpe"

  strings:
    $mz = { 4D 5A }

  condition:
    for any i in (1..#mz):
    (
      uint32(@mz[i] + uint32(@mz[i] + 0x3C)) == 0x00004550
    )
}


rule is_pe_without_dosmod_header
{
  meta:
    file_type = "exe"
    file_desc = "winpe"

  strings:
    $dosmode = "This program cannot be run in DOS mode."

  condition:
    /*
      (0 .. (uint32(0x3C))) = between end of MZ and start of PE headers
      0x3C = e_lfanew = offset of PE header
    */
    (uint16(0) == 0x5A4D and uint32(0x3C) == 0x4550)
    and not $dosmode in (0x3C .. (uint32(0x3C)))
}


rule is_dotnet_executable
{
  meta:
    file_type = "exe"
    file_desc = "winpe"

  strings:
    $a = {FF 25 00 20 40 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00}
  condition:
    $a at pe.entry_point
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


rule is_pdf_with_embedded_iqy
{
  meta:
    file_type = "pdf"
    file_desc = ""

  strings:
    $pdf_magic = "%PDF"
    $efile = /<<\/JavaScript [^\x3e]+\/EmbeddedFile/
    $fspec = /<<\/Type\/Filespec\/F\(\w+\.iqy\)\/UF\(\w+\.iqy\)/
    $openaction = /OpenAction<<\/S\/JavaScript\/JS\(/

   condition:
      $pdf_magic in (0..60)  and all of them
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


rule is_lnk
{
  meta:
    file_type = ""
    file_desc = ""

  condition:
    (uint32be(0x0) == 0x4c000000 and uint32be(0x4) == 0x1140200)
}


rule is_cab
{
  meta:
    file_type = ""
    file_desc = ""

  strings:
    $magic = {4D 53 43 46}

  condition:
    $magic at 0
}


rule is_ole
{
  meta:
    file_type = ""
    file_desc = ""

  strings:
      /* Will catch doc, docx, xls, xlsx, etc. */
      $magic = { D0 CF 11 E0 A1 B1 1A E1 00 00 00 }

  condition:
    (
      (uint32be(0x0) == 0x504b0304 and uint32be(0x4) == 0x14000600)
    ) or ($magic in (0..1024))
}


rule is_encrypted_ole
{
  meta:
    file_type = ""
    file_desc = ""

  strings:
    $str0 = "Microsoft Base Cryptography Provider v" wide
    $str1 = "EncryptedSummary" wide
    $magic = { D0 CF 11 E0 A1 B1 1A E1 00 00 00 }

  condition:
    (
      (
        (uint32be(0x0) == 0x504b0304 and uint32be(0x4) == 0x14000600)
      ) or ($magic in (0..1024))
      and 1 of ($str*)
    )
}


rule is_ole_with_embedded_flash
{
  meta:
    file_type = ""
    file_desc = ""

  strings:
      $a = { 6e db 7c d2 6d ae cf 11 96 b8 44 45 53 54 00 00 }
      $b = { 57 53 }

  condition:
    $a and $b
}


rule is_office_open_xml
{
  meta:
    file_type = ""
    file_desc = ""

  strings:
    /* Office Open XML format. Commonly seen in modern office files. */
    $ctype = "[Content_Types].xml"

  condition:
    $ctype at 30
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

rule is_iqy
{
  meta:
    file_type = ""
    file_desc = ""

  strings:
    /*
      IQY and SLK files have been used lately to spread malware in spam emails
      Catching them with this YARA rule will let us pull out URLs from them, which
      is typically the malware delivery URL
    */
    $magic = /^[ \t]*WEB[ \t]*(\x0A|\x0D\x0A)/ nocase

  condition:
    $magic at 0
}


rule is_slk
{
  meta:
    file_type = ""
    file_desc = ""

  strings:
    /*
      IQY and SLK files have been used lately to spread malware in spam emails
      Catching them with this YARA rule will let us pull out URLs from them, which
      is typically the malware delivery URL
    */
    $magic = "ID;P"

  condition:
    $magic at 0
}


/* Archive formats */
rule is_zip
{
  meta:
    file_type = ""
    file_desc = ""

  condition:
    uint16(0) == 0x4B50
}


rule is_lzip
{
  meta:
    file_type = ""
    file_desc = ""

  condition:
    (uint32be(0x0) == 0x4c5a4950)
}


rule is_lzx
{
  meta:
    file_type = ""
    file_desc = ""

  strings:
    $magic0 = {1F 9D}
    $magic1 = {1F A0}
    $magic2 = {1F 8B}

  condition:
    $magic0 at 0 or $magic1 at 0 or $magic2 at 0
}


rule is_7zip
{
  meta:
    file_type = ""
    file_desc = ""

  condition:
    (uint32be(0x0) == 0x377abcaf and uint16be(0x4) == 0x271c)
}


rule is_rar
{
  meta:
    file_type = ""
    file_desc = ""

  strings:
    $a = {52 61 72 21 1A 07 00}
    $b = {52 61 72 21 1A 07 01 00}

  condition:
    $a at 0 or $b at 0
}


rule is_deb
{
  meta:
    file_type = ""
    file_desc = ""

  strings:
    /* Debian archives (.deb) */
    $magic = {21 3C 61 72 63 68 3E}

  condition:
    $magic at 0
}


rule is_tar
{
  meta:
    file_type = ""
    file_desc = ""

  strings:
    $a = {75 73 74 61 72 00 30 30}
    $b = {75 73 74 61 72 20 20 00}

  condition:
    $a at 0 or $b at 0
}


rule is_ace_with_embedded_exe
{
  meta:
    file_type = ""
    file_desc = ""

  strings:
    $header = { 2a 2a 41 43 45 2a 2a }

    $ext0 = ".exe" nocase
    $ext1 = ".scr" nocase

  condition:
    $header at 7 and
    for any of ($ext*):
    (
        $ in (81..(81+uint16(79)))
    )
}


/* Java formats */
rule is_java_jar
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


rule is_java_class
{
  meta:
    file_type = ""
    file_desc = ""

  strings:
    $class = { CA FE BA BE }
    /* Remove false positives on macOS files */
    $page = "__PAGEZERO" ascii
    $text = "__TEXT" ascii

   condition:
      $class at 0 and not $page and not $text
}


/* Flash files */
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


/* macOS */
rule is_apple_macho
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

rule is_apple_plist
{
  meta:
    file_type = ""
    file_desc = ""

  strings:
    $a = { 62 70 6c 69 73 74 30 30 }

  condition:
    $a at 0
}


rule is_apple_dylib
{
  meta:
    file_type = ""
    file_desc = ""

  strings:
    $a = { cf fa ed fe 0c 00 00 01 }

    condition:
      $a at 0
}


rule is_apple_bom
{
  meta:
    file_type = ""
    file_desc = ""

  strings:
    $a = { 42 4f 4d 53 74 6f 72 65 }

  condition:
    $a at 0
}


rule is_apple_nib
{
  meta:
    file_type = ""
    file_desc = ""

  strings:
    $a = { 4e 49 42 41 72 63 68 69 76 65 01 }

  condition:
    $a at 0
}


/* Linux executables */
rule is_linux_elf
{
  meta:
    file_type = ""
    file_desc = ""

  condition:
    uint32(0) == 0x464C457F
}


/* Scripting */

rule is_shellscript
{
  meta:
    file_type = ""
    file_desc = ""

  strings:
    $magic = "#!"
    // catch /bin/*sh (bash, zsh, fsh, sh, )
    $interps = /\/bin\/(\w+)?sh/

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

rule is_html_with_encoded_pe
{
  meta:
    file_type = ""
    file_desc = ""

  strings:
    $header0 = /<html\s?(>)?/ nocase
    $header1 = "<!doctype html>" ascii nocase
    $end = /</html\s?(>)?/ nocase

    $mz = "4d5a"  ascii nocase // MZ header constant
    $pe = "50450000" ascii nocase // PE header constant

    condition:
      (
        ($header1 in (0..256) or $header2 in (0..256))
        or
        ($header1 in (0..256) or $header2 in (0..256))
      )
      and $pe in (@mz[1] .. filesize)
}


/* Images */
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


rule is_webshell_as_gif
{
  meta:
    file_type = ""
    file_desc = ""

  strings:
    $a = { 47 49 46 }
    $b = { 47 49 46 38 37 61 }
    $c = { 47 49 46 38 39 61 }

    $s0 = "input type"
    $s1 = "<%eval request"
    $s2 = "<%eval(Request.Item["
    $s3 = "LANGUAGE='VBScript'"
    $s4 = "$_REQUEST" fullword
    $s5 = ";eval("
    $s6 = "base64_decode"

   condition:
      ($a at 0 or $b at 0 or $c at 0)
      and 1 of ($s*)
}


rule is_jpeg
{
  meta:
    file_type = ""
    file_desc = ""

  strings:
    $a = {FF D8 FF E0 ?? ?? 4A 46 49 46 00}
    $b = {FF D8 FF E1 ?? ?? 45 78 69 66 00
    $c = {FF D8 FF E2 ?? ?? 53 50 49 46 46 00}
    $d = {FF D8 FF E3 ?? ?? 53 50 49 46 46 00}
    $e = {FF D8 FF E8 ?? ?? 53 50 49 46 46 00}
    $f = {00 00 00 0C 6A 50 20 20 0D 0A}

  condition:
    $a at 0 or
    $b at 0 or
    $c at 0 or
    $d at 0 or
    $e at 0 or
    $f at 0
}


rule is_jpeg_with_eval
{
  meta:
    file_type = "jpeg"
    file_desc = ""

  strings:
    $a = {FF E1 ?? ?? 45 78 69 66 00}
    $b = /\beval\s*\(/

    condition:
        uint16be(0x00) == 0xFFD8 and $a and $b in (@a + 0x12 .. @a + 0x02 + uint16be(@a + 0x02) - 0x06)

}


rule is_png
{
  meta:
    file_type = ""
    file_desc = ""

  strings:
    $a0 = { 89 50 4E 47 0D 0A 1A 0A }
    $a1 = { 8A 4D 4E 47 0D 0A 1A 0A }
    $b = { 49 48 44 52 }
    $c = { 49 44 41 54 }
    $d = { 49 45 4E 44 }

  condition:
    ($a0 at 0 and for any of ($b, $c):
      (@ > @a0) and $d)
    or
    (($a0 at 0 or $a1 at 0) and $d)
}


/* Emails */
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


/* Certificates */
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
