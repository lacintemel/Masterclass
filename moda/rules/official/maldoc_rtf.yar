/*
    MODA - Malicious Office Document Analyzer
    RTF Format Detection Rules

    Detects malicious indicators in Rich Text Format documents (.rtf).

    Author: MODA
    Date: 2026-07-06
    Version: 1.0
*/

rule rtf_embedded_object
{
    meta:
        author      = "MODA"
        description = "Detects RTF documents with embedded OLE objects via \\objdata control word containing binary payloads"
        date        = "2026-07-06"
        severity    = "high"
        reference   = "https://attack.mitre.org/techniques/T1027/006/"

    strings:
        // RTF file magic
        $rtf_magic = "{\\rtf" ascii

        // OLE object embedding
        $objdata     = "\\objdata" ascii nocase
        $objclass    = "\\objclass" ascii nocase
        $objemb      = "\\objemb" ascii nocase
        $objlink     = "\\objlink" ascii nocase
        $objupdate   = "\\objupdate" ascii nocase
        $result      = "\\result" ascii nocase

        // Embedded PE signatures in hex
        $pe_hex      = "4d5a9000" ascii nocase  // MZ header in hex
        $pe_hex2     = "4D5A90" ascii nocase

        // Embedded OLE compound file in hex
        $ole_hex     = "d0cf11e0a1b11ae1" ascii nocase

        // Package CLSID for OLE Package (commonly used for embedding)
        $pkg_clsid   = "0003000C" ascii nocase

    condition:
        $rtf_magic at 0 and
        $objdata and
        (
            $objemb or
            $objlink or
            $objupdate or
            any of ($pe_hex*) or
            $ole_hex or
            $pkg_clsid or
            ($objclass and $result)
        )
}

rule rtf_equation_editor_exploit
{
    meta:
        author      = "MODA"
        description = "Detects RTF documents exploiting Microsoft Equation Editor vulnerabilities (CVE-2017-11882, CVE-2018-0802)"
        date        = "2026-07-06"
        severity    = "critical"
        reference   = "https://nvd.nist.gov/vuln/detail/CVE-2017-11882"

    strings:
        // RTF file magic
        $rtf_magic = "{\\rtf" ascii

        // Equation Editor CLSID: 0002CE02-0000-0000-C000-000000000046
        $eq_clsid1 = "0002CE02" ascii nocase
        // Alternate representations
        $eq_clsid2 = "02ce0200" ascii nocase  // Little-endian byte order
        $eq_clsid3 = "00 02 CE 02" ascii nocase

        // Equation.3 OLE class
        $eq_class  = "Equation.3" ascii nocase
        $eq_class2 = "4571756174696f6e2e33" ascii nocase  // "Equation.3" hex-encoded

        // Equation Native stream
        $eq_native = "Equation Native" ascii nocase
        $eq_nat_hex = "4571756174696f6e204e6174697665" ascii nocase // hex-encoded

        // Object data with Equation Editor
        $objdata   = "\\objdata" ascii nocase

        // Common exploit shellcode patterns (EQNEDT32 stack overflow)
        // Font name overflow pattern (name record > 40 bytes)
        $sc_pattern1 = { (08|0C) 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? }
        // MTEF header
        $mtef_header = { 03 01 01 03 }

    condition:
        $rtf_magic at 0 and
        $objdata and
        (
            (any of ($eq_clsid*) and any of ($eq_class*, $eq_native, $eq_nat_hex)) or
            (any of ($eq_clsid*) and $mtef_header) or
            (any of ($eq_class*) and $sc_pattern1) or
            any of ($eq_nat_hex, $eq_class2)
        )
}

rule rtf_ole_package
{
    meta:
        author      = "MODA"
        description = "Detects RTF documents with OLE Package objects used to embed files (scripts, executables)"
        date        = "2026-07-06"
        severity    = "high"
        reference   = "https://attack.mitre.org/techniques/T1566/001/"

    strings:
        // RTF file magic
        $rtf_magic = "{\\rtf" ascii

        // OLE Package CLSID (0003000C-0000-0000-C000-000000000046)
        $pkg_clsid  = "0003000C" ascii nocase
        $pkg_clsid2 = "0c000300" ascii nocase  // Little-endian

        // Package class name
        $pkg_class  = "Package" ascii nocase
        $pkg_hex    = "5061636b616765" ascii nocase  // "Package" hex-encoded

        // OLE object embedding
        $objdata    = "\\objdata" ascii nocase

        // Common embedded file extension indicators (hex-encoded filenames)
        $ext_exe = "2e657865" ascii nocase   // ".exe"
        $ext_scr = "2e736372" ascii nocase   // ".scr"
        $ext_bat = "2e626174" ascii nocase   // ".bat"
        $ext_cmd = "2e636d64" ascii nocase   // ".cmd"
        $ext_vbs = "2e766273" ascii nocase   // ".vbs"
        $ext_js  = "2e6a73" ascii nocase     // ".js"
        $ext_ps1 = "2e707331" ascii nocase   // ".ps1"
        $ext_dll = "2e646c6c" ascii nocase   // ".dll"
        $ext_hta = "2e687461" ascii nocase   // ".hta"
        $ext_lnk = "2e6c6e6b" ascii nocase   // ".lnk"

    condition:
        $rtf_magic at 0 and
        $objdata and
        (
            (any of ($pkg_clsid*) and any of ($ext_*)) or
            ($pkg_class and any of ($ext_*)) or
            ($pkg_hex and $objdata)
        )
}

rule rtf_obfuscated
{
    meta:
        author      = "MODA"
        description = "Detects RTF documents using obfuscation techniques such as hex encoding, control word manipulation, and whitespace padding"
        date        = "2026-07-06"
        severity    = "medium"
        reference   = "https://attack.mitre.org/techniques/T1027/"

    strings:
        // RTF file magic - various obfuscated forms
        $rtf_magic  = "{\\rtf" ascii
        $rtf_magic2 = "{\\rt" ascii         // Truncated (some parsers accept this)

        // Excessive hex encoding (long hex strings without whitespace)
        // At least 500 consecutive hex characters suggest embedded binary
        $long_hex = /[0-9a-fA-F]{500,}/ ascii

        // Obfuscated control words with inserted whitespace/newlines
        // e.g., {\o b j d a t a} or {\ o b j d a t a}
        $obj_obfusc1 = /\{\\o\s*b\s*j\s*d\s*a\s*t\s*a/ ascii nocase
        $obj_obfusc2 = /\{\\o\s*b\s*j\s*e\s*m\s*b/ ascii nocase

        // Nested braces obfuscation (deeply nested groups)
        $deep_nest = /\{\{(\{){10,}/ ascii

        // Byte-stuffing: inserting \'XX hex escapes
        $hex_escape = /(\\'[0-9a-fA-F]{2}){20,}/ ascii

        // Unicode escape obfuscation (\uNNNNN)
        $unicode_esc = /(\\u[0-9]{3,5}\s*){10,}/ ascii

        // Bin control word (raw binary data)
        $bin_data = /\\bin\s*[0-9]{4,}/ ascii

    condition:
        any of ($rtf_magic*) at 0 and
        (
            $long_hex or
            any of ($obj_obfusc*) or
            $deep_nest or
            $hex_escape or
            ($unicode_esc and $bin_data) or
            (#hex_escape > 5 and #long_hex > 0)
        )
}

rule SUSP_INDICATOR_RTF_MalVer_Objects
{
    meta:
        author      = "MODA"
        description = "Detects suspicious RTF malformed or weaponized object records with OLE, Package, Equation, or encoded payload indicators"
        date        = "2026-07-06"
        severity    = "high"
        reference   = "https://attack.mitre.org/techniques/T1203/"

    strings:
        $rtf_magic = "{\\rtf" ascii

        $object    = "\\object" ascii nocase
        $objdata   = "\\objdata" ascii nocase
        $objclass  = "\\objclass" ascii nocase
        $objemb    = "\\objemb" ascii nocase
        $objlink   = "\\objlink" ascii nocase
        $objupdate = "\\objupdate" ascii nocase

        $equation_ascii = "Equation.3" ascii nocase
        $equation_hex   = "4571756174696f6e2e33" ascii nocase
        $eq_clsid       = "0002CE02" ascii nocase
        $eq_clsid_le    = "02ce0200" ascii nocase

        $package_ascii = "Package" ascii nocase
        $package_hex   = "5061636b616765" ascii nocase
        $pkg_clsid     = "0003000C" ascii nocase
        $pkg_clsid_le  = "0c000300" ascii nocase

        $ole_hex = "d0cf11e0a1b11ae1" ascii nocase
        $mz_hex  = "4d5a" ascii nocase
        $pe_hex  = "50450000" ascii nocase

        $large_hex = /[0-9a-fA-F]{800,}/ ascii
        $bin_data  = /\\bin\s*[0-9]{4,}/ ascii

    condition:
        $rtf_magic at 0 and
        $object and
        $objdata and
        (
            any of ($objclass, $objemb, $objlink, $objupdate) or
            any of ($equation_*) or
            any of ($eq_clsid*) or
            any of ($package_*) or
            any of ($pkg_clsid*) or
            any of ($ole_hex, $mz_hex, $pe_hex) or
            $large_hex or
            $bin_data
        )
}
