/*
    MODA - Malicious Office Document Analyzer
    PDF Format Detection Rules

    Detects malicious indicators in Portable Document Format files (.pdf).

    Author: MODA
    Date: 2026-07-06
    Version: 1.0
*/

rule pdf_with_javascript
{
    meta:
        author      = "MODA"
        description = "Detects PDF documents containing JavaScript code which may execute malicious actions"
        date        = "2026-07-06"
        severity    = "high"
        reference   = "https://attack.mitre.org/techniques/T1059/007/"

    strings:
        // PDF magic
        $pdf_magic = "%PDF-" ascii

        // JavaScript action references
        $js_action  = "/JS" ascii
        $js_type    = "/JavaScript" ascii
        $js_embed   = "/EmbeddedFile" ascii

        // Common malicious JavaScript functions
        $js_eval       = "eval(" ascii nocase
        $js_unescape   = "unescape(" ascii nocase
        $js_fromchar   = "String.fromCharCode" ascii nocase
        $js_replace    = ".replace(" ascii nocase
        $js_split      = ".split(" ascii nocase
        $js_this       = "this." ascii

        // Heap spray / shellcode patterns
        $heap_spray1 = "spray" ascii nocase
        $heap_spray2 = "%u" ascii
        $shellcode   = "\\x" ascii
        $nop_sled    = /(%u9090|%u0c0c){3,}/ ascii

        // Obfuscation patterns
        $js_concat   = /\+\s*["'][^"']*["']\s*\+/ ascii
        $js_charcode = /charCodeAt\s*\(/ ascii

        // Adobe-specific JavaScript methods
        $util_printf = "util.printf" ascii
        $app_doc     = "app.doc" ascii
        $collab      = "Collab.collectEmailInfo" ascii

    condition:
        $pdf_magic at 0 and
        (
            ($js_type and ($js_eval or $js_unescape or $js_fromchar)) or
            ($js_action and any of ($js_eval, $js_unescape, $heap_spray*, $shellcode, $nop_sled)) or
            ($js_type and $js_concat and $js_charcode) or
            (($js_type or $js_embed) and any of ($util_printf, $app_doc, $collab)) or
            ($js_action and $js_this and ($js_replace or $js_split) and $js_unescape)
        )
}

rule pdf_launch_action
{
    meta:
        author      = "MODA"
        description = "Detects PDF documents with Launch actions that can execute system commands or open files"
        date        = "2026-07-06"
        severity    = "critical"
        reference   = "https://attack.mitre.org/techniques/T1204/002/"

    strings:
        // PDF magic
        $pdf_magic = "%PDF-" ascii

        // Launch action
        $launch     = "/Launch" ascii
        $action     = "/Action" ascii
        $s_type     = "/S" ascii

        // Command/file launch targets
        $win_launch  = "/Win" ascii
        $f_param     = "/F" ascii
        $p_param     = "/P" ascii
        $d_param     = "/D" ascii

        // Common launch targets
        $cmd_exe     = "cmd.exe" ascii nocase
        $cmd_path    = "cmd /c" ascii nocase
        $powershell  = "powershell" ascii nocase
        $wscript     = "wscript" ascii nocase
        $cscript     = "cscript" ascii nocase
        $mshta       = "mshta" ascii nocase
        $rundll32    = "rundll32" ascii nocase

        // URI-based launch
        $uri_action  = "/URI" ascii
        $goto_remote = "/GoToR" ascii
        $goto_embed  = "/GoToE" ascii
        $submit_form = "/SubmitForm" ascii

    condition:
        $pdf_magic at 0 and
        (
            ($launch and ($action or $s_type) and $win_launch and ($f_param or $p_param or $d_param)) or
            ($launch and any of ($cmd_exe, $cmd_path, $powershell, $wscript, $cscript, $mshta, $rundll32)) or
            ($goto_remote and $f_param) or
            ($goto_embed and $f_param) or
            ($submit_form and $uri_action)
        )
}

rule pdf_embedded_file
{
    meta:
        author      = "MODA"
        description = "Detects PDF documents with embedded files that may contain executables or scripts"
        date        = "2026-07-06"
        severity    = "high"
        reference   = "https://attack.mitre.org/techniques/T1027/006/"

    strings:
        // PDF magic
        $pdf_magic = "%PDF-" ascii

        // Embedded file markers
        $embed_file  = "/EmbeddedFile" ascii
        $filespec    = "/Filespec" ascii
        $ef          = "/EF" ascii
        $uf          = "/UF" ascii

        // Embedded PE header
        $mz_header   = { 4D 5A 90 00 }

        // Embedded file with suspicious names
        $name_exe    = ".exe" ascii nocase
        $name_dll    = ".dll" ascii nocase
        $name_scr    = ".scr" ascii nocase
        $name_bat    = ".bat" ascii nocase
        $name_cmd    = ".cmd" ascii nocase
        $name_vbs    = ".vbs" ascii nocase
        $name_js     = ".js" ascii nocase
        $name_ps1    = ".ps1" ascii nocase
        $name_hta    = ".hta" ascii nocase
        $name_jar    = ".jar" ascii nocase

        // Streams with encoding that could hide content
        $flate       = "/FlateDecode" ascii
        $asciihex    = "/ASCIIHexDecode" ascii
        $ascii85     = "/ASCII85Decode" ascii
        $lzw         = "/LZWDecode" ascii

    condition:
        $pdf_magic at 0 and
        (
            ($embed_file and $mz_header) or
            ($embed_file and any of ($name_exe, $name_dll, $name_scr, $name_bat, $name_cmd, $name_vbs, $name_js, $name_ps1, $name_hta, $name_jar)) or
            ($filespec and ($ef or $uf) and $mz_header) or
            ($embed_file and 3 of ($flate, $asciihex, $ascii85, $lzw))
        )
}

rule pdf_suspicious_objects
{
    meta:
        author      = "MODA"
        description = "Detects PDF documents with suspicious combinations of objects indicative of exploitation"
        date        = "2026-07-06"
        severity    = "medium"
        reference   = "https://attack.mitre.org/techniques/T1203/"

    strings:
        // PDF magic
        $pdf_magic = "%PDF-" ascii

        // Suspicious action types
        $aa          = "/AA" ascii           // Additional Actions
        $open_action = "/OpenAction" ascii
        $acroform    = "/AcroForm" ascii
        $xfa         = "/XFA" ascii

        // Suspicious object combinations
        $obj_stream  = "/ObjStm" ascii       // Object streams (hiding objects)
        $xref_stream = "/XRef" ascii         // Cross-reference streams

        // Names / encoding tricks
        $name_hex    = /#[0-9a-fA-F]{2}/ ascii  // Hex-encoded name chars
        $jbig2       = "/JBIG2Decode" ascii      // JBIG2 (CVE-2009-0658)

        // RichMedia / Flash
        $richmedia   = "/RichMedia" ascii
        $flash       = "/Flash" ascii
        $type3d      = "/3D" ascii

        // Suspicious patterns
        $colors_large = /\/Colors\s+[0-9]{5,}/ ascii     // Extremely large color values
        $width_large  = /\/Width\s+[0-9]{5,}/ ascii       // Extremely large width
        $height_large = /\/Height\s+[0-9]{5,}/ ascii      // Extremely large height

    condition:
        $pdf_magic at 0 and
        (
            ($acroform and $xfa and ($open_action or $aa)) or
            (($obj_stream or $xref_stream) and ($open_action or $aa)) or
            ($jbig2 and ($open_action or $aa)) or
            ($richmedia and ($flash or $type3d)) or
            (2 of ($colors_large, $width_large, $height_large)) or
            (#name_hex > 10 and ($open_action or $aa))
        )
}

rule pdf_openaction
{
    meta:
        author      = "MODA"
        description = "Detects PDF documents with automatic open actions that trigger on document open"
        date        = "2026-07-06"
        severity    = "medium"
        reference   = "https://attack.mitre.org/techniques/T1204/002/"

    strings:
        // PDF magic
        $pdf_magic = "%PDF-" ascii

        // Open action triggers
        $open_action = "/OpenAction" ascii
        $aa          = "/AA" ascii

        // Action types
        $js_action   = "/JavaScript" ascii
        $launch      = "/Launch" ascii
        $uri         = "/URI" ascii
        $submit      = "/SubmitForm" ascii
        $import_data = "/ImportData" ascii
        $goto_remote = "/GoToR" ascii
        $named       = "/Named" ascii
        $goto_embed  = "/GoToE" ascii

        // Catalog reference
        $catalog     = "/Type /Catalog" ascii

        // Rendition action (multimedia)
        $rendition   = "/Rendition" ascii

    condition:
        $pdf_magic at 0 and
        $catalog and
        (
            ($open_action and any of ($js_action, $launch, $uri, $submit, $import_data, $goto_remote, $named, $goto_embed, $rendition)) or
            ($aa and any of ($js_action, $launch, $uri, $submit))
        )
}
