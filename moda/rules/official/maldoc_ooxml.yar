/*
    MODA - Malicious Office Document Analyzer
    OOXML Format Detection Rules

    Detects malicious indicators in Office Open XML documents
    (.docx, .xlsx, .pptx and macro-enabled variants).

    Author: MODA
    Date: 2026-07-06
    Version: 1.0
*/

rule ooxml_external_relationship
{
    meta:
        author      = "MODA"
        description = "Detects OOXML documents with external relationship targets (template injection, remote content loading)"
        date        = "2026-07-06"
        severity    = "high"
        reference   = "https://attack.mitre.org/techniques/T1221/"

    strings:
        // PK (ZIP) magic bytes
        $pk_magic = { 50 4B 03 04 }

        // External relationship target patterns
        $ext_target     = "TargetMode=\"External\"" ascii nocase
        $ext_target2    = "TargetMode='External'" ascii nocase

        // Remote template URLs
        $http_target    = "Target=\"http" ascii nocase
        $http_target2   = "Target='http" ascii nocase
        $https_target   = "Target=\"https" ascii nocase
        $ftp_target     = "Target=\"ftp" ascii nocase

        // Relationship file indicators
        $rels_ext       = ".rels" ascii
        $rel_ns         = "schemas.openxmlformats.org/package/2006/relationships" ascii

        // attachedTemplate relationship type
        $template_rel   = "attachedTemplate" ascii nocase
        $frame_rel      = "frame" ascii nocase
        $oleobject_rel  = "oleObject" ascii nocase
        $subDocument    = "subDocument" ascii nocase

        // SMB / UNC paths for credential harvesting
        $unc_path       = "Target=\"\\\\" ascii
        $unc_path2      = "Target=\"file://" ascii nocase

    condition:
        $pk_magic at 0 and
        $rels_ext and $rel_ns and
        (
            (any of ($ext_target*) and any of ($http_target*, $https_target*, $ftp_target*)) or
            ($template_rel and any of ($ext_target*)) or
            ($frame_rel and any of ($ext_target*)) or
            ($oleobject_rel and any of ($ext_target*)) or
            ($subDocument and any of ($ext_target*)) or
            any of ($unc_path*)
        )
}

rule ooxml_with_macros
{
    meta:
        author      = "MODA"
        description = "Detects OOXML documents containing VBA macro project (vbaProject.bin)"
        date        = "2026-07-06"
        severity    = "medium"
        reference   = "https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba"

    strings:
        // PK (ZIP) magic bytes
        $pk_magic = { 50 4B 03 04 }

        // VBA project binary inside OOXML
        $vba_project    = "vbaProject.bin" ascii
        $vba_project_xl = "xl/vbaProject.bin" ascii
        $vba_project_wd = "word/vbaProject.bin" ascii
        $vba_project_pp = "ppt/vbaProject.bin" ascii

        // Macro-enabled content types
        $macro_ct_docm = "macro" ascii nocase
        $ct_vba        = "application/vnd.ms-office.vbaProject" ascii

        // VBA attribute markers inside the embedded binary
        $vba_attr = "Attribute VB_" ascii

    condition:
        $pk_magic at 0 and
        (
            any of ($vba_project*) or
            ($ct_vba) or
            ($macro_ct_docm and $vba_attr)
        )
}

rule ooxml_embedded_objects
{
    meta:
        author      = "MODA"
        description = "Detects OOXML documents with embedded suspicious objects (OLE, ActiveX, executables)"
        date        = "2026-07-06"
        severity    = "high"
        reference   = "https://attack.mitre.org/techniques/T1027/006/"

    strings:
        // PK (ZIP) magic bytes
        $pk_magic = { 50 4B 03 04 }

        // Embedded object paths in OOXML
        $embed_ole     = "embeddings/" ascii
        $embed_activex = "activeX/" ascii
        $embed_object  = "oleObject" ascii

        // Suspicious embedded content types
        $ct_ole        = "application/vnd.openxmlformats-officedocument.oleObject" ascii
        $ct_bin        = "application/octet-stream" ascii
        $ct_activex    = "application/vnd.ms-office.activeX+xml" ascii

        // Embedded PE header
        $mz_header = { 4D 5A 90 00 }
        $pe_sig    = "PE\x00\x00"

        // Embedded scripts
        $embed_vbs = ".vbs" ascii nocase
        $embed_js  = ".js" ascii nocase
        $embed_ps1 = ".ps1" ascii nocase
        $embed_exe = ".exe" ascii nocase
        $embed_dll = ".dll" ascii nocase
        $embed_scr = ".scr" ascii nocase
        $embed_bat = ".bat" ascii nocase
        $embed_cmd = ".cmd" ascii nocase

    condition:
        $pk_magic at 0 and
        (
            ($embed_ole and ($mz_header or $pe_sig)) or
            ($embed_activex and $ct_activex) or
            ($ct_ole and any of ($embed_vbs, $embed_js, $embed_ps1, $embed_exe, $embed_dll, $embed_scr)) or
            ($embed_object and ($ct_bin or $mz_header)) or
            ($embed_ole and any of ($embed_bat, $embed_cmd))
        )
}

rule ooxml_dde_attack
{
    meta:
        author      = "MODA"
        description = "Detects OOXML documents using DDE (Dynamic Data Exchange) field codes for command execution"
        date        = "2026-07-06"
        severity    = "critical"
        reference   = "https://attack.mitre.org/techniques/T1559/002/"

    strings:
        // PK (ZIP) magic bytes
        $pk_magic = { 50 4B 03 04 }

        // DDE field code patterns in XML
        $dde_field1     = "DDEAUTO" ascii nocase
        $dde_field2     = "DDE " ascii nocase
        $dde_fldChar    = "<w:fldChar" ascii
        $dde_instrText  = "<w:instrText" ascii

        // DDE with command execution indicators
        $dde_cmd        = "cmd" ascii nocase
        $dde_powershell = "powershell" ascii nocase
        $dde_mshta      = "mshta" ascii nocase
        $dde_wscript    = "wscript" ascii nocase
        $dde_cscript    = "cscript" ascii nocase
        $dde_certutil   = "certutil" ascii nocase
        $dde_regsvr     = "regsvr32" ascii nocase
        $dde_rundll     = "rundll32" ascii nocase
        $dde_bitsadmin  = "bitsadmin" ascii nocase

        // Quote-escaped DDE in XML
        $dde_quote1 = "\\\"cmd" ascii nocase
        $dde_quote2 = "&quot;cmd" ascii nocase

        // QUOTE field DDE bypass
        $quote_field = "QUOTE" ascii

    condition:
        $pk_magic at 0 and
        (
            (any of ($dde_field*) and ($dde_fldChar or $dde_instrText) and any of ($dde_cmd, $dde_powershell, $dde_mshta, $dde_wscript, $dde_cscript)) or
            (($dde_instrText or $dde_fldChar) and any of ($dde_cmd, $dde_powershell, $dde_certutil, $dde_regsvr, $dde_rundll, $dde_bitsadmin)) or
            any of ($dde_quote*) or
            ($quote_field and any of ($dde_field*))
        )
}

rule ooxml_office_exploit_protocols
{
    meta:
        author      = "MODA"
        description = "Detects OOXML relationships or XML parts referencing Office exploit protocol handlers"
        date        = "2026-07-06"
        severity    = "critical"
        reference   = "https://attack.mitre.org/techniques/T1203/"

    strings:
        $pk_magic = { 50 4B 03 04 }

        $rels_ext    = ".rels" ascii
        $external    = "TargetMode=\"External\"" ascii nocase
        $external_s  = "TargetMode='External'" ascii nocase
        $ole_rel     = "oleObject" ascii nocase
        $template    = "attachedTemplate" ascii nocase

        $msdt        = "ms-msdt:" ascii nocase
        $mhtml       = "mhtml:" ascii nocase
        $search_ms   = "search-ms:" ascii nocase
        $officecmd   = "ms-officecmd:" ascii nocase
        $ms_word     = "ms-word:" ascii nocase
        $ms_excel    = "ms-excel:" ascii nocase
        $ms_powerpt  = "ms-powerpoint:" ascii nocase
        $hcp         = "hcp:" ascii nocase
        $script      = "script:" ascii nocase
        $javascript  = "javascript:" ascii nocase

        $encoded_msdt   = "ms%2dmsdt" ascii nocase
        $encoded_mhtml  = "mhtml%3a" ascii nocase
        $encoded_search = "search%2dms" ascii nocase

    condition:
        $pk_magic at 0 and
        (
            any of ($msdt, $mhtml, $search_ms, $officecmd, $ms_word, $ms_excel, $ms_powerpt, $hcp, $script, $javascript) or
            any of ($encoded_msdt, $encoded_mhtml, $encoded_search) or
            (($rels_ext or $external or $external_s) and ($ole_rel or $template) and any of ($msdt, $mhtml, $search_ms, $officecmd))
        )
}

rule ooxml_mshtml_activex_exploit_markers
{
    meta:
        author      = "MODA"
        description = "Detects OOXML MSHTML, ActiveX, classid, and OLE markers associated with Office exploit chains"
        date        = "2026-07-06"
        severity    = "critical"
        reference   = "https://attack.mitre.org/techniques/T1203/"

    strings:
        $pk_magic = { 50 4B 03 04 }

        $mshtml1 = "mshtml" ascii nocase
        $mshtml2 = "htmlfile" ascii nocase
        $html    = ".html" ascii nocase
        $mhtml   = "mhtml:" ascii nocase

        $activex = "activeX" ascii nocase
        $classid = "classid" ascii nocase
        $clsid   = "clsid:" ascii nocase
        $oleobj  = "oleObject" ascii nocase
        $ole_ct  = "application/vnd.openxmlformats-officedocument.oleObject" ascii

    condition:
        $pk_magic at 0 and
        (any of ($mshtml*) or $html or $mhtml) and
        any of ($activex, $classid, $clsid, $oleobj, $ole_ct)
}
