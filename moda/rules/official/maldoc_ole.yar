/*
    MODA - Malicious Office Document Analyzer
    OLE Binary Format Detection Rules

    Detects malicious indicators in OLE2 Compound Binary File Format
    documents (.doc, .xls, .ppt and related formats).

    Author: MODA
    Date: 2026-07-06
    Version: 1.0
*/

import "math"

rule ole_with_vba
{
    meta:
        author      = "MODA"
        description = "Detects OLE documents containing a VBA macro project (VBA storage or _VBA_PROJECT stream)"
        date        = "2026-07-06"
        severity    = "medium"
        reference   = "https://learn.microsoft.com/en-us/openspecs/office_file_formats/ms-ovba"

    strings:
        // OLE2 Compound File magic bytes
        $ole_magic = { D0 CF 11 E0 A1 B1 1A E1 }

        // VBA storage / project markers
        $vba_dir       = "_VBA_PROJECT" ascii wide nocase
        $vba_root      = "VBA" ascii wide
        $vba_project   = "PROJECT" ascii wide
        $vba_macro     = "Macros" ascii wide nocase
        $vba_module    = "Module" ascii wide nocase
        $vba_attr      = "Attribute VB_" ascii nocase
        $vba_dir_stream = "dir" ascii wide

    condition:
        $ole_magic at 0 and
        (
            $vba_dir or
            ($vba_root and $vba_project) or
            ($vba_macro and $vba_module) or
            ($vba_attr and $vba_dir_stream)
        )
}

rule ole_with_embedded_exe
{
    meta:
        author      = "MODA"
        description = "Detects OLE documents with embedded PE (Portable Executable) files"
        date        = "2026-07-06"
        severity    = "high"
        reference   = "https://attack.mitre.org/techniques/T1027/006/"

    strings:
        // OLE2 magic
        $ole_magic = { D0 CF 11 E0 A1 B1 1A E1 }

        // PE header markers (MZ header + PE signature)
        $mz_header = { 4D 5A 90 00 }
        $pe_sig    = "PE\x00\x00"

        // Common PE section names
        $sect_text  = ".text" ascii
        $sect_rdata = ".rdata" ascii
        $sect_data  = ".data" ascii
        $sect_rsrc  = ".rsrc" ascii

        // This program cannot be run in DOS mode
        $dos_msg = "This program cannot be run in DOS mode" ascii nocase

    condition:
        $ole_magic at 0 and
        $mz_header and
        (
            $pe_sig or
            $dos_msg or
            (2 of ($sect_text, $sect_rdata, $sect_data, $sect_rsrc))
        )
}

rule ole_suspicious_streams
{
    meta:
        author      = "MODA"
        description = "Detects OLE documents with unusual or suspicious stream names indicative of exploitation or obfuscation"
        date        = "2026-07-06"
        severity    = "medium"
        reference   = "https://attack.mitre.org/techniques/T1221/"

    strings:
        // OLE2 magic
        $ole_magic = { D0 CF 11 E0 A1 B1 1A E1 }

        // Equation Editor OLE object (CVE-2017-11882)
        $equation  = "Equation Native" ascii wide nocase
        $equation2 = "Equation.3" ascii wide nocase

        // DDE-related streams
        $dde_link   = "\x13 DDEAUTO" ascii nocase
        $dde_link2  = "\x13 DDE " ascii nocase

        // Suspicious OLE class names
        $shell_obj    = "Shell.Explorer" ascii wide nocase
        $script_obj   = "ScriptBridge" ascii wide nocase
        $htmlfile      = "htmlfile" ascii wide nocase
        $package       = "Package" ascii wide nocase
        $ole_package   = "OLE2Link" ascii wide nocase

        // PowerShell payload streams
        $ps_stream = "powershell" ascii wide nocase

        // Suspicious object class identifiers
        $objdata   = "\\objdata" ascii nocase
        $objclass  = "\\objclass" ascii nocase

    condition:
        $ole_magic at 0 and
        (
            any of ($equation*) or
            any of ($dde_link*) or
            ($shell_obj or $script_obj or $htmlfile) or
            ($package and $ole_package) or
            $ps_stream or
            ($objdata and $objclass)
        )
}

rule ole_encrypted_content
{
    meta:
        author      = "MODA"
        description = "Detects OLE documents with encrypted streams or password-protected content that may hide malicious payloads"
        date        = "2026-07-06"
        severity    = "medium"
        reference   = "https://attack.mitre.org/techniques/T1027/"

    strings:
        // OLE2 magic
        $ole_magic = { D0 CF 11 E0 A1 B1 1A E1 }

        // Office encryption markers
        $encrypt_info   = "EncryptionInfo" ascii wide
        $encrypt_pkg    = "EncryptedPackage" ascii wide
        $strong_encrypt = "StrongEncryptionDataSpace" ascii wide
        $data_spaces    = "DataSpaces" ascii wide
        $drm_content    = "DRMContent" ascii wide

        // RC4 / encryption stream names
        $rc4_header    = { 01 00 01 00 }  // RC4 encryption header version
        $transform_info = "TransformInfo" ascii wide
        $primary_stream = "\x06DataSpaces" ascii wide

        // Password stream indicator
        $password = "password" ascii wide nocase

    condition:
        $ole_magic at 0 and
        (
            ($encrypt_info and $encrypt_pkg) or
            $strong_encrypt or
            ($data_spaces and ($transform_info or $primary_stream)) or
            ($drm_content) or
            ($rc4_header in (0..4096) and $password)
        )
}

rule ole_with_activex
{
    meta:
        author      = "MODA"
        description = "Detects OLE documents containing ActiveX controls which may be used for code execution"
        date        = "2026-07-06"
        severity    = "high"
        reference   = "https://attack.mitre.org/techniques/T1559/"

    strings:
        // OLE2 magic
        $ole_magic = { D0 CF 11 E0 A1 B1 1A E1 }

        // ActiveX control markers
        $activex_stream = "MBD" ascii wide        // ActiveX storage prefix
        $ocx_data       = "\x00o\x00c\x00x\x00" wide // .ocx in wide chars
        $activex_ctl    = "MSForms" ascii wide nocase
        $cmd_button     = "CommandButton" ascii wide nocase
        $ole_control    = "OLEControl" ascii wide nocase

        // Common dangerous ActiveX CLSIDs (string form)
        // Shell.Explorer.2
        $clsid_shell   = "8856F961-340A-11D0-A96B-00C04FD705A2" ascii wide nocase
        // ShockwaveFlash.ShockwaveFlash
        $clsid_flash   = "D27CDB6E-AE6D-11CF-96B8-444553540000" ascii wide nocase
        // MSXML2.XMLHTTP
        $clsid_xmlhttp = "88D96A0A-F192-11D4-A65F-0040963251E5" ascii wide nocase

        // InProcServer / control registration
        $inproc = "InprocServer32" ascii wide nocase
        $classid = "CLSID" ascii wide

        // Forms user control stream
        $user_form = "UserForm" ascii wide nocase
        $frame_ctl = "Frame" ascii wide nocase

    condition:
        $ole_magic at 0 and
        (
            ($activex_stream and ($ocx_data or $activex_ctl)) or
            ($cmd_button and $ole_control) or
            any of ($clsid_*) or
            ($inproc and $classid) or
            ($user_form and ($frame_ctl or $cmd_button))
        )
}
