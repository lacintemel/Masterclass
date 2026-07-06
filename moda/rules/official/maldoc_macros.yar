/*
    MODA - Malicious Office Document Analyzer
    Malicious VBA Macro Detection Rules

    Detects malicious patterns in VBA macro code including
    auto-execution, shell commands, download, obfuscation, and
    process injection techniques.

    Author: MODA
    Date: 2026-07-06
    Version: 1.0
*/

rule macro_autoexec
{
    meta:
        author      = "MODA"
        description = "Detects VBA macros with auto-execution entry points that trigger without user interaction"
        date        = "2026-07-06"
        severity    = "medium"
        reference   = "https://attack.mitre.org/techniques/T1137/"

    strings:
        // VBA attribute marker
        $vba_attr = "Attribute VB_" ascii

        // Auto-execution triggers
        $auto_open      = "AutoOpen" ascii nocase
        $auto_close     = "AutoClose" ascii nocase
        $auto_exec      = "AutoExec" ascii nocase
        $auto_exit      = "AutoExit" ascii nocase
        $auto_new       = "AutoNew" ascii nocase
        $doc_open       = "Document_Open" ascii nocase
        $doc_close      = "Document_Close" ascii nocase
        $doc_new        = "Document_New" ascii nocase
        $doc_befclose   = "Document_BeforeClose" ascii nocase
        $wb_open        = "Workbook_Open" ascii nocase
        $wb_activate    = "Workbook_Activate" ascii nocase
        $wb_befclose    = "Workbook_BeforeClose" ascii nocase
        $ws_activate    = "Worksheet_Activate" ascii nocase
        $ws_change      = "Worksheet_Change" ascii nocase

        // Class initialization
        $class_init     = "Class_Initialize" ascii nocase
        $userform_init  = "UserForm_Initialize" ascii nocase
        $userform_act   = "UserForm_Activate" ascii nocase

        // Presentation events (PowerPoint)
        $ppt_open       = "Presentation_Open" ascii nocase
        $slide_show     = "SlideShowBegin" ascii nocase

    condition:
        $vba_attr and
        any of ($auto_*, $doc_*, $wb_*, $ws_*, $class_init, $userform_*, $ppt_open, $slide_show)
}

rule macro_shell_execution
{
    meta:
        author      = "MODA"
        description = "Detects VBA macros using Shell, WScript.Shell, or similar methods to execute system commands"
        date        = "2026-07-06"
        severity    = "high"
        reference   = "https://attack.mitre.org/techniques/T1059/"

    strings:
        // VBA attribute or Sub/Function markers
        $vba_code = "Sub " ascii nocase
        $vba_func = "Function " ascii nocase

        // Direct shell execution
        $shell_func     = "Shell(" ascii nocase
        $shell_exec     = "Shell " ascii nocase
        $vba_shell      = "VBA.Shell" ascii nocase

        // WScript.Shell
        $wscript_shell  = "WScript.Shell" ascii nocase
        $wsh_run        = ".Run " ascii nocase
        $wsh_exec       = ".Exec(" ascii nocase

        // CreateObject for shell
        $create_shell   = "CreateObject(\"WScript.Shell\")" ascii nocase
        $create_shell2  = "CreateObject(\"Shell.Application\")" ascii nocase
        $create_wmi     = "CreateObject(\"WbemScripting" ascii nocase

        // ShellExecute via Shell.Application
        $shell_app      = "Shell.Application" ascii nocase
        $shell_execute  = "ShellExecute" ascii nocase

        // Process creation
        $win32_process  = "Win32_Process" ascii nocase
        $process_create = "Create(" ascii nocase

        // Command strings
        $cmd_exe        = "cmd.exe" ascii nocase
        $cmd_slash_c    = "cmd /c" ascii nocase
        $cmd_slash_k    = "cmd /k" ascii nocase
        $powershell     = "powershell" ascii nocase
        $pwsh           = "pwsh" ascii nocase
        $mshta          = "mshta" ascii nocase

    condition:
        any of ($vba_code, $vba_func) and
        (
            ($shell_func or $shell_exec or $vba_shell) or
            ($wscript_shell and ($wsh_run or $wsh_exec)) or
            any of ($create_shell*) or
            ($shell_app and $shell_execute) or
            ($win32_process and $process_create) or
            ($create_wmi and any of ($cmd_exe, $cmd_slash_c, $cmd_slash_k, $powershell, $pwsh, $mshta))
        )
}

rule macro_download
{
    meta:
        author      = "MODA"
        description = "Detects VBA macros with download/network functionality to retrieve remote payloads"
        date        = "2026-07-06"
        severity    = "high"
        reference   = "https://attack.mitre.org/techniques/T1105/"

    strings:
        // VBA code markers
        $vba_code = "Sub " ascii nocase
        $vba_func = "Function " ascii nocase

        // XMLHTTP / ServerXMLHTTP
        $xmlhttp        = "MSXML2.XMLHTTP" ascii nocase
        $server_xmlhttp = "MSXML2.ServerXMLHTTP" ascii nocase
        $xmlhttp_obj    = "Microsoft.XMLHTTP" ascii nocase
        $winhttp        = "WinHttp.WinHttpRequest" ascii nocase

        // HTTP methods
        $http_open   = ".Open " ascii nocase
        $http_send   = ".Send" ascii nocase
        $http_resp   = ".ResponseBody" ascii nocase
        $http_text   = ".ResponseText" ascii nocase
        $http_get    = "\"GET\"" ascii nocase
        $http_post   = "\"POST\"" ascii nocase

        // URLDownloadToFile API
        $url_download = "URLDownloadToFile" ascii nocase
        $urlmon       = "urlmon" ascii nocase

        // PowerShell download
        $ps_download  = "DownloadFile" ascii nocase
        $ps_download2 = "DownloadString" ascii nocase
        $ps_webclient = "Net.WebClient" ascii nocase
        $invoke_web   = "Invoke-WebRequest" ascii nocase
        $iwr          = "Invoke-RestMethod" ascii nocase

        // WinAPI for downloading
        $inet_open    = "InternetOpenA" ascii nocase
        $inet_openw   = "InternetOpenW" ascii nocase
        $inet_openurl = "InternetOpenUrl" ascii nocase
        $inet_read    = "InternetReadFile" ascii nocase

        // Saving downloaded content
        $adodb_stream = "ADODB.Stream" ascii nocase
        $save_tofile  = "SaveToFile" ascii nocase

        // URL indicators
        $http_url  = "http://" ascii nocase
        $https_url = "https://" ascii nocase

    condition:
        any of ($vba_code, $vba_func) and
        (
            (any of ($xmlhttp, $server_xmlhttp, $xmlhttp_obj, $winhttp) and any of ($http_open, $http_send) and any of ($http_get, $http_post, $http_resp, $http_text)) or
            ($url_download and $urlmon) or
            ($url_download and any of ($http_url, $https_url)) or
            (any of ($ps_download, $ps_download2, $ps_webclient, $invoke_web, $iwr) and any of ($http_url, $https_url)) or
            (any of ($inet_open, $inet_openw) and $inet_openurl and $inet_read) or
            ($adodb_stream and $save_tofile and any of ($http_url, $https_url)) or
            (any of ($xmlhttp, $winhttp) and any of ($http_resp, $http_text) and $adodb_stream)
        )
}

rule macro_obfuscated
{
    meta:
        author      = "MODA"
        description = "Detects VBA macros using obfuscation techniques to hide malicious intent"
        date        = "2026-07-06"
        severity    = "medium"
        reference   = "https://attack.mitre.org/techniques/T1027/"

    strings:
        // VBA code markers
        $vba_code = "Sub " ascii nocase
        $vba_func = "Function " ascii nocase

        // Chr() / ChrW() concatenation (common obfuscation)
        $chr_concat  = /Chr\w?\(\d+\)\s*(&|&\s*)\s*Chr\w?\(\d+\)/ ascii nocase
        $chrw_concat = /ChrW?\(\d+\)\s*&\s*ChrW?\(\d+\)/ ascii nocase

        // Heavy string concatenation
        $str_concat  = /"\s*&\s*"\s*&\s*"\s*&\s*"/ ascii

        // Base64 decode patterns
        $base64_dec  = "Base64" ascii nocase
        $from_base64 = "FromBase64String" ascii nocase

        // Replace-based obfuscation
        $replace_func = "Replace(" ascii nocase
        $mid_func     = "Mid(" ascii nocase
        $left_func    = "Left(" ascii nocase
        $right_func   = "Right(" ascii nocase

        // CallByName (indirect function calls)
        $callbyname  = "CallByName" ascii nocase

        // Reverse string
        $strreverse  = "StrReverse" ascii nocase

        // Environment variable obfuscation
        $environ     = "Environ(" ascii nocase

        // Execute / Eval for dynamic code
        $exec_code   = "Execute(" ascii nocase
        $eval_code   = "Eval(" ascii nocase
        $exec_global = "ExecuteGlobal" ascii nocase

        // Array-based payload reconstruction
        $array_func  = "Array(" ascii nocase
        $join_func   = "Join(" ascii nocase

        // Lots of numeric Chr calls suggests obfuscation
        $many_chr    = /Chr\w?\(\d+\)/ ascii nocase

    condition:
        any of ($vba_code, $vba_func) and
        (
            (#chr_concat > 3 or #chrw_concat > 3) or
            (#many_chr > 15) or
            ($str_concat and any of ($replace_func, $mid_func, $left_func, $right_func)) or
            (any of ($base64_dec, $from_base64) and any of ($exec_code, $eval_code, $exec_global)) or
            ($callbyname and $strreverse) or
            ($strreverse and any of ($exec_code, $eval_code)) or
            ($array_func and $join_func and any of ($exec_code, $eval_code, $exec_global)) or
            ($exec_global and ($replace_func or $strreverse or $environ))
        )
}

rule macro_process_injection
{
    meta:
        author      = "MODA"
        description = "Detects VBA macros using Windows API calls for process injection and memory manipulation"
        date        = "2026-07-06"
        severity    = "critical"
        reference   = "https://attack.mitre.org/techniques/T1055/"

    strings:
        // VBA code markers
        $vba_code = "Sub " ascii nocase
        $vba_func = "Function " ascii nocase
        $declare  = "Declare" ascii nocase

        // Process injection APIs
        $virtual_alloc     = "VirtualAlloc" ascii nocase
        $virtual_alloc_ex  = "VirtualAllocEx" ascii nocase
        $virtual_protect   = "VirtualProtect" ascii nocase
        $write_process     = "WriteProcessMemory" ascii nocase
        $create_thread     = "CreateThread" ascii nocase
        $create_remote     = "CreateRemoteThread" ascii nocase
        $rtl_move_memory   = "RtlMoveMemory" ascii nocase
        $nt_create_thread  = "NtCreateThreadEx" ascii nocase

        // Memory operations
        $heap_alloc        = "HeapAlloc" ascii nocase
        $global_alloc      = "GlobalAlloc" ascii nocase
        $local_alloc       = "LocalAlloc" ascii nocase

        // Process access
        $open_process      = "OpenProcess" ascii nocase
        $enum_processes    = "EnumProcesses" ascii nocase

        // Shellcode execution patterns
        $call_window_proc  = "CallWindowProc" ascii nocase
        $enum_windows      = "EnumWindows" ascii nocase
        $enum_child        = "EnumChildWindows" ascii nocase
        $enum_desktop      = "EnumDesktopWindows" ascii nocase

        // Memory page constants
        $page_exec         = "PAGE_EXECUTE" ascii nocase
        $mem_commit        = "MEM_COMMIT" ascii nocase

    condition:
        any of ($vba_code, $vba_func) and
        $declare and
        (
            ($virtual_alloc and ($rtl_move_memory or $write_process) and $create_thread) or
            ($virtual_alloc_ex and $write_process and ($create_remote or $nt_create_thread)) or
            ($virtual_alloc and any of ($call_window_proc, $enum_windows, $enum_child, $enum_desktop)) or
            ($open_process and ($enum_processes or $virtual_alloc_ex) and $write_process) or
            (2 of ($virtual_alloc, $virtual_protect, $rtl_move_memory, $create_thread, $global_alloc, $local_alloc) and ($page_exec or $mem_commit)) or
            (any of ($heap_alloc, $global_alloc, $local_alloc) and $rtl_move_memory and any of ($call_window_proc, $create_thread))
        )
}

rule macro_environment_access
{
    meta:
        author      = "MODA"
        description = "Detects VBA macros accessing environment variables and system information for reconnaissance or payload deployment"
        date        = "2026-07-06"
        severity    = "low"
        reference   = "https://attack.mitre.org/techniques/T1082/"

    strings:
        // VBA code markers
        $vba_code = "Sub " ascii nocase
        $vba_func = "Function " ascii nocase

        // Environment variable access
        $environ     = "Environ(" ascii nocase
        $env_temp    = "\"TEMP\"" ascii nocase
        $env_tmp     = "\"TMP\"" ascii nocase
        $env_appdata = "\"APPDATA\"" ascii nocase
        $env_userprofile = "\"USERPROFILE\"" ascii nocase
        $env_username   = "\"USERNAME\"" ascii nocase
        $env_computername = "\"COMPUTERNAME\"" ascii nocase
        $env_os      = "\"OS\"" ascii nocase
        $env_windir  = "\"WINDIR\"" ascii nocase
        $env_sysroot = "\"SYSTEMROOT\"" ascii nocase
        $env_programfiles = "\"PROGRAMFILES\"" ascii nocase
        $env_public  = "\"PUBLIC\"" ascii nocase

        // WMI system info queries
        $wmi_os      = "Win32_OperatingSystem" ascii nocase
        $wmi_cs      = "Win32_ComputerSystem" ascii nocase
        $wmi_proc    = "Win32_Processor" ascii nocase
        $wmi_bios    = "Win32_BIOS" ascii nocase
        $wmi_disk    = "Win32_DiskDrive" ascii nocase
        $wmi_net     = "Win32_NetworkAdapter" ascii nocase

        // File system operations
        $filesys_obj  = "Scripting.FileSystemObject" ascii nocase
        $create_text  = "CreateTextFile" ascii nocase
        $write_line   = "WriteLine" ascii nocase
        $copy_file    = "CopyFile" ascii nocase
        $move_file    = "MoveFile" ascii nocase
        $delete_file  = "DeleteFile" ascii nocase

        // Registry access
        $reg_read     = "RegRead" ascii nocase
        $reg_write    = "RegWrite" ascii nocase
        $reg_delete   = "RegDelete" ascii nocase
        $shell_reg    = "HKEY_" ascii nocase

    condition:
        any of ($vba_code, $vba_func) and
        (
            ($environ and 3 of ($env_*)) or
            (2 of ($wmi_*) and $environ) or
            ($filesys_obj and ($create_text or $write_line or $copy_file) and any of ($env_temp, $env_appdata, $env_tmp)) or
            (any of ($reg_read, $reg_write, $reg_delete) and $shell_reg and $environ) or
            ($filesys_obj and any of ($delete_file, $move_file) and $environ)
        )
}
