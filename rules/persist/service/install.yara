rule register_service_start: windows medium {
  meta:
    description = "installs and starts a Windows Service"

  strings:
    $s_install = "RegisterServiceCtrlHandlerA"
    $s_create  = "CreateServiceA"
    $s_start   = "StartServiceA"

  condition:
    filesize < 5MB and all of them
}

rule register_service_start_high: windows high {
  meta:
    description = "installs and starts a Windows Service"

  strings:
    $s_install = "RegisterServiceCtrlHandlerA"
    $s_create  = "CreateServiceA"
    $s_start   = "StartServiceA"
    $o_netsh   = "netsh"
    $o_filter  = "SetUnhandledExceptionFilter"

  condition:
    filesize < 200KB and all of ($s*) and any of ($o*)
}
