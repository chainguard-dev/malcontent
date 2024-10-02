rule win_kill_proc_likely : high {
  meta:
    description = "Likely Windows EDR/Antivirus bypass"
  strings:
	$f_gcp = "GetCurrentProcess"
	$f_gct = "GetCurrentThread"
	$f_time = "GetSystemTimeAsFileTime"
	$debug_pfp = "IsProcessorFeaturePresent"
	$debug_qpc = "QueryPerformanceCounter"
	$debug_idp = "IsDebuggerPresent"
	$debug_uhf = "UnhandledExceptionFilter"
	$kill_gmh = "GetModuleHandle"
	$kill_tp = "TerminateProcess"

  condition:
	filesize < 1MB and 1 of ($kill*) and 2 of ($debug*) and 1 of ($f*)
}

rule win_kill_proc : high {
  meta:
    description = "Windows EDR/Antivirus bypass"
  strings:
	$f_gcp = "GetCurrentProcess"
	$f_gct = "GetCurrentThread"
	$f_time = "GetSystemTimeAsFileTime"
	$debug_pfp = "IsProcessorFeaturePresent"
	$debug_qpc = "QueryPerformanceCounter"
	$debug_idp = "IsDebuggerPresent"
	$debug_uhf = "UnhandledExceptionFilter"
	$kill_gmh = "GetModuleHandle"
	$kill_tp = "TerminateProcess"

  condition:
	filesize < 1MB and all of ($kill*) and 3 of ($debug*) and 1 of ($f*)
}

rule edr_stopper : critical {
  meta:
    description = "Stops EDR/Antivirus services"
  strings:
	$kind_malwarebytes = "alwarebytes"
	$stop = "stopservice"
  condition:
	filesize < 1MB and $stop and any of ($kind*)
}
