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

    $not_printdeps_exe = {55 73 61 67 65 3A 0A 20 20 50 72 69 6E 74 44 65 70 73 20 46 49 4C 45 2E 2E 2E 00 00 00 00 00 56 65 72 73 69 6F 6E 3A 20 72 00 00 25 70 00 00 65 45 00 00 70 50}
  condition:
	filesize < 1MB and 1 of ($kill*) and 2 of ($debug*) and 1 of ($f*) and none of ($not_*)
}

rule win_kill_proc : critical {
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

    $not_printdeps_exe = {55 73 61 67 65 3A 0A 20 20 50 72 69 6E 74 44 65 70 73 20 46 49 4C 45 2E 2E 2E 00 00 00 00 00 56 65 72 73 69 6F 6E 3A 20 72 00 00 25 70 00 00 65 45 00 00 70 50}
  condition:
	filesize < 1MB and all of ($kill*) and 3 of ($debug*) and 1 of ($f*) and none of ($not_*)
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
