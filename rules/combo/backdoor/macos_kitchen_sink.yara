rule macos_kitchen_sink_binary {
  meta:
    hash_2023_KandyKorn_kandykorn = "927b3564c1cf884d2a05e1d7bd24362ce8563a1e9b85be776190ab7f8af192f6"
  strings:
    $f_sysctl = "sysctl"
    $f_mkdtemp = "mkdtemp"
    $f_mktemp = "mktemp"
    $f_inet_addr = "inet_addr"
    $f_waitpid = "waitpid"
    $f_proc_listpids = "proc_listpids"
    $f_kill = "kill"
    $f_chdir = "chdir"
    $f_setsockopt = "setsockopt"
    $f_getpid = "getpid"
    $f_unlink = "unlink"
    $f_chmod = "chmod"

	$not_osquery = "OSQUERY"
  condition:
    90% of ($f*) and none of ($not*)
}
