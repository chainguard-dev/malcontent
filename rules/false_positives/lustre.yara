rule sanity_sec_test: override {
  meta:
    description          = "sanity-sec.sh"
    rename_system_binary = "medium"
    chmod_dangerous_exec = "medium"

  strings:
    $function = "check_and_setup_lustre"
    $lustre   = "lustre"
    $source   = ". $LUSTRE/tests/test-framework.sh"
    $test     = /test_\w+{1,3}/

  condition:
    filesize < 512KB and #lustre > 50 and all of them
}

rule sanity_test: override {
  meta:
    description          = "sanity.sh"
    rename_system_binary = "medium"
    chmod_dangerous_exec = "medium"
    kill_unusual         = "medium"

  strings:
    $function = "check_and_setup_lustre"
    $lustre   = "lustre"
    $regexp   = "proc_regexp=\"/{proc,sys}/{fs,sys,kernel/debug}/{lustre,lnet}/\""
    $test     = /test_\w+{1,3}/

  condition:
    filesize < 2MB and #lustre > 200 and all of them
}
