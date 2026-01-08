rule file_context: override {
  meta:
    description         = "file_contexts.bin"
    dev_shm_file        = "medium"
    dev_shm_hidden      = "medium"
    hidden_pid_file     = "medium"
    kmem                = "medium"
    linux_multi_persist = "medium"
    sshd_path_value     = "medium"
    var_tmp_path_hidden = "medium"

  strings:
    $selinux  = "selinux"
    $s2rp     = "\"S2RP"
    $pattern1 = "!\"#$%&'()*+,-./0123456789:;<=>?@abcdefghijklmnopqrstuvwxyz[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"
    $pattern2 = "!\"#$%&'()*+,-./0123456789:;<=>?@abcdefghijklmnopqrstuvwxyz[\\]^_`ABCDEFGHIJKLMNOPQRSTUVWXYZ{|}~"
    $ercp     = "ERCP"

  condition:
    filesize < 6MB and #selinux > 50 and $s2rp and all of ($pattern*) and $ercp
}
