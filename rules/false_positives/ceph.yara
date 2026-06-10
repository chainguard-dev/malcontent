rule ceph: override {
  meta:
    description            = "Ceph distributed storage system binaries and CLI tools"
    sus_dylib_tls_get_addr = "low"
    proc_d_cmdline         = "medium"
    multiple_gcc           = "low"
    multiple_gcc_high      = "low"

  strings:
    $libceph      = "libceph-common.so"
    $ceph_context = "CephContext"
    $ceph_path    = "/usr/lib/ceph"

  condition:
    filesize < 600KB and $libceph and any of ($ceph_context, $ceph_path)
}

rule ceph_base: override {
  meta:
    description            = "Ceph distributed storage system binaries"
    proc_d_cmdline         = "medium"
    sus_dylib_tls_get_addr = "medium"
    multiple_gcc_high      = "medium"

  strings:
    $libceph     = "libceph-common.so"
    $ceph_thread = "ceph_pthread_getname"

  condition:
    filesize < 20MB and all of them
}

rule ceph_tools: override {
  meta:
    description            = "Ceph distributed storage system tools"
    sus_dylib_tls_get_addr = "harmless"
    proc_d_cmdline         = "medium"
    multiple_gcc           = "low"
    multiple_gcc_high      = "low"

  strings:
    $ceph_argparse  = "ceph_argparse"
    $libceph        = "libceph-common.so"
    $g_ceph_context = "g_ceph_context"

  condition:
    filesize < 1MB and $ceph_argparse and any of ($libceph, $g_ceph_context)
}
