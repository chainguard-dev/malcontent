rule microvm_init_initramfs: override {
  meta:
    description               = "microvm-init prebuilt initramfs cpio archive"
    http_url_with_exe         = "low"
    root_authorized_keys      = "medium"
    unusual_cd_dev            = "medium"
    selinux_disable_val       = "low"
    linux_network_filter_exec = "medium"
    var_hidden                = "low"
    suspected_data_stealer    = "low"

  strings:
    $microvm_init = "microvm-init@local"
    $virtio_init  = "9pnet_virtio"
    $sshd_config  = "sshd_config.d/microvm-init.conf"

  condition:
    filesize < 300MB and $microvm_init and any of ($virtio_init, $sshd_config)
}
