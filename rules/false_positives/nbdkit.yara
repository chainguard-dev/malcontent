rule nbdkit_info_plugin: override {
  meta:
    description                = "nbdkit-info-plugin.so: base64exportname is an NBD export mode"
    base64_shell_double_encode = "low"

  strings:
    $plugin = /nbdkit-info-plugin\.so/
    $mode   = /mode=exportname\|base64exportname/

  condition:
    filesize < 100KB and all of them
}
