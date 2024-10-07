rule nvim_binary : override {
  meta:
    description = "nvim"
    linux_multi_persist = "high"
    original_severity = "critical"
  strings:
    $nvim_generic = /nvim_\w{0,32}/
    $nvim_path = "/home/build/src/nvim"
  condition:
    all of them
}
