rule kuma_cp_binary : override {
  meta:
    description = "kuma-cp"
    downgrade = "true"
    malware_shellcode_hash = "high"
    original_severity = "critical"
  strings:
    $kuma_cp = "kuma_cp"
    $kuma_io = "kuma.io"
    $kuma_repo = "github.com/kumahq/kuma"
  condition:
    all of them
}
