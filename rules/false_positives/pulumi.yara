rule pulumi_binary : override {
  meta:
    description = "pulumi"
    malware_shellcode_hash = "high"
    original_severity = "critical"
  strings:
    $author = ".Package.Publisher \"Pulumi Corp.\""
    $pulumi = "github.com/pulumi"
    $pulumi_repo = "github.com/pulumi/pulumi"
  condition:
    all of them
}
