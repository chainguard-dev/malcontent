rule crossplane_aws_provider: override {
  meta:
    description              = "provider-aws-* crossplane-contrib/provider-upjet-aws Go binary"
    RUSSIANPANDA_Mintsloader = "harmless"
    BlackTech_TSCookie_elf   = "harmless"

  strings:
    $upjet_build     = "crossplane-contrib/provider-upjet-aws/internal/version"
    $upbound         = "github.com/upbound/provider-aws/v2"
    $upbound_version = "github.com/upbound/provider-aws/v2/internal/version"
    $xray_cmd        = "github.com/upbound/provider-aws/v2/cmd/provider/xray"
    $config_cmd      = "github.com/upbound/provider-aws/v2/cmd/provider/config"

  condition:
    filesize > 100MB and filesize < 1500MB and $upbound and ($upjet_build or $upbound_version or $xray_cmd or $config_cmd)
}
