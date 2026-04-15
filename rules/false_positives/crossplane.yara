rule crossplane_aws_provider: override {
  meta:
    description              = "provider-aws-* crossplane-contrib/provider-upjet-aws Go binary"
    RUSSIANPANDA_Mintsloader = "harmless"

  strings:
    $upjet_build = "crossplane-contrib/provider-upjet-aws/internal/version"
    $upbound     = "github.com/upbound/provider-aws/v2"

  condition:
    filesize > 100MB and filesize < 1500MB and all of them
}
