rule elliptic: harmless {
  strings:
    $go          = "crypto/elliptic"
    $p224        = "elliptic.p224"
    $p225        = "elliptic.p256"
    $p256inverse = "p256Inverse"

  condition:
    any of them
}
