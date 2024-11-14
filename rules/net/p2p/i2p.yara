rule i2p_user: high {
  meta:
    description = "Uses the I2P Anonymous Network"

  strings:
    $base32_i2p_domain = ".b32.i2p"
    $other_i2p_domain  = /\.[a-z]{1,128}\.i2p/
    $i2p_relay         = "/i2p."
    $i2p_projekt       = "i2p_projekt"
    $i2p_router        = "i2p.router"

  condition:
    any of them
}
