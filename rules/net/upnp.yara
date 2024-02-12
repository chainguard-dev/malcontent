rule upnp_client {
  meta:
    hash_2011_bin_fxagent = "737bb6fe9a7ad5adcd22c8c9e140166544fa0c573fe5034dfccc0dc237555c83"
    hash_2021_trojan_Mirai_3_Gafgyt = "0afd9f52ddada582d5f907e0a8620cbdbe74ea31cf775987a5675226c1b228c2"
    hash_2021_trojan_Mirai_dclea = "206ad8fec64661c1fed8f20f71523466d0ca4ed9c01d20bea128bfe317f4395a"
    hash_2021_miner_gijuf = "24ee0e3d65b0593198fbe973a58ca54402b0879d71912f44f4b831003a5c7819"
    hash_2021_trojan_miner_oztkc = "2f85ca8f89dfb014b03afb11e5d2198a8adbae1da0fd76c81c67a81a80bf1965"
    hash_2021_trojan_Mirai_aspze = "341a49940749d5f07d32d1c8dfddf6388a11e45244cc54bc8768a8cd7f00b46a"
    hash_2020_HackTool_Portscan = "5a628dc26dae0309941d70021cfbb4281189f85b074bf3e696058d73c4609101"
    hash_2021_miner_nyoan = "9f059b341ac4e2e00ab33130fea5da4b1390f980d3db607384d87e736f30273e"
    hash_2021_miner_vsdhx = "caa114893cf5cb213b39591bbcb72f66ee4519be07269968e714a8d3f24c3382"
    hash_2021_miner_fdxme = "d1a95861c6b9836c0c3d8868019054931d1339ae896ad11575e99d91a358696d"
    hash_2021_trojan_Mirai_leeyo = "ff2a39baf61e34f14f9c49c27faed07bdd431605b3c845ab82023c39589e6798"
  strings:
    $upnp_firewall = "WANIPv6FirewallControl"
    $upnp_schema = "schemas-upnp-org"
    $u_ssdp_discover = "ssdp:discover"
    $u_addr = "239.255.255.250"
    $not_igd = "UPnP/IGD"
    $not_c1 = "CaptureOne"
  condition:
    any of ($u*) and none of ($not*)
}
