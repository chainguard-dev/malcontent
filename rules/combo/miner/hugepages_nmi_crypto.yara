rule hugepages_probably_miner {
  meta:
    hash_2023_installer_mi = "9a5f6318a395600637bd98e83d2aea787353207ed7792ec9911b775b79443dcd"
    hash_2023_Unix_Downloader_Rocke_2f64 = "2f642efdf56b30c1909c44a65ec559e1643858aaea9d5f18926ee208ec6625ed"
    hash_2023_Downloads_9929 = "99296550ab836f29ab7b45f18f1a1cb17a102bb81cad83561f615f3a707887d7"
    hash_2021_miner_XMR_Stak = "1b1a56aec5b02355b90f911cdd27a35d099690fcbeb0e0622eaea831d64014d3"
    hash_2023_Linux_Malware_Samples_1f1b = "1f1bf32f553b925963485d8bb8cc3f0344720f9e67100d610d9e3f5f6bc002a1"
    hash_2023_Linux_Malware_Samples_240f = "240fe01d9fcce5aae311e906b8311a1975f8c1431b83618f3d11aeaff10aede3"
    hash_2023_Linux_Malware_Samples_39c3 = "39c33c261899f2cb91f686aa6da234175237cd72cfcd9291a6e51cbdc86d4def"
    hash_2023_Linux_Malware_Samples_3ff6 = "3ff6b4287e49a01724626a9e11adceee7a478aa5e5778ec139a3f9011a02f3af"
  strings:
    $hugepages = "vm.nr_hugepages"
    $s_watchdog = "kernel.nmi_watchdog"
    $s_wallet = "wallet"
    $s_xmr = "xmr"
  condition:
    $hugepages and any of ($s*)
}
