rule nuclei: override {
  meta:
    description               = "nuclei vulnerability scanner binary"
    http_hardcoded_ip_dev_shm = "medium"

  strings:
    $module           = /github\.com\/projectdiscovery\/nuclei\/v3/
    $projectdiscovery = /projectdiscovery\.io/

  condition:
    filesize < 200MB and all of them
}
