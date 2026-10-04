rule yauaa_preheat_cases: override {
  meta:
    description                                                 = "nl/basjes/parse/useragent/PreHeatCases.class, Yauaa test user agents including Log4Shell samples"
    SIGNATURE_BASE_EXPL_JNDI_Exploit_Patterns_Dec21_1           = "harmless"
    SIGNATURE_BASE_EXPL_Log4J_Callbackdomain_Iocs_Dec21_1       = "harmless"
    SIGNATURE_BASE_SUSP_Base64_Encoded_Exploit_Indicators_Dec21 = "harmless"
    SIGNATURE_BASE_SUSP_Jdniexploit_Indicators_Dec21            = "harmless"
    http_hardcoded_ip_dev_shm                                   = "low"
    curl_download_ip                                            = "low"

  strings:
    $class_name = /nl\/basjes\/parse\/useragent\/PreHeatCases/
    $yauaa_site = /yauaa\.basjes\.nl/

  condition:
    uint32be(0) == 0xCAFEBABE and filesize < 1MB and all of them
}
