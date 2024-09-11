rule tool_frp_str {
    meta:
        description = "Detect fast reverse proxy (frp)"
        author = "JPCERT/CC Incident Response Group"
        reference = "https://github.com/fatedier/frp"

    strings:
        $str1 = "json:\"dst_addr\""
        $str2 = "json:\"bind_addr\""
        $str3 = "json:\"proxy_name\""
        $str4 = "json:\"log_way\""
        $str5 = "json:\"maxdays\""
        $str6 = "json:\"sk\""
        $str7 = "json:\"authenticate_new_work_conns\""
        $str8 = "json:\"detailed_errors_to_client\""
        $str9 = "json:\"oidc_skip_expiry_check\""
        $str10 = "json:\"health_check_interval_s\""
        $str11 = "json:\"token_type,omitempty\""

    condition:
        6 of ($str*)
}