rule go_scan_tool_val: medium {
  meta:
    description = "Uses struct with JSON representations for host:port"

  strings:
    $j_port     = "json:\"port\""
    $j_hostname = "json:\"hostname\""
    $j_host     = "json:\"host\""
    $j_hip      = "json:\"ip\""

  condition:
    $j_port and any of ($j_h*)
}

rule host_port_ref: medium {
  meta:
    description = "connects to an arbitrary host:port"

  strings:
    $host_port = /host.{0,12}port/

  condition:
    any of them
}

rule hostname_port: medium {
  meta:
    description = "connects to an arbitrary hostname:port"

  strings:
    $hostname = "hostname" fullword
    $port     = "port" fullword

  condition:
    all of them
}

rule port_number: medium {
  meta:
    description = "references a 'port number'"

  strings:
    $port_sp_number = "port number" fullword
    $port_number    = "port_number" fullword

  condition:
    any of them
}

rule hardcoded_host_port: medium {
  meta:
    description = "hardcoded hostname:port destination"

  strings:
    $h_domain_tld        = /[a-z]{3,16}\.[a-z]{3}:\d{2,5}/ fullword
    $host_domain_tld     = /[a-z]{3,64}\.[a-z]{3,64}\.[a-z]{2,3}:\d{2,5}/ fullword
    $host_domain_sld_tld = /[a-z]{3,64}\.[a-z]{3,64}\.[a-z]{2,3}\.[a-z]{2,3}:\d{2,5}/ fullword

  condition:
    any of ($h*)
}

rule hardcoded_host_port_over_10k: high {
  meta:
    description = "hardcoded hostname:port destination with high port"

  strings:
    $h_domain_tld        = /[a-z]{3,16}\.[a-z]{3}:\d{4,5}/ fullword
    $host_domain_tld     = /[a-z]{3,64}\.[a-z]{3,64}\.[a-z]{2,3}:\d{4,5}/ fullword
    $host_domain_sld_tld = /[a-z]{3,64}\.[a-z]{3,64}\.[a-z]{2,3}\.[a-z]{2,3}:\d{4,5}/ fullword

    $not_roughtime_cloudflare = "roughtime.cloudflare.com:2003"
    $not_roughtime_google     = "sandbox.google.com:2002"
    $not_foo_bar              = "foo.bar:"
    $not_example_com          = "example.com:"
    $not_mygateway            = "mygateway.com:"
    $not_mymachine            = "mymachine.com:"
    $not_ruby_http            = "http://hypnotoad.org:1234?hail=all"
    $not_test_parse           = "test_parse"
    $not_slash_test           = "/test" fullword
    $not_test_message         = "test_message"
    $not_unit_test            = "unit test"
    $not_example_registry     = "registry.com:5000"

  condition:
    any of ($h*) and none of ($not*)
}
