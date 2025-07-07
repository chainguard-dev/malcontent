rule common_ip_blocklist: high {
  meta:
    description = "avoids execution if host has particular IP address"
    ref         = "https://www.zscaler.com/blogs/security-research/technical-analysis-bandit-stealer"

  strings:
    $ = "109.145.173.169" fullword
    $ = "109.74.154.90" fullword
    $ = "109.74.154.91" fullword
    $ = "109.74.154.91" fullword
    $ = "109.74.154.92" fullword
    $ = "178.239.165.70" fullword
    $ = "188.105.91.116" fullword
    $ = "188.105.91.143" fullword
    $ = "188.105.91.173" fullword
    $ = "192.211.110.74" fullword
    $ = "192.40.57.234" fullword
    $ = "192.87.28.103" fullword
    $ = "193.128.114.45" fullword
    $ = "193.225.193.201" fullword
    $ = "194.154.78.160" fullword
    $ = "195.181.175.105" fullword
    $ = "195.239.51.3" fullword
    $ = "195.239.51.59" fullword
    $ = "195.74.76.222" fullword
    $ = "20.99.160.173" fullword
    $ = "212.119.227.151" fullword
    $ = "212.119.227.167" fullword
    $ = "213.33.142.50" fullword
    $ = "23.128.248.46" fullword
    $ = "34.105.0.27" fullword
    $ = "34.105.183.68" fullword
    $ = "34.105.72.241" fullword
    $ = "34.138.96.23" fullword
    $ = "34.141.146.114" fullword
    $ = "34.141.245.25" fullword
    $ = "34.142.74.220" fullword
    $ = "34.145.195.58" fullword
    $ = "34.145.89.174" fullword
    $ = "34.253.248.228" fullword
    $ = "34.83.46.130" fullword
    $ = "34.85.243.241" fullword
    $ = "34.85.253.170" fullword
    $ = "35.192.93.107" fullword
    $ = "35.199.6.13" fullword
    $ = "35.229.69.227" fullword
    $ = "35.237.47.12" fullword
    $ = "64.124.12.162" fullword
    $ = "78.139.8.50" fullword
    $ = "79.104.209.33" fullword
    $ = "80.211.0.97" fullword
    $ = "84.147.54.113" fullword
    $ = "84.147.62.12" fullword
    $ = "87.166.50.213" fullword
    $ = "88.132.225.100" fullword
    $ = "88.132.226.203" fullword
    $ = "88.132.227.238" fullword
    $ = "88.132.231.71" fullword
    $ = "88.153.199.169" fullword
    $ = "92.211.109.160" fullword
    $ = "92.211.192.144" fullword
    $ = "92.211.52.62" fullword
    $ = "92.211.55.199" fullword
    $ = "93.216.75.209" fullword
    $ = "95.25.204.90" fullword
    $ = "95.25.81.24" fullword

  condition:
    2 of them
}
