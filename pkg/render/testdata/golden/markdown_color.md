## /usr/bin/tool [😈 CRITICAL]

| RISK | KEY | DESCRIPTION | EVIDENCE |
|:--|:--|:--|:--|
| EXTREME | [hw/cpu]() | reads cpu info | [cpuinfo](https://github.com/search?q=cpuinfo&type=code) |
| CRITICAL | [exec/shell]() | runs shell commands, by [Bob](https://bob.example) | [/bin/sh](https://github.com/search?q=%2Fbin%2Fsh&type=code)<br>[sh -c](https://github.com/search?q=sh+-c&type=code)<br>`$sh_var` |
| CRIT | [malware/family]() | names a family | [family](https://github.com/search?q=family&type=code) |
| HIGH | [anti-static/obfuscation/hex]() | hex-encoded payload | [\\x41\\x42](https://github.com/search?q=%5Cx41%5Cx42&type=code)<br>[evil%1B\[2Jpayload%09tab](https://github.com/search?q=evil%1B%5B2Jpayload%09tab&type=code)<br>[naïve 😈 ‮rtl](https://github.com/search?q=na%C3%AFve+%F0%9F%98%88+%E2%80%AErtl&type=code) |
| HIGH | [c2/addr/url]() | [contains a hardcoded URL](https://ref.example/url) | [https:&#8203;//example.com/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa](<https://example.com/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa>)<br>[http:&#8203;//x.example/a\|b](<http://x.example/a%7Cb>) |
| MED | [collect/files]() | collects files | [glob](https://github.com/search?q=glob&type=code) |
| MEDIUM | [fs/file/write]() | writes files - often, by Dee | [fwrite](https://github.com/search?q=fwrite&type=code)<br>[fopen](https://github.com/search?q=fopen&type=code) |
| MEDIUM | [net/socket/connect](https://r/connect) | connects to a remote host - via TCP, by Alice | [connect](https://github.com/search?q=connect&type=code)<br>[AF\_INET](https://github.com/search?q=AF_INET&type=code)<br>[ab](https://github.com/search?q=ab&type=code) |
| MEDIUM | [sus/text]() | by Carol | [password](https://github.com/search?q=password&type=code)<br>[credential](https://github.com/search?q=credential&type=code) |
| LOW | [fs/file/read]() | reads files | |
| LOW | [net/dns]() | resolves names | [gethostbyname](https://github.com/search?q=gethostbyname&type=code) |
| NONE | [nonamespace]() | no slash in the ID | [abcd](https://github.com/search?q=abcd&type=code)<br>[abcde](https://github.com/search?q=abcde&type=code) |
| | [os/env/get]() | calls getenv | [getenv](https://github.com/search?q=getenv&type=code)<br>[setenv](https://github.com/search?q=setenv&type=code) |

## /tmp/naïve 😈%1B\]0;title%07\\back‮slash [🔵 LOW]

| RISK | KEY | DESCRIPTION | EVIDENCE |
|:--|:--|:--|:--|
| LOW | [fs/write]() | writes files | [fopen](https://github.com/search?q=fopen&type=code) |

## /opt/escapes [🟡 MEDIUM]

| RISK | KEY | DESCRIPTION | EVIDENCE |
|:--|:--|:--|:--|
| MEDIUM | [evasion/sweep-0-1]() | plain description | [q](https://github.com/search?q=q&type=code) |
| MEDIUM | [evasion/sweep-0-2]() | plain description | [qq](https://github.com/search?q=qq&type=code) |
| MEDIUM | [evasion/sweep-0-3]() | plain description | [qqq](https://github.com/search?q=qqq&type=code) |
| MEDIUM | [evasion/sweep-0-4]() | plain description | [qqqq](https://github.com/search?q=qqqq&type=code) |
| MEDIUM | [evasion/sweep-1-1]() | ends in a partial escape [ | [1mq](https://github.com/search?q=1mq&type=code) |
| MEDIUM | [evasion/sweep-1-2]() | ends in a partial escape [ | [1mqq](https://github.com/search?q=1mqq&type=code) |
| MEDIUM | [evasion/sweep-1-3]() | ends in a partial escape [ | [1mqqq](https://github.com/search?q=1mqqq&type=code) |
| MEDIUM | [evasion/sweep-1-4]() | ends in a partial escape [ | [1mqqqq](https://github.com/search?q=1mqqqq&type=code) |
| MEDIUM | [evasion/sweep-2-1]() | ends in an escape byte  | [\[0mq](https://github.com/search?q=%5B0mq&type=code) |
| MEDIUM | [evasion/sweep-2-2]() | ends in an escape byte  | [\[0mqq](https://github.com/search?q=%5B0mqq&type=code) |
| MEDIUM | [evasion/sweep-2-3]() | ends in an escape byte  | [\[0mqqq](https://github.com/search?q=%5B0mqqq&type=code) |
| MEDIUM | [evasion/sweep-2-4]() | ends in an escape byte  | [\[0mqqqq](https://github.com/search?q=%5B0mqqqq&type=code) |
| MEDIUM | [evasion/sweep-3-1]() | has a whole escape [31mred[0m and [10Gcolumn | [2;3Gq](https://github.com/search?q=2%3B3Gq&type=code) |
| MEDIUM | [evasion/sweep-3-2]() | has a whole escape [31mred[0m and [10Gcolumn | [2;3Gqq](https://github.com/search?q=2%3B3Gqq&type=code) |
| MEDIUM | [evasion/sweep-3-3]() | has a whole escape [31mred[0m and [10Gcolumn | [2;3Gqqq](https://github.com/search?q=2%3B3Gqqq&type=code) |
| MEDIUM | [evasion/sweep-3-4]() | has a whole escape [31mred[0m and [10Gcolumn | [2;3Gqqqq](https://github.com/search?q=2%3B3Gqqqq&type=code) |

