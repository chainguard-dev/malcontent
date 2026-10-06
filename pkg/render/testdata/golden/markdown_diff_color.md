## Deleted: /old/tool [🛑 HIGH]

| RISK | KEY | DESCRIPTION | EVIDENCE |
|:--|:--|:--|:--|
| -HIGH | [net/connect](https://r/connect) | connects | [AF\_INET](https://github.com/search?q=AF_INET&type=code) |
| -LOW | [fs/read](https://r/read) | reads files | |

## Added: /new/tool%1B\[2J [🟡 MEDIUM]

| RISK | KEY | DESCRIPTION | EVIDENCE |
|:--|:--|:--|:--|
| +MEDIUM | **[fs/write](https://r/write)** | writes files | [evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-](https://github.com/search?q=evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-&type=code) |

## Changed (2 added, 3 removed): /mod/changed [🔵 LOW → 🛑 HIGH]

### 2 new behaviors

| RISK | KEY | DESCRIPTION | EVIDENCE |
|:--|:--|:--|:--|
| +HIGH | **[exec/shell](https://r/shell)** | runs a shell - quickly, by Dee | [/bin/sh](https://github.com/search?q=%2Fbin%2Fsh&type=code)<br>[evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-](https://github.com/search?q=evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-evidence-&type=code) |

### 3 removed behaviors

| RISK | KEY | DESCRIPTION | EVIDENCE |
|:--|:--|:--|:--|
| -LOW | [fs/read](https://r/read) | reads files | [fopen](https://github.com/search?q=fopen&type=code) |
| -NONE | [c2/beacon](https://r/beacon) | beacons | |

## Moved (1 added, 0 removed): /mod/old-name -> /mod/new-name

### 1 new behavior

| RISK | KEY | DESCRIPTION | EVIDENCE |
|:--|:--|:--|:--|
| +MEDIUM | **[crypto/rc4](https://r/rc4)** | uses RC4 | [rc4\_init](https://github.com/search?q=rc4_init&type=code) |

## Changed (0 added, 1 removed): /mod/lowered [🛑 HIGH → 🔵 LOW]

### 1 removed behavior

| RISK | KEY | DESCRIPTION | EVIDENCE |
|:--|:--|:--|:--|
| -HIGH | [net/connect](https://r/connect) | connects | |

