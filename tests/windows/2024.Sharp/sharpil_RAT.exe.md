## windows/2024.Sharp/sharpil_RAT.exe [😈 CRITICAL]

| RISK | KEY | DESCRIPTION | EVIDENCE |
|:--|:--|:--|:--|
| CRITICAL | [3P/YARAForge/ditekshen_telegramchatbot](https://github.com/ditekshen/detection/blob/e76c93dcdedff04076380ffc60ea54e45b313635/yara/indicator_suspicious.yar#L1293-L1308) | Detects executables using Telegram Chat Bot, by [ditekSHen](https://github.com/ditekshen/detection) | `$p1`<br>`$p2`<br>`$s1`<br>`$s2`<br>`$s4` |
| HIGH | [net/email/send]() | sends e-mail with a hardcoded credentials | [NetworkCredential](https://github.com/search?q=NetworkCredential&type=code) |
| MEDIUM | [c2/addr/discord]() | may report back to 'Discord' | [Discord](https://github.com/search?q=Discord&type=code) |
| MEDIUM | [c2/addr/telegram]() | telegram | [Telegram](https://github.com/search?q=Telegram&type=code) |
| MEDIUM | [data/embedded/app_manifest]() | [Contains embedded Microsoft Windows application manifest](https://learn.microsoft.com/en-us/cpp/build/reference/manifestuac-embeds-uac-information-in-manifest?view=msvc-170) | [requestedExecutionLevel](https://github.com/search?q=requestedExecutionLevel&type=code)<br>[requestedPrivileges](https://github.com/search?q=requestedPrivileges&type=code) |
| MEDIUM | [discover/processes/list]() | accesses process list | [ProcessList](https://github.com/search?q=ProcessList&type=code) |
| MEDIUM | [exfil/stealer/browser]() | may access cookies | [Cookies](https://github.com/search?q=Cookies&type=code) |
| MEDIUM | [net/download]() | download files | [DownloadString](https://github.com/search?q=DownloadString&type=code)<br>[Downloads](https://github.com/search?q=Downloads&type=code) |
| MEDIUM | [net/ip/addr]() | mentions an 'IP address' | [ipAddr](https://github.com/search?q=ipAddr&type=code) |
| LOW | [anti-behavior/random_behavior]() | uses a random number generator | [Random](https://github.com/search?q=Random&type=code) |
| LOW | [credential/password]() | references a 'password' | [Passwords](https://github.com/search?q=Passwords&type=code) |
| LOW | [crypto/public_key]() | references a 'public key' | [PublicKey](https://github.com/search?q=PublicKey&type=code) |
| LOW | [fs/directory/create]() | [creates directories](https://man7.org/linux/man-pages/man2/mkdir.2.html) | [CreateDirectory](https://github.com/search?q=CreateDirectory&type=code) |
| LOW | [hw/wireless]() | wireless network base station ID | [BSSID](https://github.com/search?q=BSSID&type=code) |

