## linux/clean/ls.x86_64 [🟡 MEDIUM]

| RISK | KEY | DESCRIPTION | EVIDENCE |
|:--|:--|:--|:--|
| MEDIUM | [process/name_set]() | [get or set the current process name](https://stackoverflow.com/questions/273691/using-progname-instead-of-argv0) | [__progname](https://github.com/search?q=__progname&type=code) |
| LOW | [c2/addr/url]() | binary contains hardcoded URL | [https://wiki.xiph.org/MIME_Types_and_File_Extensions](https%3A%2F%2Fwiki.xiph.org%2FMIME_Types_and_File_Extensions)<br>[https://www.gnu.org/software/coreutils/](https%3A%2F%2Fwww.gnu.org%2Fsoftware%2Fcoreutils%2F)<br>[https://translationproject.org/team/](https%3A%2F%2Ftranslationproject.org%2Fteam%2F)<br>[https://gnu.org/licenses/gpl.html](https%3A%2F%2Fgnu.org%2Flicenses%2Fgpl.html) |
| LOW | [c2/tool_transfer/arch]() | references a specific architecture | [https://](https%3A%2F%2F)<br>[x86](https://github.com/search?q=x86&type=code) |
| LOW | [c2/tool_transfer/os]() | references a specific operating system | [https://](https%3A%2F%2F)<br>[linux](https://github.com/search?q=linux&type=code) |
| LOW | [data/compression/lzma]() | [works with lzma files](https://en.wikipedia.org/wiki/Lempel%E2%80%93Ziv%E2%80%93Markov_chain_algorithm) | [lzma](https://github.com/search?q=lzma&type=code) |
| LOW | [discover/system/hostname]() | [get computer host name](https://man7.org/linux/man-pages/man2/sethostname.2.html) | [gethostname](https://github.com/search?q=gethostname&type=code) |
| LOW | [exec/shell/TERM]() | [Look up or override terminal settings](https://www.gnu.org/software/gettext/manual/html_node/The-TERM-variable.html) | [TERM](https://github.com/search?q=TERM&type=code) |
| LOW | [fs/link_read]() | [read value of a symbolic link](https://man7.org/linux/man-pages/man2/readlink.2.html) | [readlink](https://github.com/search?q=readlink&type=code) |
| LOW | [net/url/embedded]() | contains embedded HTTPS URLs | [https://wiki.xiph.org/MIME_Types_and_File_Extensions](https%3A%2F%2Fwiki.xiph.org%2FMIME_Types_and_File_Extensions)<br>[https://www.gnu.org/software/coreutils/](https%3A%2F%2Fwww.gnu.org%2Fsoftware%2Fcoreutils%2F)<br>[https://translationproject.org/team/](https%3A%2F%2Ftranslationproject.org%2Fteam%2F)<br>[https://gnu.org/licenses/gpl.html](https%3A%2F%2Fgnu.org%2Flicenses%2Fgpl.html) |
| LOW | [os/env/get]() | Retrieve environment variables | [getenv](https://github.com/search?q=getenv&type=code) |

