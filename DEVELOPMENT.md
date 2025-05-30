
# Development

## How do I contribute new rules?

Contributing is easy! All of malcontent's rules are in [YARA](https://virustotal.github.io/yara/) format: just throw a new rule into the `rules/` subdirectory and you are ready to go.

You can verify that your new rule works by running:

```
go run ./cmd/mal analyze <path>
```

For debugging rules, it's sometimes useful to use the `yara` command:

```
yara -s -w rules/combo/dropper/shell.yara <path>
```

## Running tests

unit tests:

```make test```

integration tests:

```make integration```

## Viewing test coverage

Generate an html report in `out/coverage.html`:

```make coverage-html```

Open the coverage report in a browser automatically:

```make coverage-browser```


## Writing rule tests

Not every rule needs a test, but tests do ensure that a rules behavior stays consistent:

1. Add a sample to https://github.com/chainguard-dev/malcontent-samples
2. Create a directory within `test_data` using the same directory name as your sample:

```
mkdir -p test_data/macOS/2024.Rustdoor/
```
3. Create an empty file for a specific sample file with the ending name of ".simple":

```
touch test_data/macOS/2024.Rustdoor/fakepdf.sh.simple
```
4. Refresh all the testdata: `make refresh-sample-testdata`

## Profiling

`malcontent` can be profiled by running `--profile=true`. This will generate timestamped profiles in an untracked `profiles` directory:

```
bash-5.2$ ls -l profiles/ | grep -v "total" | awk '{ print $9 }'
cpu_329605000.pprof
mem_329605000.pprof
trace_329605000.out
```

The traces can be inspected via `go tool pprof` and `go tool trace`.

For example, the memory profile can be inspected by running:

```
go tool pprof -http=:8080 profiles/mem_<timestamp>.pprof
```
## Troubleshooting

#### Error: ld: library 'yara' not found

If you get this error at installation:

```
ld: library 'yara' not found
```

The `yara` C library is required:

```
brew install yara || sudo apt install libyara-devel || sudo dnf install yara-devel || sudo pacman -S yara
```

Additionally, ensure that Yara's version is `4.3.2`.

If this version is not available via package managers, manually download the release from [here](https://github.com/VirusTotal/yara/releases) and build it from source by following [these](https://yara.readthedocs.io/en/latest/gettingstarted.html#compiling-and-installing-yara) steps.

Once Yara is installed, run `sudo ldconfig -v` to ensure that the library is loaded.
