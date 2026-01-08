# Network Share Tools (ns-tools)

I wanted to transfer files fast, and I was bored so I wrote a tool to do this. There are 2 tools bundled in this repo.

- ns : The original network share bash script I wrote to actually do the job (without encryption)
- nsen : The tool I wrote in rust with encryption so I can use it later

## Building

### MacOS, Linux, BSD
This package is written in rust. You need **rust** and **cargo**.
```shell
cargo build -r
```

Copy and paste the nsen binary into somewhere on your path.

### Windows

Windows users please use WSL with the Linux instructions or use standard rust compilation tools for nsen

## Usage

### Receiver
```shell
nsen recv
```

### Sender
```shell
nsen send <receiver ip> <file/dir path>
```
**Remember to fill in `<receiver ip>` and `<file/dir path>` with actual values.**
