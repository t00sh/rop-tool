ropc
====

Tool for finding gadgets in binaries.


### OPTIONS

```
Usage : ./ropc [OPTIONS] filename
Tool for searching Gadgets in ELF binaries

MODES
  -G, --gadget       Gadget searching mode
  -S, --string       String searching mode (argument required)
  -P, --payload      Payload generator mode

Payload options
  -p, --ptype       Specify the payload generator to use
  -l, --list        List payload generators available

Filter options
  -b, --bad          Specify bad chars
  -d, --depth        Specify the depth searching (gadget mode only)
  -a, --all          Display all gadgets (gadget mode only)

Output options
  -n, --no-color     No colors
  -f, --flavor       Specify the flavor (gadget mode only) : intel or att

General options
  -r, --raw          Open file in raw mode
  -h, --help         Print help
  -v, --version      Print version

```

### FEATURES
* Multiples modes : String searching, Gadget searching and Payload generator
* Colored output
* Intel and AT&T flavor
* Support of ELF and PE binary format
* Support of I386 and IA64 architecture
* ...


### EXAMPLES

Basic gadget searching

* ropc ./program 

Search gadgets and exclude bad bytes in address

* ropc ./program -b "\x00\x0a"

Display all gadgets with AT&T syntax

* ropc ./program -f att -a

List payloads

* ropc -l

Genere a payload

* ropc ./program -P

Search a string in memory

* ropc ./program -S "/bin/sh"

Search in RAW file (not supported format)

* ropc ./program -r

### AUTHOR
Tosh 

duretsimon73 -at- gmail ~dot~ com