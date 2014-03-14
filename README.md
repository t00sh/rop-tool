ropc
====

Tool for finding gadgets in ELF32 binaries.


=== OPTIONS

```
Usage : ./ropc [options]
Tool for searching Gadgets in ELF binaries

MODES
  -G --gadget        Gadget searching mode
  -S --string        String searching mode
  -P --payload       Payload generator mode

Gadget Mode
  -b, --bad          Specify bad chars
  -d, --depth        Specify the depth searching
  -f, --file         Specify the file
  -a, --all          Display all gadgets
  -n, --no-color     No colored output
  -F, --flavor       Specify the flavor (intel or att)

String Mode
  -b, --bad          Specify bad chars
  -f, --file         Specify the file
  -s, --search       Specify the string to search

General options
  -h, --help         Print help
  -v, --version      Print version

=== AUTHOR
Tosh 

duretsimon73 -at- gmail ~dot~ com