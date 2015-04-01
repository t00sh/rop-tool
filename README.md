ropc v2.0
====

A tool to help you writing binary exploits


### OPTIONS

```
ropc v2.0
Help you to make binary exploits.

Usage: ropc <cmd> [OPTIONS]

Commands :
   gadget      Search gadgets
   search      Search on binary
   help        Print help
   version     Print version

Try "ropc help <cmd>" for more informations about a command.

```

#### GADGET COMMAND

```
Usage : ropc gadget [OPTIONS] [FILENAME]

OPTIONS:
  --arch, -A               Select an architecture (in raw mode only)
  --all, -a                Print all gadgets
  --bad, -B           [b]  Specify bad chars in address
  --depth, -d         [d]  Specify the depth for gadget searching (default is 5)
  --flavor, -f        [f]  Select a flavor (att or intel)
  --help, -h               Print this help message
  --no-color, -n           Don't colorize output
  --raw, -r                Open file in raw mode (don't considere any file format)
```

#### SEARCH COMMAND

```
Usage : ropc search [OPTIONS] [FILENAME]

OPTIONS:
  --all-string, -a    [n]  Search all printable strings of at least [n] caracteres. (default is 6)
  --byte, -b          [b]  Search the byte [b] in binary
  --bad, -B           [b]  Specify bad chars in address
  --dword, -d         [d]  Search the dword [d] in binary
  --help, -h               Print this help message
  --no-color, -n           Don't colorize output
  --qword, -q         [q]  Search the qword [q] in binary
  --raw, -r                Open file in raw mode (don't considere any file format)
  --split-string, -s  [s]  Search a string "splited" in memory (which is not contiguous in memory)
  --string, -S        [s]  Search a string (a byte sequence) in binary
  --word, -w          [w]  Search the word [w] in binary
```


### FEATURES
* String searching, Gadget searching
* Colored output
* Intel and AT&T flavor
* Support of ELF and PE binary format
* Support of big and little endian
* Support of x86 and x86_64 architecture


### EXAMPLES

Basic gadget searching

* ropc g ./program 

Display all gadgets with AT&T syntax

* ropc g ./program -f att -a

Search in RAW file (not supported format)

* ropc g ./program -r

Search a "splitted" string in the binary

* ropc s ./program -s "/bin/sh"

Search all strings in binary

* ropc s ./program -a

### SCREENSHOTS

```
ropc gadget /bin/ls
```

![ScreenShot](https://t0x0sh.org/repo/RopC/screens/screen1.png)

```
ropc search /bin/ls -a
```

![ScreenShot](https://t0x0sh.org/repo/RopC/screens/screen2.png)

```
ropc search /bin/ls -s "/bin/sh\x00"
```

![ScreenShot](https://t0x0sh.org/repo/RopC/screens/screen3.png)

```
ropc search /bin/ls -w 0x90
```

![ScreenShot](https://t0x0sh.org/repo/RopC/screens/screen4.png)


### DEPENDENCIES
- [capstone](http://capstone-engine.org/)

### RELEASES
- https://t0x0sh.org/repo/RopC/releases/

### LICENSE
- GPLv3 license : http://www.gnu.org/licenses/gpl-3.0.txt

### AUTHOR
Tosh 

tosh -at- t0x0sh ~dot~ org

