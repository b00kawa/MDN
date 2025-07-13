# magic_number_detector.py  
A simple CLI utility to identify files by their magic numbers (file signatures).  
Created for learning purposes and for experimenting with file identification via headers.

## Purpose

A lightweight tool to analyze files and determine their type based on known and custom magic numbers.  
Ideal for CTFs, DFIR, and general file forensics.

---

## Usage:

```
python magic_number_detector.py path/to/file [another/file ...]
```

## Options:
    -j, --json     Output results in JSON format (useful for scripts).
    -l, --list     List all known magic numbers.
    --add HEX:NAME Add a custom magic number definition (hex string without
                   spaces) mapped to NAME. Can be supplied multiple times.

## Examples:
    python magic_number_detector.py sample.pdf
    python magic_number_detector.py *.bin -j
    python magic_number_detector.py --list
    python magic_number_detector.py firmware.bin --add "7f454c46:ELF Executable"

