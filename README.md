# LibWres

## Microsoft® Windows™ is a registered trademark of Microsoft® Corporation. This name is used for referential use only, and does not aim to usurp copyrights from Microsoft. Microsoft Ⓒ 2025 All rights reserved. All resources belong to Microsoft Corporation.

## Introduction

LibWres is a C++ library for reading and parsing Windows Portable Executable (PE) files. Based on wrestool from [icoutils](https://www.nongnu.org/icoutils/).

This library is primarily written for [libqmsstyles](https://github.com/The-Evil-Ass-Fountain-Openers/libqmsstyles), but it can be used as a generic library for parsing and extracing resources from files that follow the PE format (`.exe`, `.dll`, `.mui`, `.msstyles`, etc. files).

## Testing 

After building the library, do the following:

```bash
$ cd /path/to/libwres/build/test 
$ ./libwrestest > log.txt
```

## Credits

- [Wine](https://www.winehq.org/) for winemine.exe and shell32.dll used for testing
- [SandTechStuff's](https://github.com/SandTechStuff) [Aero11](https://github.com/SandTechStuff/Aero11) msstyles theme used for testing
