# xps3-client

This repository contains an open source implementation of the "xprintserver" protocol version 3.
Only two API calls are implemented: `getaccountlist` and `store3`. However, this should be enough to submit a print job.
This is only an implementation of the protocol and not a fully functional printer driver!
It is possible to print PJL data from the command line. Feel free to implement a CUPS backend for this protocol.

The goal of this code is to achieve **interoperability**! It potentially enables printing on the many platforms not
supported by the proprietary client: Smartphones, tablets, browsers, ARM notebooks, headless devices, etc.

### Dependencies

* Python 2.7
* [PyCrypto](https://www.dlitz.net/software/pycrypto/)

### Usage

Produce a file with PJL data for your print job. For example with (Ghostscript)[http://www.ghostscript.com]:

    gs -sDEVICE=pxlmono -o job.pjl -f document.pdf

Upload your job to the print server. In this example the print server is at IP `10.11.12.13` on port `1234` and we
submit a job called `MyJob` to our account `55555`:

    ./print.py 10.11.12.13 1234 55555 MyJob job.pjl

### Encryption Key

The 128-bit 3DES encryption key, which is used to encrypt/obfuscate API calls, is not included in this repository.
To obtain it, you may attach a debugger to the proprietary client and extract the key from memory.
The key's MD5 hash is `0a6d1a902be1182b7e9df7b19f7cba18`.

### License

The code in this repository is published under the MIT license.

