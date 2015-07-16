# openssl-version_scan
Ever wanted to know which versions of OpenSSL are really deployed on your servers? openssl-version_scan scans processes and directories for OpenSSL version information and lists versions numbers for both statically and dynamically linked libraries.

Note: Currently relies on ldd to resolve shared libraries. You might want to disable this behavior by providing the ```--no-shared``` option as this can be a security risk when run on untusted binaries.

Use at own risk.

### usage

      USAGE: ossl.py [options...] <path1> ... <pathN>

          options:
          -p, --procs                   scan running processes
          -i, --ignore-prefix=<path>    skip files prefixed with <path,...>

          -S, --no-shared               do NOT scan shared libraries
          -M, --no-mmap                 do NOT use memory mapped files (significant slower)

          -w, --wikimarkup              enable wiki style table output
          -v, --verbosity=<level>       <level> 0 [none] ... 10 [debug] ... 20 [info] ... 50 [critical]
          -l, --logfile=<file>          log output to <file>

### example

        # scan all files
        #> python openssl_scan.py --procs --ignore-prefix=/proc/ /
        # scan /usr/sbin
        #> python openssl_scan.py --procs  /usr/sbin
        2015-07-15 22:18:51,484 [MainThread  ] [INFO ]  [*] scanning process list...
        2015-07-15 22:18:55,891 [MainThread  ] [INFO ]  [*] scanning path (recursive): /usr/sbin ...
        2015-07-15 22:19:02,202 [MainThread  ] [INFO ]  ===========Results============
        2015-07-15 22:19:02,202 [MainThread  ] [INFO ]  [>] File Overview:
        2015-07-15 22:19:02,204 [MainThread  ] [INFO ]  * File: /usr/lib/i386-linux-gnu/i686/cmov/libcrypto.so.1.0.0
         ** [static]  set(['OpenSSL 1.0.1e'])
         ** [dynamic] set([])
        2015-07-15 22:19:02,205 [MainThread  ] [INFO ]  * File: /usr/sbin/tkiptun-ng
         ** [static]  set([])
         ** [dynamic] set(['OpenSSL 1.0.1e'])
        2015-07-15 22:19:02,205 [MainThread  ] [INFO ]  * File: /usr/sbin/airbase-ng
         ** [static]  set([])
         ** [dynamic] set(['OpenSSL 1.0.1e'])
        2015-07-15 22:19:02,205 [MainThread  ] [INFO ]  * File: /usr/lib/libnetsnmptrapd.so.15
         ** [static]  set([])
         ** [dynamic] set(['OpenSSL 1.0.1e'])
        2015-07-15 22:19:02,206 [MainThread  ] [INFO ]  * File: /usr/sbin/unafs
         ** [static]  set([])
         ** [dynamic] set(['OpenSSL 1.0.1e'])
        2015-07-15 22:19:02,206 [MainThread  ] [INFO ]  * File: /usr/sbin/besside-ng
         ** [static]  set([])
         ** [dynamic] set(['OpenSSL 1.0.1e'])
        2015-07-15 22:19:02,206 [MainThread  ] [INFO ]  * File: /usr/sbin/dsniff
         ** [static]  set([])
         ** [dynamic] set(['OpenSSL 1.0.1e'])
        2015-07-15 22:19:02,206 [MainThread  ] [INFO ]  * File: /usr/lib/libnetsnmp.so.15
         ** [static]  set([])
         ** [dynamic] set(['OpenSSL 1.0.1e'])
        2015-07-15 22:19:02,206 [MainThread  ] [INFO ]  * File: /usr/bin/ssh-agent
         ** [static]  set([])
         ** [dynamic] set(['OpenSSL 1.0.1e'])
        2015-07-15 22:19:02,206 [MainThread  ] [INFO ]  * File: /usr/sbin/sshd
         ** [static]  set([])
         ** [dynamic] set(['OpenSSL 1.0.1e'])
        2015-07-15 22:19:02,206 [MainThread  ] [INFO ]  * File: /usr/lib/libnetsnmphelpers.so.15
         ** [static]  set([])
         ** [dynamic] set(['OpenSSL 1.0.1e'])
        2015-07-15 22:19:02,207 [MainThread  ] [INFO ]  * File: /usr/sbin/snmptrapd
         ** [static]  set([])
         ** [dynamic] set(['OpenSSL 1.0.1e'])
        2015-07-15 22:19:02,208 [MainThread  ] [INFO ]  * File: /usr/lib/i386-linux-gnu/i686/cmov/libssl.so.1.0.0
         ** [static]  set(['OpenSSL 1.0.1e'])
         ** [dynamic] set(['OpenSSL 1.0.1e'])
        2015-07-15 22:19:02,208 [MainThread  ] [INFO ]  * File: /usr/lib/i386-linux-gnu/libpkcs11-helper.so.1
         ** [static]  set([])
         ** [dynamic] set(['OpenSSL 1.0.1e'])
        2015-07-15 22:19:02,209 [MainThread  ] [INFO ]  * File: /usr/sbin/snmpd
         ** [static]  set([])
         ** [dynamic] set(['OpenSSL 1.0.1e'])
        2015-07-15 22:19:02,209 [MainThread  ] [INFO ]  * File: /usr/sbin/ettercap
         ** [static]  set([])
         ** [dynamic] set(['OpenSSL 1.0.1e'])
        2015-07-15 22:19:02,209 [MainThread  ] [INFO ]  * File: /usr/sbin/tcpdump
         ** [static]  set([])
         ** [dynamic] set(['OpenSSL 1.0.1e'])
        2015-07-15 22:19:02,209 [MainThread  ] [INFO ]  * File: /usr/sbin/mini-httpd
         ** [static]  set([])
         ** [dynamic] set(['OpenSSL 1.0.1e'])
        2015-07-15 22:19:02,209 [MainThread  ] [INFO ]  * File: /usr/sbin/airodump-ng
         ** [static]  set([])
         ** [dynamic] set(['OpenSSL 1.0.1e'])
        2015-07-15 22:19:02,209 [MainThread  ] [INFO ]  * File: /usr/sbin/openvpn
         ** [static]  set([])
         ** [dynamic] set(['OpenSSL 1.0.1e'])
        2015-07-15 22:19:02,209 [MainThread  ] [INFO ]  * File: /usr/sbin/john
         ** [static]  set([])
         ** [dynamic] set(['OpenSSL 1.0.1e'])
        2015-07-15 22:19:02,209 [MainThread  ] [INFO ]  * File: /usr/sbin/aireplay-ng
         ** [static]  set([])
         ** [dynamic] set(['OpenSSL 1.0.1e'])
        2015-07-15 22:19:02,210 [MainThread  ] [INFO ]  * File: /usr/lib/libnetsnmpmibs.so.15
         ** [static]  set([])
         ** [dynamic] set(['OpenSSL 1.0.1e'])
        2015-07-15 22:19:02,210 [MainThread  ] [INFO ]  * File: /usr/sbin/ntpd
         ** [static]  set([])
         ** [dynamic] set(['OpenSSL 1.0.1e'])
        2015-07-15 22:19:02,210 [MainThread  ] [INFO ]  * File: /usr/lib/libnetsnmpagent.so.15
         ** [static]  set([])
         ** [dynamic] set(['OpenSSL 1.0.1e'])
        2015-07-15 22:19:02,210 [MainThread  ] [INFO ]  * File: /usr/sbin/unique
         ** [static]  set([])
         ** [dynamic] set(['OpenSSL 1.0.1e'])
        2015-07-15 22:19:02,210 [MainThread  ] [INFO ]  * File: /usr/sbin/unshadow
         ** [static]  set([])
         ** [dynamic] set(['OpenSSL 1.0.1e'])
        2015-07-15 22:19:02,210 [MainThread  ] [INFO ]  * File: /usr/sbin/wesside-ng
         ** [static]  set([])
         ** [dynamic] set(['OpenSSL 1.0.1e'])
        2015-07-15 22:19:02,210 [MainThread  ] [INFO ]  * File: /usr/sbin/sshmitm
         ** [static]  set([])
         ** [dynamic] set(['OpenSSL 1.0.1e'])
        2015-07-15 22:19:02,210 [MainThread  ] [INFO ]  * File: /usr/sbin/airtun-ng
         ** [static]  set([])
         ** [dynamic] set(['OpenSSL 1.0.1e'])
        2015-07-15 22:19:02,211 [MainThread  ] [INFO ]  * File: /usr/sbin/webmitm
         ** [static]  set([])
         ** [dynamic] set(['OpenSSL 1.0.1e'])
        2015-07-15 22:19:02,211 [MainThread  ] [INFO ]  * File: /usr/sbin/ntp-keygen
         ** [static]  set(['OpenSSL 1.0.1c'])
         ** [dynamic] set(['OpenSSL 1.0.1e'])
        2015-07-15 22:19:02,211 [MainThread  ] [INFO ]  ==========Statistics==========
        2015-07-15 22:19:02,211 [MainThread  ] [INFO ]  [>] Scan:
        2015-07-15 22:19:02,211 [MainThread  ] [INFO ]   Candidate files (total):      1250
        2015-07-15 22:19:02,211 [MainThread  ] [INFO ]   Files scanned:                 557
        2015-07-15 22:19:02,211 [MainThread  ] [INFO ]   Traces of openssl detected:     32
        2015-07-15 22:19:02,212 [MainThread  ] [INFO ]   * static traces:                 3
        2015-07-15 22:19:02,212 [MainThread  ] [INFO ]   * shared library references:    31
        2015-07-15 22:19:02,212 [MainThread  ] [INFO ]  [>] distinct openssl versions:
        2015-07-15 22:19:02,212 [MainThread  ] [INFO ]  * OpenSSL 1.0.1c
        2015-07-15 22:19:02,212 [MainThread  ] [INFO ]  * OpenSSL 1.0.1e
        2015-07-15 22:19:02,212 [MainThread  ] [INFO ]  [>] version overview:
        2015-07-15 22:19:02,212 [MainThread  ] [INFO ]         version         |  static  | shared references |
        2015-07-15 22:19:02,213 [MainThread  ] [INFO ]  ---------------------- |----------|-------------------|
        2015-07-15 22:19:02,213 [MainThread  ] [INFO ]  * OpenSSL 1.0.1c       |       1  |                1  |
        2015-07-15 22:19:02,213 [MainThread  ] [INFO ]  * OpenSSL 1.0.1e       |       2  |               50  |
        2015-07-15 22:19:02,213 [MainThread  ] [INFO ]  [i] this scan took 10.73 seconds
