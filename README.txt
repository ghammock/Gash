Gash - A multiple algorithm file integrity checker
Copyright (C) 2014 Gary Hammock, PE

================================================================================
                                DESCRIPTION
================================================================================

Gash is an application that can use different types of hashing algorithms to
calculate a file's message digest or hash.

================================================================================
                                   USAGE
================================================================================

Linux/Unix:
    gash <hashType> [filename]
           or
    gash <options>

Windows(R):
    gash.exe <hashType> [filename]
           or
    gash.exe <options>

================================================================================
                                 HASH TYPES
================================================================================
Note: The flags are case sensitive!

    Hash Type        Flag
    ---------        ----
    MD5              -md5
    SHA-256          -sha256
    CRC-32           -crc32
    ELF              -elf

================================================================================
                                 REFERENCES
================================================================================
1.) Rivest, Ron.  RFC 1321.  "The MD5 Message-Digest Algorithm".  MIT Laboratory
      for Computer Science and RSA Data Security, Inc. Apr 1992.

2.) Schneier, Bruce.  "Applied Cryptography".  2nd Edition. John Wiley & Sons,
      Inc.  New York.  1996.

3.) FIPS 180-1, "Secure Hash Standard".  17 Apr 1995.  National Institute of
      Standards and Technology.

4.) FIPS 180-2, "Secure Hash Standard".  01 Aug 2002.  National Institute of
      Standards and Technology.

5.) Wikipedia. Website.  "Cyclic Redundancy Check".
      http://en.wikipedia.org/wiki/Cyclic_redundancy_check
      Retrieved on: 2009-12-17.

6.) Tool Interface Standards.  "Executable and Linking Format".  Portable
      Formats Specification, Version 1.1.