# Lesson 05

Here we will find Heartbleed vulnerability (CVE-2014-0160).

***
This example has been taken from [google/fuzzer-stest-suite] repository.
***


### Build vulnerable openssl version

```bash
tar xzf openssl1.0.1f.tgz
cd openssl1.0.1f/

./config
make clean
make CC="clang -O2 -fno-omit-frame-pointer -g -fsanitize=address -fsanitize-coverage=trace-pc-guard,trace-cmp,trace-gep,trace-div" -j$(nproc)
```

### Build and run the fuzzer

Take a look into the fuzzer:

```c
// Copyright 2016 Google Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <assert.h>
#include <stdint.h>
#include <stddef.h>

#ifndef CERT_PATH
# define CERT_PATH
#endif

SSL_CTX *Init() {
  SSL_library_init();
  SSL_load_error_strings();
  ERR_load_BIO_strings();
  OpenSSL_add_all_algorithms();
  SSL_CTX *sctx;
  assert (sctx = SSL_CTX_new(TLSv1_method()));
  /* These two file were created with this command:
      openssl req -x509 -newkey rsa:512 -keyout server.key \
     -out server.pem -days 9999 -nodes -subj /CN=a/
  */
  assert(SSL_CTX_use_certificate_file(sctx, CERT_PATH "server.pem",
                                      SSL_FILETYPE_PEM));
  assert(SSL_CTX_use_PrivateKey_file(sctx, CERT_PATH "server.key",
                                     SSL_FILETYPE_PEM));
  return sctx;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  static SSL_CTX *sctx = Init();
  SSL *server = SSL_new(sctx);
  BIO *sinbio = BIO_new(BIO_s_mem());
  BIO *soutbio = BIO_new(BIO_s_mem());
  SSL_set_bio(server, sinbio, soutbio);
  SSL_set_accept_state(server);
  BIO_write(sinbio, Data, Size);
  SSL_do_handshake(server);
  SSL_free(server);
  return 0;
}
```

Build the fuzzer:

```bash
cd ..
clang++ -g openssl_fuzzer.cc -O2 -fno-omit-frame-pointer -fsanitize=address \
    -fsanitize-coverage=trace-pc-guard,trace-cmp,trace-gep,trace-div \
    -Iopenssl1.0.1f/include openssl1.0.1f/libssl.a openssl1.0.1f/libcrypto.a \
    ../../libFuzzer/libFuzzer.a -o openssl_fuzzer
```

Run the fuzzer:

```bash
mkdir corpus1
./openssl_fuzzer ./corpus1/
```

After some time:

```
INFO: Seed: 3620533608
INFO: Loaded 1 modules (88608 guards): [0xcad4c0, 0xd03d40), 
Loading corpus dir: ./corpus1/
INFO: -max_len is not provided, using 64
INFO: A corpus is not provided, starting from an empty corpus
#0  READ units: 1
#1  INITED cov: 1473 ft: 385 corp: 1/1b exec/s: 0 rss: 31Mb
#2  NEW    cov: 1479 ft: 414 corp: 2/36b exec/s: 0 rss: 31Mb L: 35 MS: 1 InsertRepeatedBytes-
#111  NEW    cov: 1479 ft: 417 corp: 3/79b exec/s: 0 rss: 36Mb L: 43 MS: 5 ShuffleBytes-CrossOver-CMP-EraseBytes-EraseBytes- DE: "\x00\x00"-
#2256 NEW    cov: 1490 ft: 439 corp: 4/128b exec/s: 0 rss: 127Mb L: 49 MS: 5 PersAutoDict-ChangeBit-ChangeBinInt-ChangeBinInt-InsertRepeatedBytes- DE: "\x00\x00"-

<...>

#120643 NEW    cov: 1563 ft: 721 corp: 37/1736b exec/s: 24128 rss: 373Mb L: 46 MS: 2 CopyPart-CMP- DE: "\x00\x00\x00\x00\x00\x00\x00v"-
#121008 NEW    cov: 1565 ft: 723 corp: 38/1758b exec/s: 24201 rss: 373Mb L: 22 MS: 2 ChangeBinInt-EraseBytes-
=================================================================
==32104==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x629000009748 at pc 0x0000004aad87 bp 0x7fff9266d020 sp 0x7fff9266c7d0
READ of size 25344 at 0x629000009748 thread T0
    #0 0x4aad86 in __asan_memcpy (/usr/local/google/home/mmoroz/Projects/libfuzzer-workshop/lessons/HB/openssl_fuzzer+0x4aad86)
    #1 0x4ff232 in tls1_process_heartbeat /usr/local/google/home/mmoroz/Projects/libfuzzer-workshop/lessons/HB/openssl1.0.1f/ssl/t1_lib.c:2586:3
    #2 0x580be0 in ssl3_read_bytes /usr/local/google/home/mmoroz/Projects/libfuzzer-workshop/lessons/HB/openssl1.0.1f/ssl/s3_pkt.c:1092:4
    #3 0x585c37 in ssl3_get_message /usr/local/google/home/mmoroz/Projects/libfuzzer-workshop/lessons/HB/openssl1.0.1f/ssl/s3_both.c:457:7
    #4 0x548a54 in ssl3_get_client_hello /usr/local/google/home/mmoroz/Projects/libfuzzer-workshop/lessons/HB/openssl1.0.1f/ssl/s3_srvr.c:941:4
    #5 0x544a4e in ssl3_accept /usr/local/google/home/mmoroz/Projects/libfuzzer-workshop/lessons/HB/openssl1.0.1f/ssl/s3_srvr.c:357:9
    #6 0x4f0d42 in LLVMFuzzerTestOneInput /usr/local/google/home/mmoroz/Projects/libfuzzer-workshop/lessons/HB/openssl_fuzzer.cc:39:3
    <...>
```

**READ** of size **25344** due to  **heap-buffer-overflow** in 
`tls1_process_heartbeat` function. Here it is. One of the scariest
vulnerabilities can be found in a few minutes. Fuzzing is awesome.


[Heartbleed]: https://en.wikipedia.org/wiki/Heartbleed
[google/fuzzer-stest-suite]: https://github.com/google/fuzzer-test-suite/blob/master/tutorial/libFuzzerTutorial.md#heartbleed