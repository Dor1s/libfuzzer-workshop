# Lesson 06

Here we will find [c-ares] vulnerability (CVE-2016-5180) that has been exploited
to obtain [remote code execution] with root privileges on ChromeOS.

***
This example has been taken from [google/fuzzer-stest-suite] repository.
***


### Build vulnerable c-ares version

```bash
tar xzvf c-ares.tgz
cd c-ares

./buildconf
./configure CC="clang -O2 -fno-omit-frame-pointer -g -fsanitize=address -fsanitize-coverage=trace-pc-guard,trace-cmp,trace-gep,trace-div"
make CFLAGS=
```

### Build and run the fuzzer


Take a look into the fuzzer:

```cpp
#include <ares.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  unsigned char *buf;
  int buflen;
  std::string s(reinterpret_cast<const char *>(data), size);
  ares_create_query(s.c_str(), ns_c_in, ns_t_a, 0x1234, 0, &buf, &buflen, 0);
  ares_free_string(buf);
  return 0;
}
```

Build the fuzzer:

```bash
cd ..
clang++ -g c_ares_fuzzer.cc -O2 -fno-omit-frame-pointer -fsanitize=address \
    -fsanitize-coverage=trace-pc-guard,trace-cmp,trace-gep,trace-div \
    -Ic-ares c-ares/.libs/libcares.a \
    ../../libFuzzer/libFuzzer.a -o c_ares_fuzzer
```

And run it:

```bash
mkdir corpus1
./c_ares_fuzzer corpus1
```

Let's look into its output:

```bash
INFO: Seed: 250951835
INFO: Loaded 1 modules (152 guards): [0x747340, 0x7475a0), 
Loading corpus dir: corpus1
INFO: -max_len is not provided, using 64
INFO: A corpus is not provided, starting from an empty corpus
#0  READ units: 1
#1  INITED cov: 12 ft: 11 corp: 1/1b exec/s: 0 rss: 26Mb
#2  NEW    cov: 18 ft: 17 corp: 2/2b exec/s: 0 rss: 26Mb L: 1 MS: 1 ChangeBit-
#5  NEW    cov: 19 ft: 21 corp: 3/4b exec/s: 0 rss: 27Mb L: 2 MS: 4 ChangeBit-CrossOver-ShuffleBytes-ChangeByte-
#8  NEW    cov: 19 ft: 25 corp: 4/52b exec/s: 0 rss: 27Mb L: 48 MS: 2 CopyPart-InsertRepeatedBytes-
#10 NEW    cov: 20 ft: 26 corp: 5/109b exec/s: 0 rss: 29Mb L: 57 MS: 4 CopyPart-InsertRepeatedBytes-InsertByte-CMP- DE: ".\x00\x00\x00\x00\x00\x00\x00"-
#26 NEW    cov: 20 ft: 30 corp: 6/148b exec/s: 0 rss: 29Mb L: 39 MS: 5 InsertRepeatedBytes-EraseBytes-ChangeBit-ChangeByte-CMP- DE: "\x01\x00"-
#28 NEW    cov: 22 ft: 32 corp: 7/199b exec/s: 0 rss: 29Mb L: 51 MS: 2 InsertRepeatedBytes-PersAutoDict- DE: ".\x00\x00\x00\x00\x00\x00\x00"-
#43 NEW    cov: 22 ft: 36 corp: 8/238b exec/s: 0 rss: 29Mb L: 39 MS: 2 ShuffleBytes-PersAutoDict- DE: ".\x00\x00\x00\x00\x00\x00\x00"-
#48 NEW    cov: 23 ft: 37 corp: 9/273b exec/s: 0 rss: 29Mb L: 35 MS: 2 CrossOver-PersAutoDict- DE: ".\x00\x00\x00\x00\x00\x00\x00"-
#62 NEW    cov: 23 ft: 41 corp: 10/312b exec/s: 0 rss: 29Mb L: 39 MS: 1 CMP- DE: "\x00\x00\x00\x00\x00\x00\x00\x01"-
#84 NEW    cov: 23 ft: 44 corp: 11/336b exec/s: 0 rss: 29Mb L: 24 MS: 3 ChangeByte-CrossOver-PersAutoDict- DE: ".\x00\x00\x00\x00\x00\x00\x00"-
#87 NEW    cov: 23 ft: 45 corp: 12/367b exec/s: 0 rss: 29Mb L: 31 MS: 1 EraseBytes-
#212  NEW    cov: 23 ft: 47 corp: 13/423b exec/s: 0 rss: 29Mb L: 56 MS: 1 CopyPart-
#224  NEW    cov: 23 ft: 48 corp: 14/487b exec/s: 0 rss: 29Mb L: 64 MS: 3 ChangeByte-PersAutoDict-CrossOver- DE: ".\x00\x00\x00\x00\x00\x00\x00"-
#899  NEW    cov: 23 ft: 50 corp: 15/547b exec/s: 0 rss: 29Mb L: 60 MS: 3 EraseBytes-ChangeByte-CopyPart-
#1019 NEW    cov: 26 ft: 53 corp: 16/602b exec/s: 0 rss: 29Mb L: 55 MS: 3 CopyPart-PersAutoDict-CMP- DE: ".\x00\x00\x00\x00\x00\x00\x00"-"\\\x00\x00\x00\x00\x00\x00\x00"-
#1483 NEW    cov: 26 ft: 55 corp: 17/658b exec/s: 0 rss: 29Mb L: 56 MS: 2 EraseBytes-CopyPart-
#2760 NEW    cov: 27 ft: 56 corp: 18/722b exec/s: 0 rss: 30Mb L: 64 MS: 4 InsertRepeatedBytes-ChangeByte-CopyPart-InsertByte-
=================================================================
==15515==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6030000470f5 at pc 0x0000004f1acf bp 0x7fff4e5b1310 sp 0x7fff4e5b1308
WRITE of size 1 at 0x6030000470f5 thread T0
    #0 0x4f1ace in ares_create_query /home/mmoroz/projects/libfuzzer-workshop/lessons/06/c-ares/ares_create_query.c:196:3
    #1 0x4f0684 in LLVMFuzzerTestOneInput /home/mmoroz/projects/libfuzzer-workshop/lessons/06/c_ares_fuzzer.cc:16:3
    <...>
```



[c-ares]: https://c-ares.haxx.se/
[remote code execution]: https://googlechromereleases.blogspot.com/2016/09/stable-channel-updates-for-chrome-os.html
[google/fuzzer-stest-suite]: https://github.com/google/fuzzer-test-suite/blob/master/tutorial/libFuzzerTutorial.md#heartbleed
