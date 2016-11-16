# Lesson 04

Writing fuzzers. Here will be examples of different fuzzers.

## Sample fuzzer #1

Consider the following function:

```cpp
bool VulnerableFunction1(const uint8_t* data, size_t size) {
  bool result = false;
  if (size >= 3) {
    result = data[0] == 'F' &&
             data[1] == 'U' &&
             data[2] == 'Z' &&
             data[3] == 'Z';
  }

  return result;
}
```

Do you see any bug there? Let's try to fuzz it with the following fuzz target:

```cpp
#include "vulnerable_functions.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  VulnerableFunction1(data, size);
  return 0;
}

```

Compile the fuzzer in the following way:
```bash
clang++ -g -std=c++11 -fsanitize=address -fsanitize-coverage=trace-pc-guard \
    first_fuzzer.cc ../../libFuzzer/libFuzzer.a \
    -o first_fuzzer
```

Create an empty directory for corpus and run the fuzzer:

```bash
mkdir corpus1
./first_fuzzer corpus1
```

You should see the following input:
```bash
$ ./first_fuzzer corpus1/
INFO: Seed: 2547238898
INFO: Loaded 1 modules (32 guards): [0x744ea0, 0x744f20), 
Loading corpus dir: corpus1/
INFO: -max_len is not provided, using 64
INFO: A corpus is not provided, starting from an empty corpus
#0  READ units: 1
#1  INITED cov: 3 ft: 3 corp: 1/1b exec/s: 0 rss: 26Mb
#10 NEW    cov: 4 ft: 4 corp: 2/31b exec/s: 0 rss: 26Mb L: 30 MS: 4 ChangeBit-ChangeByte-ShuffleBytes-InsertRepeatedBytes-
#30588  NEW    cov: 5 ft: 5 corp: 3/60b exec/s: 0 rss: 29Mb L: 29 MS: 2 InsertByte-InsertRepeatedBytes-
#124562 NEW    cov: 6 ft: 6 corp: 4/90b exec/s: 0 rss: 36Mb L: 30 MS: 1 InsertByte-
#331574 NEW    cov: 7 ft: 7 corp: 5/99b exec/s: 0 rss: 52Mb L: 9 MS: 3 EraseBytes-CrossOver-InsertByte-
=================================================================
==14322==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000247d93 at pc 0x0000004f0781 bp 0x7ffd8e9af800 sp 0x7ffd8e9af7f8
READ of size 1 at 0x602000247d93 thread T0
    #0 0x4f0780  (/home/mmoroz/projects/libfuzzer-workshop/lessons/04/first_fuzzer+0x4f0780)
    #1 0x4f07f9  (/home/mmoroz/projects/libfuzzer-workshop/lessons/04/first_fuzzer+0x4f07f9)
    #2 0x4f9f17  (/home/mmoroz/projects/libfuzzer-workshop/lessons/04/first_fuzzer+0x4f9f17)
    #3 0x4fa100  (/home/mmoroz/projects/libfuzzer-workshop/lessons/04/first_fuzzer+0x4fa100)
    <...>
```

Wow! The fuzzer has just found a **heap-buffer-overflow**. Let's try to
reproduce the crash:

```bash
$ ./first_fuzzer crash-0eb8e4ed029b774d80f2b66408203801cb982a60 
```

To get a symbolized stacktrace, add `symbolize=1` option to `ASAN_OPTIONS` env
variable:
```bash
ASAN_OPTIONS=symbolize=1 ./first_fuzzer crash-0eb8e4ed029b774d80f2b66408203801cb982a60 
```

The symbolized result looks like:

```bash
INFO: Seed: 3080648570
INFO: Loaded 1 modules (32 guards): [0x744ea0, 0x744f20), 
./first_fuzzer: Running 1 inputs 1 time(s) each.
Running: crash-0eb8e4ed029b774d80f2b66408203801cb982a60
=================================================================
==15226==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x602000000093 at pc 0x0000004f0781 bp 0x7ffe1dda1650 sp 0x7ffe1dda1648
READ of size 1 at 0x602000000093 thread T0
    #0 0x4f0780 in VulnerableFunction1(unsigned char const*, unsigned long) /home/mmoroz/projects/libfuzzer-workshop/lessons/04/./vulnerable_functions.h:16:14
    #1 0x4f07f9 in LLVMFuzzerTestOneInput /home/mmoroz/projects/libfuzzer-workshop/lessons/04/sample_fuzzer_one.cc:10:3
    #2 0x4f9f17 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /home/mmoroz/projects/libfuzzer-workshop/libFuzzer/Fuzzer/FuzzerLoop.cpp:515:13
    #3 0x4fa100 in fuzzer::Fuzzer::RunOne(unsigned char const*, unsigned long) /home/mmoroz/projects/libfuzzer-workshop/libFuzzer/Fuzzer/FuzzerLoop.cpp:469:3
    #4 0x4f0983 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /home/mmoroz/projects/libfuzzer-workshop/libFuzzer/Fuzzer/FuzzerDriver.cpp:272:6
    #5 0x4f2642 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /home/mmoroz/projects/libfuzzer-workshop/libFuzzer/Fuzzer/FuzzerDriver.cpp:482:9
    #6 0x4f08b0 in main /home/mmoroz/projects/libfuzzer-workshop/libFuzzer/Fuzzer/FuzzerMain.cpp:20:10
    #7 0x7f64a1cdbf44 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x21f44)
    #8 0x41b557 in _start (/home/mmoroz/projects/libfuzzer-workshop/lessons/04/first_fuzzer+0x41b557)

0x602000000093 is located 0 bytes to the right of 3-byte region [0x602000000090,0x602000000093)
allocated by thread T0 here:
    #0 0x4ed57b in operator new[](unsigned long) (/home/mmoroz/projects/libfuzzer-workshop/lessons/04/first_fuzzer+0x4ed57b)
    #1 0x4f9e5a in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) /home/mmoroz/projects/libfuzzer-workshop/libFuzzer/Fuzzer/FuzzerLoop.cpp:506:23
    #2 0x4fa100 in fuzzer::Fuzzer::RunOne(unsigned char const*, unsigned long) /home/mmoroz/projects/libfuzzer-workshop/libFuzzer/Fuzzer/FuzzerLoop.cpp:469:3
    #3 0x4f0983 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) /home/mmoroz/projects/libfuzzer-workshop/libFuzzer/Fuzzer/FuzzerDriver.cpp:272:6
    #4 0x4f2642 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) /home/mmoroz/projects/libfuzzer-workshop/libFuzzer/Fuzzer/FuzzerDriver.cpp:482:9
    #5 0x4f08b0 in main /home/mmoroz/projects/libfuzzer-workshop/libFuzzer/Fuzzer/FuzzerMain.cpp:20:10
    #6 0x7f64a1cdbf44 in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x21f44)

SUMMARY: AddressSanitizer: heap-buffer-overflow /home/mmoroz/projects/libfuzzer-workshop/lessons/04/./vulnerable_functions.h:16:14 in VulnerableFunction1(unsigned char const*, unsigned long)
Shadow bytes around the buggy address:
  0x0c047fff7fc0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c047fff7fd0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c047fff7fe0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c047fff7ff0: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0c047fff8000: fa fa 00 00 fa fa 00 fa fa fa 00 fa fa fa 03 fa
=>0x0c047fff8010: fa fa[03]fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c047fff8020: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c047fff8030: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c047fff8040: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c047fff8050: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
  0x0c047fff8060: fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa fa
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==15226==ABORTING
```

To get symbolized stack-traces by default, let's export `ASAN_OPTIONS` env var:
```bash
export ASAN_OPTIONS=symbolize=1
```


## Sample fuzzer #2

Consider another function:

```cpp
constexpr auto kMagicHeader = "ZN_2016";
constexpr std::size_t kMaxPacketLen = 1024;
constexpr std::size_t kMaxBodyLength = 1024 - sizeof(kMagicHeader);

bool VulnerableFunction2(const uint8_t* data, size_t size, bool verify_hash) {
  if (size < sizeof(kMagicHeader))
    return false;

  std::string header(reinterpret_cast<const char*>(data), sizeof(kMagicHeader));

  std::array<uint8_t, kMaxBodyLength> body;

  if (strcmp(kMagicHeader, header.c_str()))
    return false;

  auto target_hash = data[--size];

  if (size > kMaxPacketLen)
    return false;

  if (!verify_hash)
    return true;

  std::copy(data, data + size, body.data());
  auto real_hash = DummyHash(body);
  return real_hash == target_hash;
}
```

This example is a bit more complicated, but let's fuzz it with the simplest
fuzz target (almost the same as the first one written above):

```cpp
#include "vulnerable_functions.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  VulnerableFunction2(data, size, false);
  return 0;
}
```

Compile the fuzzer:

```bash
clang++ -g -std=c++11 -fsanitize=address -fsanitize-coverage=trace-pc-guard \
    second_fuzzer.cc ../../libFuzzer/libFuzzer.a \
    -o second_fuzzer
```

Run the fuzzer:

```bash
mkdir corpus2
./second_fuzzer corpus2
```

The output is pretty boring:

```bash
$ ./second_fuzzer ./corpus2/
INFO: Seed: 989537009
INFO: Loaded 1 modules (74 guards): [0x745f60, 0x746088),
Loading corpus dir: ./corpus2/
INFO: -max_len is not provided, using 64
INFO: A corpus is not provided, starting from an empty corpus
#0  READ units: 1
#1  INITED cov: 3 ft: 3 corp: 1/1b exec/s: 0 rss: 12Mb
#6  NEW    cov: 4 ft: 4 corp: 2/27b exec/s: 0 rss: 13Mb L: 26 MS: 5 ChangeBit-ChangeBit-ShuffleBytes-ChangeBit-InsertRepeatedBytes-
#6048 NEW    cov: 5 ft: 5 corp: 3/35b exec/s: 0 rss: 14Mb L: 8 MS: 2 InsertRepeatedBytes-TempAutoDict- DE: "ZN_2016"-
#1048576  pulse  cov: 5 ft: 5 corp: 3/35b exec/s: 524288 rss: 148Mb
#2097152  pulse  cov: 5 ft: 5 corp: 3/35b exec/s: 524288 rss: 284Mb
#4194304  pulse  cov: 5 ft: 5 corp: 3/35b exec/s: 524288 rss: 521Mb
#8388608  pulse  cov: 5 ft: 5 corp: 3/35b exec/s: 493447 rss: 523Mb
#16777216 pulse  cov: 5 ft: 5 corp: 3/35b exec/s: 508400 rss: 523Mb
<...>
```

Let's modify the fuzz target to use different values for `verify_hash` argument
of the target API:

```cpp
#include "vulnerable_functions.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  bool verify_hash_flags[] = { false, true };

  for (auto flag : verify_hash_flags)
    VulnerableFunction2(data, size, flag);
  return 0;
}
```

Compile the fuzzer:

```bash
clang++ -g -std=c++11 -fsanitize=address -fsanitize-coverage=trace-pc-guard \
    third_fuzzer.cc ../../libFuzzer/libFuzzer.a \
    -o third_fuzzer
```

Run the fuzzer on the same corpus:

```bash
$ ./third_fuzzer corpus2/
INFO: Seed: 2627375800
INFO: Loaded 1 modules (74 guards): [0x745fa0, 0x7460c8),
Loading corpus dir: corpus2/
INFO: -max_len is not provided, using 64
#0  READ units: 2
#2  INITED cov: 24 ft: 23 corp: 2/34b exec/s: 0 rss: 12Mb
#30 NEW    cov: 24 ft: 24 corp: 3/40b exec/s: 0 rss: 13Mb L: 6 MS: 3 ChangeBinInt-ShuffleBytes-EraseBytes-
#1048576  pulse  cov: 24 ft: 24 corp: 3/40b exec/s: 524288 rss: 219Mb
#2097152  pulse  cov: 24 ft: 24 corp: 3/40b exec/s: 419430 rss: 426Mb
#4194304  pulse  cov: 24 ft: 24 corp: 3/40b exec/s: 419430 rss: 524Mb
#8388608  pulse  cov: 24 ft: 24 corp: 3/40b exec/s: 399457 rss: 524Mb
<...>
```

The fuzzer has found a new path, but things are still boring. Please note:

```
INFO: -max_len is not provided, using 64
```

while our target analyzes packets of `ZN_2016` protocol that may have length up
to `constexpr std::size_t kMaxPacketLen = 1024;` bytes.

Let's add `-max_len=1024` libFuzzer argument:

```bash
./third_fuzzer corpus2/ -max_len=1024
```

**BOOM!**

```
INFO: Seed: 2391963130
INFO: Loaded 1 modules (74 guards): [0x745fa0, 0x7460c8),
Loading corpus dir: corpus2/
#0  READ units: 3
#3  INITED cov: 24 ft: 24 corp: 3/75b exec/s: 0 rss: 14Mb
=================================================================
==1530==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7ffd0a3ccbc8 at pc 0x0000004ab13c bp 0x7ffd0a3cc630 sp 0x7ffd0a3cbde0
WRITE of size 1023 at 0x7ffd0a3ccbc8 thread T0
    #0 0x4ab13b in __asan_memmove (/usr/local/google/home/mmoroz/Projects/libfuzzer-workshop/lessons/04/third_fuzzer+0x4ab13b)
    #1 0x4f1697 in unsigned char* std::__copy_move<false, true, std::random_access_iterator_tag>::__copy_m<unsigned char>(unsigned char const*, unsigned char const*, unsigned char*) /usr/bin/../lib/gcc/x86_64-linux-gnu/4.8/../../../../include/c++/4.8/bits/stl_algobase.h:372:6
    #2 0x4f153d in unsigned char* std::__copy_move_a<false, unsigned char const*, unsigned char*>(unsigned char const*, unsigned char const*, unsigned char*) /usr/bin/../lib/gcc/x86_64-linux-gnu/4.8/../../../../include/c++/4.8/bits/stl_algobase.h:389:14
    #3 0x4f148b in unsigned char* std::__copy_move_a2<false, unsigned char const*, unsigned char*>(unsigned char const*, unsigned char const*, unsigned char*) /usr/bin/../lib/gcc/x86_64-linux-gnu/4.8/../../../../include/c++/4.8/bits/stl_algobase.h:426:18
    #4 0x4f123e in unsigned char* std::copy<unsigned char const*, unsigned char*>(unsigned char const*, unsigned char const*, unsigned char*) /usr/bin/../lib/gcc/x86_64-linux-gnu/4.8/../../../../include/c++/4.8/bits/stl_algobase.h:458:15
    #5 0x4f0d13 in VulnerableFunction2(unsigned char const*, unsigned long, bool) /usr/local/google/home/mmoroz/Projects/libfuzzer-workshop/lessons/04/./vulnerable_functions.h:61:3
    #6 0x4f10e4 in LLVMFuzzerTestOneInput /usr/local/google/home/mmoroz/Projects/libfuzzer-workshop/lessons/04/third_fuzzer.cc:13:5
    <...>
```

We have `stack-buffer-overflow` vulnerability at `vulnerable_functions.h:61:3`.


## Sample fuzzer #3

Look at the following function:

```cpp
constexpr std::size_t kZn2016VerifyHashFlag = 0x0001000;

bool VulnerableFunction3(const uint8_t* data, size_t size, std::size_t flags) {
  bool verify_hash = flags & kZn2016VerifyHashFlag;
  return VulnerableFunction2(data, size, verify_hash);
}
```

Actually it is just a wrapper for the previous vulnerable function, but the main
point here is a large space of possible `flags` values.

*Note*: imagine that there are more than two different `flags` values possible.
If your fantasy needs inspiration, please take a look at possible values of
`flags` and `mode` arguments of standard [open()] function.

Enumeration of all possible combinations in the fuzzer doesn't seem reasonable.
Also there is no guarantee that new possible values will not be added.

In this case, we can get some randomization of `flags` values using `data`
provided by libFuzzer:

```cpp
#include "vulnerable_functions.h"

#include <functional>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  std::string data_string(reinterpret_cast<const char*>(data), size);
  auto data_hash = std::hash<std::string>()(data_string);

  std::size_t flags = static_cast<size_t>(data_hash);
  VulnerableFunction3(data, size, flags);
  return 0;
}
```

Compile the fuzzer:

```bash
clang++ -g -std=c++11 -fsanitize=address -fsanitize-coverage=trace-pc-guard \
    fourth_fuzzer.cc ../../libFuzzer/libFuzzer.a \
    -o fourth_fuzzer
```

and run on the empty corpus:

```bash
mkdir corpus3
./fourth_fuzzer corpus3/ -max_len=1024
```

As you see, it finds the same crash pretty quickly again, but, now the fuzzer is
universal in terms of possible `flags` values.

[open()]: http://man7.org/linux/man-pages/man2/open.2.html
