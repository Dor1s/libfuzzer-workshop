# libfuzzer-workshop
Materials of *"Modern fuzzing of C/C++ Projects"* workshop.

The first version of the workshop had been presented at [ZeroNights'16] security
conference.

## Disclaimer

This workshop was originally developed in 2016. As of today (2021 and beyond),
the practical side of the workshop might be not working right away, because
libFuzzer greatly evolved over the years. The theoretical part of the workshop
is a good learning material still, but for the practical lessons it is
recommended to follow the most recent version of the [libFuzzer tutorial].

## Requirements

* 2-3 hours of your time
* Linux-based OS
* C/C++ experience (nothing special, but you need to be able to read, write and
compile C/C++ code)
* a recent version of **clang** compiler. Distributions from
package managers are too old and most likely won't work (the workshop
called "modern", right?), you have two options:
   * checkout **llvm** repository and build it yourself. To make it easy,
     feel free to use [checkout_build_install_llvm.sh] script, it has been
     tested on clean Ubuntu 16.04
   * a [VirtualBox VM] with working environment is available, credentials:
     `fuzzer:zeronights`
* `sudo apt-get install -y make autoconf automake libtool pkg-config zlib1g-dev`


Fuzzing experience is not required.

## Contents
1. An introduction to fuzz testing
2. An example of traditional fuzzing
3. Coverage-guided fuzzing
4. Writing fuzzers (simple examples)
5. Finding Heartbleed (CVE-2014-0160)
6. Finding c-ares $100,000 bug (CVE-2016-5180)
7. How to improve your fuzzer
8. Fuzzing libxml2, learning how to improve the fuzzer and analyze performance
9. Fuzzing libpng, learning an importance of seed corpus and other stuff
10. Fuzzing re2
11. Fuzzing pcre2
12. Chromium integration & homework assignment


Most of the examples have been taken from [libFuzzer tutorial] and
[Fuzzer Test Suite].

## Prerequisites

### libFuzzer
Building libFuzzer is extreemly easy:
```bash
cd libFuzzer
Fuzzer/build.sh
```

libFuzzer repository could be found inside LLVM's compiler-rt project.


## Links

* all slides in a single presentation: [Modern Fuzzing of C/C++ Projects](https://docs.google.com/presentation/d/1pbbXRL7HaNSjyCHWgGkbpNotJuiC4O7L_PDZoGqDf5Q/edit?usp=sharing)
* libFuzzer documentation: [http://libfuzzer.info](http://libfuzzer.info)
* libFuzzer tutorial: [http://tutorial.libfuzzer.info](http://tutorial.libfuzzer.info)
* Google Online Security Blog: [Guided in-process fuzzing of Chrome components](https://security.googleblog.com/2016/08/guided-in-process-fuzzing-of-chrome.html)



[Fuzzer Test Suite]: https://github.com/google/fuzzer-test-suite
[VirtualBox VM]: https://drive.google.com/file/d/0B19rvTqcOBfTZHZseDk3ZkNjWHc/view?usp=sharing
[ZeroNights'16]: https://2016.zeronights.org/program/workshops/#ws1
[checkout_build_install_llvm.sh]: checkout_build_install_llvm.sh
[libFuzzer tutorial]: http://tutorial.libfuzzer.info
