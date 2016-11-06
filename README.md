# libfuzzer-workshop
Materials of *"Modern fuzzing of C/C++ Projects"* workshop.

The workshop will be hosted at [ZeroNights'16] security conference.

## Requirements

* 2-3 hours of your time
* Linux-based OS
* C/C++ experience (nothing special, but you need to be able to read, write and
compile C/C++ code)
* Optional requirement: a recent version of clang compiler. Distributions from
package managers are too old and most likely won't work (the workshop
called "modern", right?), you have two options:
 * checkout **clang** repository and build it yourself
 * checkout **Chromium** repository and use the binaries located at
`src/third_party/llvm-build/Release+Asserts/bin/`
* **clang** and other binaries will be provided as the workshop materials, but if
you don't want to run untrusted binaries, please consider one of the options
above

Fuzzing experience is not required.

## Contents
1. An introduction to fuzz testing
2. An exmaple of traditional (out-of-process, no guided) fuzzing
3. ...

## Links

* libFuzzer documentation: [http://libfuzzer.info](http://libfuzzer.info)
* libFuzzer tutorial: [http://tutorial.libfuzzer.info](http://tutorial.libfuzzer.info)
* Google Online Security Blog: [Guided in-process fuzzing of Chrome components](https://security.googleblog.com/2016/08/guided-in-process-fuzzing-of-chrome.html)


[ZeroNights'16]: https://2016.zeronights.org/program/workshops/#ws1
