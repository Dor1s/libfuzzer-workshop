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


[ZeroNights'16]: https://2016.zeronights.org/program/workshops/#ws1