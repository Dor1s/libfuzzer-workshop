# Lesson 12

This is a theoretical lesson with a homework assignment, see the slides.

## Assignment:

1. check out [Chromium] repository
2. try to [build existing fuzzers]
3. write a new one

[Codesearch] is a pretty useful instrument to find [existing targets] and to
search for [new ones] as well.

Once you find a bug with it, submit your fuzzer to [Chrome Fuzzer Program].

**Happy fuzzing!**


[Chromium]: https://www.chromium.org/developers/how-tos/get-the-code
[Chrome Fuzzer Program]: https://www.google.com/about/appsecurity/chrome-rewards/index.html#fuzzerprogram
[Codesearch]: https://cs.chromium.org/
[build existing fuzzers]: https://chromium.googlesource.com/chromium/src/+/master/testing/libfuzzer/reproducing.md#Reproducing-LibFuzzer-ASan-bugs
[existing targets]: https://cs.chromium.org/search/?q=LLVMFuzzerTestOneInput&sq=package:chromium&type=cs
[new ones]: https://cs.chromium.org/search/?q=file:.*%5C.h+%22const+uint8_t*%22&sq=package:chromium&type=cs
