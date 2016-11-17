# Lesson 10

Here we will be fuzzing [pcre2]. During this lesson we will:
* ???


### Build the target

```
tar xzf pcre2.tgz
cd pcre2

./autogen.sh

export FUZZ_CXXFLAGS="-O2 -fno-omit-frame-pointer -g -fsanitize=address \
    -fsanitize-coverage=trace-pc-guard,trace-cmp,trace-gep,trace-div"

CXX="clang++ $FUZZ_CXXFLAGS" CC="clang $FUZZ_CXXFLAGS" \
    CCLD="clang++ $FUZZ_CXXFLAGS" ./configure --enable-never-backslash-C \
    --with-match-limit=1000 --with-match-limit-recursion=1000

make -j2
```

### Build and run the fuzzer

```bash
cd ..

clang++ -std=c++11 pcre2_fuzzer.cc -I pcre2/src \
    -Wl,--whole-archive pcre2/.libs/*.a -Wl,-no-whole-archive \
    ../../libFuzzer/libFuzzer.a $FUZZ_CXXFLAGS -o pcre2_fuzzer

mkdir corpus1
./pcre2_fuzzer ./corpus1 -print_final_stats=1 -max_total_time=300
```

TODO: show problems if they are and play with arguments.


### Fuzzing pcre2-10.00

***
This section has been added to let everybody to feel like a l33t h4x0r again :)
***

```bash
tar xzf pcre2-10.00.tgz
cd pcre2-10.00

./autogen.sh

export FUZZ_CXXFLAGS="-O2 -fno-omit-frame-pointer -g -fsanitize=address \
    -fsanitize-coverage=trace-pc-guard,trace-cmp,trace-gep,trace-div"

CXX="clang++ $FUZZ_CXXFLAGS" CC="clang $FUZZ_CXXFLAGS" \
    CCLD="clang++ $FUZZ_CXXFLAGS" ./configure --enable-never-backslash-C \
    --with-match-limit=1000 --with-match-limit-recursion=1000

make -j2

cd ..

clang++ -std=c++11 pcre2_fuzzer.cc -I pcre2-10.00/src \
    -Wl,--whole-archive pcre2-10.00/.libs/*.a -Wl,-no-whole-archive \
    ../../libFuzzer/libFuzzer.a $FUZZ_CXXFLAGS -o pcre2_10.00_fuzzer

mkdir corpus2
./pcre2_10.00_fuzzer ./corpus2 -print_final_stats=1 -max_total_time=300
```

Feel free to re-run the last command to see several crashes.

[pcre2]: http://www.pcre.org/current/doc/html/pcre2.html
