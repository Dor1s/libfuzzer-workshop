# Lesson 11

Here we will be fuzzing [pcre2]. During this lesson we will:
* compare fuzzing of different regexp libraries
* find known bugs and feel like a l33t h4x0r :)


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

Play with different parameters (see how speed changes with different `max_len`
values).


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

Feel free to re-run the last command to see several crashes, for example:

```bash
#290587 NEW    cov: 1884 ft: 7593 corp: 2868/129Kb exec/s: 5381 rss: 522Mb L: 62 MS: 1 ChangeBit-
=================================================================
==17288==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6040005d164f at pc 0x000000585f99 bp 0x7fff827c53d0 sp 0x7fff827c53c8
READ of size 1 at 0x6040005d164f thread T0
    #0 0x585f98 in match /home/mmoroz/projects/libfuzzer-workshop/lessons/10/pcre2-10.00/src/pcre2_match.c:5968:11
    #1 0x549d4b in pcre2_match_8 /home/mmoroz/projects/libfuzzer-workshop/lessons/10/pcre2-10.00/src/pcre2_match.c:6876:8
    #2 0x59bfa5 in regexec /home/mmoroz/projects/libfuzzer-workshop/lessons/10/pcre2-10.00/src/pcre2posix.c:291:6
    #3 0x4f093a in LLVMFuzzerTestOneInput /home/mmoroz/projects/libfuzzer-workshop/lessons/10/pcre2_fuzzer.cc:21:5
    <...>
```

and

```bash
#473083 NEW    cov: 2325 ft: 9716 corp: 3963/184Kb exec/s: 2263 rss: 697Mb L: 64 MS: 2 ChangeBinInt-ShuffleBytes-
=================================================================
==17265==ERROR: AddressSanitizer: heap-use-after-free on address 0x61000012caca at pc 0x000000585e83 bp 0x7ffcb3379bd0 sp 0x7ffcb3379bc8
READ of size 1 at 0x61000012caca thread T0
    #0 0x585e82 in match /home/mmoroz/projects/libfuzzer-workshop/lessons/10/pcre2-10.00/src/pcre2_match.c:1426:16
    #1 0x549d4b in pcre2_match_8 /home/mmoroz/projects/libfuzzer-workshop/lessons/10/pcre2-10.00/src/pcre2_match.c:6876:8
    #2 0x59bfa5 in regexec /home/mmoroz/projects/libfuzzer-workshop/lessons/10/pcre2-10.00/src/pcre2posix.c:291:6
    #3 0x4f093a in LLVMFuzzerTestOneInput /home/mmoroz/projects/libfuzzer-workshop/lessons/10/pcre2_fuzzer.cc:21:5
    <...>
```



[pcre2]: http://www.pcre.org/current/doc/html/pcre2.html
