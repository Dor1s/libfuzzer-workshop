# Lesson 10

Here we will be fuzzing [re2]. During this lesson we will:
* learn how `max_len` parameter may affect execution speed


### Build the target

```
tar xzf re2.tgz
cd re2

export FUZZ_CXXFLAGS="-O2 -fno-omit-frame-pointer -g -fsanitize=address \
    -fsanitize-coverage=trace-pc-guard,trace-cmp,trace-gep,trace-div"

make clean
CXX=clang++ CXXFLAGS="$FUZZ_CXXFLAGS"  make -j
```

### Build and run the fuzzer

```bash
cd ..

clang++ -std=c++11 re2_fuzzer.cc $FUZZ_CXXFLAGS -I re2 \
    re2/obj/libre2.a ../../libFuzzer/libFuzzer.a -lz \
    -o re2_fuzzer

mkdir corpus1
./re2_fuzzer ./corpus1 -print_final_stats=1 -max_total_time=300
```

Play with different `-max_len` parameter values and other adjustments.

[re2]: https://github.com/google/re2
