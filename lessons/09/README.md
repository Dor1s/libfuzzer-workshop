# Lesson 09

Here we will be fuzzing [libpng]. During this lesson we will:
* see an importance of seed corpus

### Build the target

Disabling of error messages is a bit tricky here and need to be done before the
compilation"

```bash
tar xzf libpng.tgz
cd libpng

# Disable logging via library build configuration control.
cat scripts/pnglibconf.dfa | sed -e "s/option STDIO/option STDIO disabled/" \
> scripts/pnglibconf.dfa.temp
mv scripts/pnglibconf.dfa.temp scripts/pnglibconf.dfa

# build the library.
autoreconf -f -i

export FUZZ_CXXFLAGS="-O2 -fno-omit-frame-pointer -g -fsanitize=address \
    -fsanitize-coverage=trace-pc-guard,trace-cmp,trace-gep,trace-div"

./configure CC="clang" CFLAGS="$FUZZ_CXXFLAGS"
make -j2
```

### Build and run the fuzzer

Take a look at [the fuzzer]. Please note how we disable CRC check. Otherwise,
the fuzzer would almost always exit because of invalid checksum of PNG chunks.


Build the fuzzer:

```bash
cd ..
clang++ -std=c++11 libpng_read_fuzzer.cc $FUZZ_CXXFLAGS -I libpng \
    libpng/.libs/libpng16.a ../../libFuzzer/libFuzzer.a -lz \
    -o libpng_read_fuzzer
```

Run the fuzzer on empty corpus with `-mxa_len=2048` for 5 minutes:

```bash
mkdir corpus1
./libpng_read_fuzzer -max_len=2048 -max_total_time=300 -print_final_stats=1 \
    corpus1
```

Open a new terminal and run the fuzzer with a dictionary:

```bash
mkdir corpus2
./libpng_read_fuzzer -max_len=2048 -max_total_time=300 -dict=png.dict \
    -print_final_stats=1 corpus2
```

Then let's wait until both processes end :)


Let's run the fuzzer using a seed corpus. For seed corpus we will use some [test
images] from Chromium repo. 

Run two more fuzzer instances. One with the seed corpus:

```bash
mkdir corpus3
./libpng_read_fuzzer -max_len=2048 -max_total_time=300 -print_final_stats=1 \
    -timeout=5 corpus3 seed_corpus
```

And another one with the seed corpus and the dictionary (super-combo!):

```bash
mkdir corpus4
./libpng_read_fuzzer -max_len=2048 -max_total_time=300 -dict=png.dict \
    -print_final_stats=1 -timeout=5 corpus4 seed_corpus
```

Compare and analyze the output of four fuzzers being run with different
configurations.



[libpng]: http://www.libpng.org/pub/png/libpng.html
[test images]: https://cs.chromium.org/chromium/src/cc/test/data/
[the fuzzer]: libpng_read_fuzzer.cc

