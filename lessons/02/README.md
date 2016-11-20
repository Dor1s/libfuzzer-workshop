# Lesson 02

## Traditional out-of-process fuzzing

**Target**: [pdfium]

**Mutation engine**: [radamsa]

**Seed corpus**: collected from previous [PDFium bugs]


## Instruction

Take a look at [generate_testcases.py](generate_testcases.py) scripts. Then use
`radamsa` to generate testcases from `seed_corpus`:
```bash
cd lessons/02
./generate_testcases.py
```

Verify number of files generated:
```bash
ls work/corpus/ | wc -l
1000
```

Take a look at [run_fuzzing.py](run_fuzzing.py) script. Then run fuzzing:
```bash
tar xzf bin/asan.tgz
./run_fuzzing.py
```

If you don't see any output, no crash has been found. Feel free to re-generate
testcases many more times. Though it should take for a while to find a crash.


[pdfium]: https://pdfium.googlesource.com/pdfium/
[radamsa]: https://github.com/aoh/radamsa
[PDFium bugs]: https://bugs.chromium.org/p/chromium/issues/list?can=1&q=Type%3DBug-Security+component%3AInternals%3EPlugins%3EPDF+label%3Aallpublic+opened%3E2015-04-09&colspec=ID+Pri+M+Stars+ReleaseBlock+Component+Status+Owner+Summary+OS+Modified&x=m&y=releaseblock&cells=ids
