# Lesson 02

## Traditional out-of-process fuzzing

**Target**: [pdfium]

**Mutation engine**: [radamsa]

**Seed corpus**: collected from previous [PDFium bugs]


## Instruction

Use `radamsa` to generate testcases from `seed_corpus`:
```bash
./generate_testcases.py
```

Verify number of files generated:
```bash
ls work/corpus/ | wc -l
1000
```

Run fuzzing:
```bash
unxz bin/asan.tar.xz && tar xf bin/asan.tar
./run_fuzzing.py
```

If you don't see any output, no crash has been found.


[pdfium]: https://pdfium.googlesource.com/pdfium/
[radamsa]: https://github.com/aoh/radamsa
[PDFium bugs]: https://bugs.chromium.org/p/chromium/issues/list?can=1&q=Type%3DBug-Security+component%3AInternals%3EPlugins%3EPDF+label%3Aallpublic+opened%3E2015-04-09&colspec=ID+Pri+M+Stars+ReleaseBlock+Component+Status+Owner+Summary+OS+Modified&x=m&y=releaseblock&cells=ids
