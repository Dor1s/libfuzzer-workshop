#!/usr/bin/env python2
import os
import subprocess

WORK_DIR = 'work'

def checkOutput(s):
  if 'Segmentation fault' in s or 'error' in s.lower():
    return False
  else:
    return True

corpus_dir = os.path.join(WORK_DIR, 'corpus')
corpus_filenames = os.listdir(corpus_dir)

for f in corpus_filenames:
  testcase_path = os.path.join(corpus_dir, f)
  cmd = ['bin/asan/pdfium_test', testcase_path]
  process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)
  output = process.communicate()[0]
  if not checkOutput(output):
    print testcase_path
    print output
    print '-' * 80
