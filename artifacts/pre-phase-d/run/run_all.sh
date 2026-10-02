#!/bin/bash
# Pre-Phase-D full validation. Logs to work/pre-phase-d/run/.
cd /home/naishring/APKForge
source tools/env.sh >/dev/null 2>&1
unset FORCE_COLOR
export PYTHONHASHSEED=0
OUT=work/pre-phase-d/run; rm -rf $OUT; mkdir -p $OUT
PY=.venv-validation/bin/python
SNAP=artifacts/pre-phase-d/run/snap.sh
stage() { echo "=== $1 $(date -Iseconds)" | tee -a $OUT/timeline.txt; $SNAP >> $OUT/timeline.txt; }

stage "pytest-full-with-corpus start"
APKFORGE_CORPUS_BUILD=1 $PY -m pytest -p no:cacheprovider -q -rfEs > $OUT/pytest_full_with_corpus.txt 2>&1; echo "pytest exit=$?" | tee -a $OUT/timeline.txt
stage "c4 start"
$PY build-tests/run_corpus_validation.py run > $OUT/c4_stdout.txt 2>&1; echo "c4 exit=$?" | tee -a $OUT/timeline.txt
stage "c5-modify start"
$PY build-tests/run_c5_validation.py modify > $OUT/c5_modify_stdout.txt 2>&1; echo "c5 modify exit=$?" | tee -a $OUT/timeline.txt
stage "c5-noop start"
$PY build-tests/run_c5_validation.py noop > $OUT/c5_noop_stdout.txt 2>&1; echo "c5 noop exit=$?" | tee -a $OUT/timeline.txt
stage "security-corpus start"
cp tests/corpus_results.json $OUT/corpus_results.tracked.bak
$PY tests/corpus_runner.py > $OUT/corpus_runner_stdout.txt 2>&1; echo "corpus_runner exit=$?" | tee -a $OUT/timeline.txt
mv tests/corpus_results.json $OUT/corpus_results.json; cp $OUT/corpus_results.tracked.bak tests/corpus_results.json
stage "pytest-full second run (leak check) start"
$PY -m pytest -p no:cacheprovider -q > $OUT/pytest_full_rerun.txt 2>&1; echo "pytest rerun exit=$?" | tee -a $OUT/timeline.txt
stage "done"
