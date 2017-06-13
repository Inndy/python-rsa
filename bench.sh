#!/bin/bash

export NONRANDOM=1

for PY in pypy pypy3 python2 python3
do
	$PY --version
	time $PY bench.py
done
