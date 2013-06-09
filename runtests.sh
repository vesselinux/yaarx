#!/bin/bash
#
# Automatically run all tests
#
BIN_PATH=./bin

for tests_file in $BIN_PATH/*tests*
do
  echo $tests_file
  ./$tests_file
done