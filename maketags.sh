#!/bin/bash
#
# Generating TAG file for source code browsing
#

SRC=./src/*.cc
TESTS=./tests/*.cc
INCLUDE=./include/*.hh

echo "Tagging source files..."
echo $SRC
etags $SRC
echo $TESTS
etags -a $TESTS

echo "Tagging header files..."
echo $INCLUDE
etags -a $INCLUDE

echo "TAG file generated successfully."