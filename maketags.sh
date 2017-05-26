#!/bin/bash
#
# Generating TAG file for source code browsing
#

SRC=./src/*.cc
TESTS=./tests/*.cc
INCLUDE=./include/*.hh
CODINGTOOL_SRC=../codingtool/src/*.cpp
CODINGTOOL_INCLUDES=../codingtool/includes/*.h
CODINGTOOL_EXAMPLES=../codingtool/examples/*.cpp

echo "Tagging source files..."
echo $SRC
etags $SRC
echo $TESTS
etags -a $TESTS

echo "Tagging header files..."
echo $INCLUDE
etags -a $INCLUDE

echo "Tagging CodingTool files..."
echo $CODINGTOOL_SRC
etags -a $CODINGTOOL_SRC
echo $CODINGTOOL_INCLUDES
etags -a $CODINGTOOL_INCLUDES
echo $CODINGTOOL_EXAMPLES
etags -a $CODINGTOOL_EXAMPLES

echo "TAG file generated successfully."
