#!/bin/bash
#
# Common  script to search for strings in files
#
FIND_STRING=$1

grep -r -n --exclude="*svn*" \
           --exclude=TAGS \
           --exclude="*.log " \
           --exclude="*.html" \
           --exclude="*.log" \
           --exclude="*.dox" \
           --exclude=Makefile \
           --exclude=Doxyfile \
           --exclude=readme.txt \
           --exclude=makelogo.sh \
           --exclude=dump.c \
           --exclude-dir="./doc" \
           --exclude-dir="./bin" \
           --exclude-dir="./obj" \
           --exclude-dir="./log" \
           --exclude-dir=".svn" \
           $FIND_STRING .