#!/bin/bash

# see: http://www.imagemagick.org/Usage/text/
#        -font TlwgTypistB \
#        -font TlwgTypewriter \
#        -font TlwgTypoB \

convert -size 80x50 \
        -border 1.5 \
        -bordercolor white \
        -background black \
        -fill white \
        -font TlwgTypistB \
        -gravity center \
        label:YAARX \
        new_logo.jpg

