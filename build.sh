#!/bin/bash

sh autogen.sh
./configure --enable-default-event-plugin
make -j 2
