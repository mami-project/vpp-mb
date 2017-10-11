#!/bin/bash

cd ../mmb-plugin
autoreconf -fis
./configure
make
sudo make install

