#!/bin/sh

cd $1

cd /crun
git clean -fdx
./autogen.sh
./configure CFLAGS='-Wall -Wextra -Werror' --disable-systemd && make -j $(nproc)

