#!/bin/bash

set -xeuo pipefail

SKIP_GPG=${SKIP_GPG:-}
SKIP_CHECKS=${SKIP_CHECKS:-}

NIX_CACHE=${NIX_CACHE:-/nix}
NIX_IMAGE=${NIX_IMAGE:-nixos/nix:2.24.9}

test -e Makefile && make distclean

./autogen.sh

./configure

make -j $(nproc)

VERSION=$($(dirname $0)/git-version-gen --prefix "" .)
if test x$SKIP_CHECKS = x; then
    grep $VERSION NEWS
fi

OUTDIR=${OUTDIR:-release-$VERSION}
if test -e $OUTDIR; then
    echo "the directory $OUTDIR already exists" >&2
    exit 1
fi

mkdir -p $OUTDIR

rm -f crun-*.tar*

make dist-gzip
make ZSTD_OPT="--ultra -c22" dist-zstd

mv crun-*.tar.gz $OUTDIR
mv crun-*.tar.zst $OUTDIR

make distclean

RUNTIME=${RUNTIME:-podman}
RUNTIME_EXTRA_ARGS=${RUNTIME_EXTRA_ARGS:-}

mkdir -p /nix

NIX_ARGS="--extra-experimental-features nix-command --print-build-logs --option cores $(nproc) --option max-jobs $(nproc)"

for ARCH in amd64 arm64 ppc64le riscv64 s390x; do
    $RUNTIME run --init --rm $RUNTIME_EXTRA_ARGS --privileged -v ${NIX_CACHE}:/nix -v ${PWD}:${PWD} -w ${PWD} ${NIX_IMAGE} \
             nix $NIX_ARGS build --max-jobs auto --file nix/default-${ARCH}.nix
    unshare -m bash -c "test -e /nix || mkdir /nix; mount --bind $NIX_CACHE /nix; ls /nix; cp ./result/bin/crun $OUTDIR/crun-$VERSION-linux-${ARCH}"

    rm -rf result

    $RUNTIME run --init --rm $RUNTIME_EXTRA_ARGS --privileged -v ${NIX_CACHE}:/nix -v ${PWD}:${PWD} -w ${PWD} ${NIX_IMAGE} \
        nix $NIX_ARGS build --max-jobs auto --file nix/default-${ARCH}.nix --arg enableSystemd false
    unshare -m bash -c "test -e /nix || mkdir /nix; mount --bind $NIX_CACHE /nix; ls /nix; cp ./result/bin/crun $OUTDIR/crun-$VERSION-linux-${ARCH}-disable-systemd"

    rm -rf result
done

if test x$SKIP_GPG = x; then
    for i in $OUTDIR/*; do
        gpg2 -b --armour $i
    done
fi
