#!/bin/sh
# End-to-end test for the APX NDD pass: rewrite the fixture binary with
# `peepopt -m apx`, then prove under Intel SDE's APX emulation that it
# behaves identically, actually executes NDD instructions, and that a second
# pass finds nothing new. Requires SDE_PATH (an SDE kit directory); the chip
# defaults to Diamond Rapids, the first APX implementation.
set -eu

: "${SDE_PATH:?must set SDE_PATH to an Intel SDE kit directory}"
SDE_CHIP="${SDE_CHIP:--dmr}"

./test-apx-fixture > apx-baseline.out

cp test-apx-fixture test-apx-fixture.opt
./peepopt -m apx test-apx-fixture.opt > apx-peepopt.log
count=$(grep -c '^R apx ' apx-peepopt.log)
echo "R apx rewrites: $count"
# The 17 fixture bodies contribute 16 (the REX-less 32-bit pair must stay);
# crt/driver code may legitimately add more.
test "$count" -ge 16

"$SDE_PATH/sde64" $SDE_CHIP -- ./test-apx-fixture.opt > apx-rewritten.out
diff apx-baseline.out apx-rewritten.out

# The mix histogram proves NDD forms executed rather than merely decoded.
"$SDE_PATH/sde64" $SDE_CHIP -mix -omix apx-mix.out -- ./test-apx-fixture.opt > /dev/null
grep -q '^\*apx_ndd' apx-mix.out

# Idempotence: rewritten sites no longer match the candidate shape.
./peepopt -m apx test-apx-fixture.opt > apx-peepopt2.log
test "$(grep -c '^R apx ' apx-peepopt2.log)" -eq 0

echo "test-apx PASS"
