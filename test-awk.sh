#!/bin/sh
# End-to-end test on a real system binary: copy gawk, rewrite it with
# `peepopt -m apx` (which also runs the post-rewrite boundary verifier),
# then prove under Intel SDE's APX emulation that the rewritten interpreter
# behaves identically over broad coverage (test-awk.awk), actually executes
# NDD instructions, and that a second pass finds nothing new. gawk's
# switch-heavy interpreter also exercises the jump-table target protection
# on real .rodata tables. Requires SDE_PATH; AWK_BIN overrides /bin/awk.
set -eu

: "${SDE_PATH:?must set SDE_PATH to an Intel SDE kit directory}"
SDE_CHIP="${SDE_CHIP:--dmr}"
AWK_BIN="${AWK_BIN:-/bin/awk}"
LC_ALL=C
export LC_ALL

# Deterministic input: n, n^2 mod 97, and a label cycling through tags.
seq 1 5000 | while read -r n; do
    case $((n % 4)) in
    0) tag="foo$((n % 10))" ;;
    1) tag="bar$((n % 10))" ;;
    2) tag="baz" ;;
    3) tag="qux" ;;
    esac
    printf '%d %d %s\n' "$n" $((n * n % 97)) "$tag"
done > awk-input.txt

# Baseline from the unmodified binary, run natively; twice, to prove the
# coverage script itself is deterministic before blaming any rewrite.
"$AWK_BIN" -f test-awk.awk awk-input.txt > awk-baseline.out
"$AWK_BIN" -f test-awk.awk awk-input.txt > awk-baseline2.out
diff awk-baseline.out awk-baseline2.out

cp -L "$AWK_BIN" test-awk-bin.opt
chmod u+w test-awk-bin.opt
./peepopt -m apx test-awk-bin.opt > awk-peepopt.log
count=$(grep -c '^R ' awk-peepopt.log)
echo "rewrites: $count"
# A -m apx dry run reports ~863 sites today; assert a loose floor so a
# regression that guts a pass fails while binary drift does not.
test "$count" -ge 400

"$SDE_PATH/sde64" $SDE_CHIP -- ./test-awk-bin.opt -f test-awk.awk awk-input.txt > awk-rewritten.out
diff awk-baseline.out awk-rewritten.out

# The mix histogram proves NDD forms executed rather than merely decoded.
"$SDE_PATH/sde64" $SDE_CHIP -mix -omix awk-mix.out -- ./test-awk-bin.opt -f test-awk.awk awk-input.txt > /dev/null
grep -q '^\*apx_ndd' awk-mix.out

# Idempotence: rewritten sites no longer match the candidate shape.
./peepopt -m apx test-awk-bin.opt > awk-peepopt2.log
test "$(grep -c '^R ' awk-peepopt2.log)" -eq 0

echo "test-awk PASS"
