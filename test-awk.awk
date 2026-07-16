# Deterministic coverage script for test-awk.sh: exercises gawk's
# interpreter broadly so a peepopt-rewritten binary gets compared against
# the original over a wide range of opcodes. Everything here must produce
# identical output on every run of the same binary — no timestamps, no
# unordered array iteration, no locale dependence (the driver pins LC_ALL=C).

function fib(n) {
    return n < 2 ? n : fib(n - 1) + fib(n - 2)
}

function join(a, n,    i, s) {
    for (i = 1; i <= n; i++) {
        s = s (i > 1 ? "," : "") a[i]
    }
    return s
}

BEGIN {
    PROCINFO["sorted_in"] = "@ind_str_asc"

    # Arithmetic: integer, float, modulo, exponent, unary minus, comparison
    printf "arith %d %d %d %.6f %g %d\n",
        7 * 6, 17 % 5, 2 ^ 16, 355 / 113, -1.5e-3, (3 < 4) + (4 <= 3)

    # Printf formats
    printf "fmt %d %i %o %x %X %e %f %g %c %s |%8.3f| |%-6d|\n",
        -42, 42, 64, 255, 255, 12345.678, 12345.678, 0.000123,
        65, "str", 3.14159, 7

    # String functions
    s = "The Quick Brown Fox Jumps Over The Lazy Dog"
    printf "str %d %d %s %s %s\n",
        length(s), index(s, "Fox"), toupper(substr(s, 5, 5)),
        tolower(substr(s, 11, 5)), substr(s, 37)
    t = s
    printf "sub %d %s\n", gsub(/o/, "0", t), t
    t = s
    sub(/Quick/, "[&&]", t)
    printf "amp %s\n", t
    printf "gensub %s\n", gensub(/([A-Z])[a-z]+/, "<\\1>", "g", s)
    if (match(s, /(B[a-z]+) (F[a-z]+)/, m)) {
        printf "match %d %d %s %s\n", RSTART, RLENGTH, m[1], m[2]
    }
    n = split("alpha:beta:gamma:delta", parts, ":")
    printf "split %d %s\n", n, join(parts, n)
    printf "strtonum %d %d %d\n", strtonum("0x1F"), strtonum("017"), strtonum("99")

    # Bitwise operations
    printf "bits %d %d %d %d %d %d\n",
        and(0xF0F0, 0x0FF0), or(0xF000, 0x000F), xor(0xFFFF, 0x0F0F),
        lshift(1, 20), rshift(1048576, 10), and(compl(0), 0xFFFF)

    # Deterministic PRNG: same binary, same seed, same sequence
    srand(42)
    out = ""
    for (i = 0; i < 8; i++) {
        out = out sprintf(" %.10f", rand())
    }
    printf "rand%s\n", out

    # Recursion
    printf "fib %d %d %d\n", fib(10), fib(15), fib(20)

    # Arrays: multi-dimensional, delete, sorted iteration, asort/asorti
    for (i = 1; i <= 3; i++) {
        for (j = 1; j <= 3; j++) {
            grid[i, j] = i * 10 + j
        }
    }
    delete grid[2, 2]
    total = 0
    for (k in grid) {
        total += grid[k]
    }
    printf "grid %d %d\n", total, length(grid)
    split("banana apple cherry apple", fruit, " ")
    nf = asort(fruit, sorted)
    printf "asort %d %s\n", nf, join(sorted, nf)
    words["zeta"] = 1; words["alpha"] = 2; words["mu"] = 3
    ni = asorti(words, idx)
    printf "asorti %d %s\n", ni, join(idx, ni)
}

# Per-record rules over the generated input (fields: n, n^2 mod 97, label)
/^[0-9]/ {
    sum += $1
    sq_sum += $2
    if (min == "" || $1 < min) min = $1
    if ($1 > max) max = $1
}

$3 ~ /^(foo|bar)[0-9]*$/ {
    tagged++
    freq[$3 ~ /foo/ ? "foo" : "bar"]++
}

NF == 3 && $1 % 7 == 0 {
    sevens++
    seven_cat = seven_cat "/" $1
}

END {
    PROCINFO["sorted_in"] = "@ind_str_asc"
    printf "agg records=%d sum=%d sq=%d min=%d max=%d\n", NR, sum, sq_sum, min, max
    printf "tagged %d", tagged
    for (k in freq) {
        printf " %s=%d", k, freq[k]
    }
    printf "\n"
    printf "sevens %d %s\n", sevens, substr(seven_cat, 2, 60)
}
