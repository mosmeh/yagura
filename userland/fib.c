#include <panic.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#define MAX_N 45

static uint32_t recursion(uint32_t n) {
    if (n < 2)
        return n;
    return recursion(n - 1) + recursion(n - 2);
}

static uint32_t memo[MAX_N + 1];

static uint32_t memoized_recursion(uint32_t n) {
    if (memo[n])
        return memo[n];
    if (n < 2)
        return memo[n] = n;
    return memo[n] = memoized_recursion(n - 1) + memoized_recursion(n - 2);
}

static void measure_and_report(uint32_t (*func)(uint32_t)) {
    for (size_t i = 30; i <= MAX_N; ++i) {
        clock_t start = clock();
        uint32_t res = func(i);
        clock_t end = clock();
        double elapsed = (double)((end - start) * 1000) / CLOCKS_PER_SEC;
        printf("%u%6u ms: %u\n", i, (unsigned)elapsed, res);
    }
}

int main(void) {
    puts("memoized recursion:");
    measure_and_report(memoized_recursion);

    puts("recursion:");
    measure_and_report(recursion);

    return 0;
}
