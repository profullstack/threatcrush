/*
 * The interface between libinjection (vendor/libinjection, BSD-3-Clause) and
 * ThreatCrush's JavaScript wrapper (src/core/crs/libinjection.ts). Compiled
 * with libinjection into src/core/crs/libinjection/libinjection.wasm by
 * scripts/build-libinjection-wasm.mjs.
 *
 * JavaScript asks for an input buffer of n bytes, copies the value into it and
 * calls tc_sqli(n) or tc_xss(n), which return libinjection's
 * injection_result_t: 1 TRUE, 0 FALSE, -1 ERROR.
 */
#include <stdlib.h>

#include "libinjection.h"
#include "libinjection_xss.h"

static char *input;
static size_t input_cap;

/* libinjection writes at most 5 tokens and a NUL; ModSecurity passes 8 bytes. */
static char fingerprint[8];

/* A buffer of at least n bytes for the next call's input, or NULL if out of memory. */
char *tc_input(size_t n) {
    if (n > input_cap || input == NULL) {
        free(input);
        input_cap = n > 256 ? n : 256;
        input = malloc(input_cap);
        if (input == NULL) input_cap = 0;
    }
    return input;
}

int tc_sqli(size_t n) {
    fingerprint[0] = '\0';
    return (int)libinjection_sqli(input, n, fingerprint);
}

/* The NUL-terminated fingerprint of the last tc_sqli call. */
const char *tc_fingerprint(void) { return fingerprint; }

int tc_xss(size_t n) { return (int)libinjection_xss(input, n); }
