/*
 * tea121-lite MVP capability-boundary demo.
 *
 * This file intentionally groups both successful analyses and current
 * limitations. It is a demonstration fixture, not a correctness oracle for
 * the complete C language.
 *
 * Expected behavior under the current analyzer:
 *   1. mvp_safe_constant             -> clean
 *   2. mvp_definite_oob              -> definite alarm
 *   3. mvp_variable_index            -> possible alarm
 *   4. mvp_strcpy_safe               -> clean
 *   5. mvp_strcpy_oob                -> definite alarm
 *   6. mvp_loop_safe_false_positive  -> possible alarm (current false positive)
 *   7. mvp_loop_oob                  -> possible alarm
 *   8. mvp_constant_branch_fp        -> definite alarm (current false positive)
 *   9. mvp_unknown_effect            -> unknown_effect Diagnostic, no clean claim
 *  10. mvp_unsupported_operation     -> unsupported Diagnostic
 *
 * The false positives are deliberate: they show where loop widening and
 * conditional-feasibility reasoning are still incomplete.
 *
 * Current aggregate result:
 *   6 alarms: 4 intentional detections + 2 known false positives
 *   4 diagnostics: 1 unknown_effect + 3 unsupported instructions
 *   final status: unsupported
 */

#include <string.h>

/* The analyzer does not know this external function's side effects. */
static void external_effect(void *pointer);

/*
 * Direct, fully constant access. Both object size and index are exact, so the
 * analyzer can prove that [7, 8) is inside [0, 8).
 */
int mvp_safe_constant(void) {
    char buffer[8];
    buffer[7] = 'A';
    return buffer[7];
}

/*
 * Direct one-past-the-end access. Offset is exactly 8 and the object is
 * 8 bytes, so the result should be a definite Alarm.
 */
int mvp_definite_oob(void) {
    char buffer[8];
    buffer[8] = 'A';
    return 0;
}

/*
 * The parameter starts as Top. The analyzer cannot prove any particular
 * index safe, but it also cannot prove which concrete index is invalid.
 * This should therefore produce a possible Alarm.
 */
int mvp_variable_index(int index) {
    char buffer[8];
    buffer[index] = 'A';
    return 0;
}

/*
 * Global string literal length is available as an exact summary: "abcd"
 * has length 4, and strcpy writes 5 bytes including the terminator.
 */
int mvp_strcpy_safe(void) {
    char buffer[5];
    strcpy(buffer, "abcd");
    return buffer[0];
}

/*
 * The same copy into a 4-byte object should be a definite Alarm.
 */
int mvp_strcpy_oob(void) {
    char buffer[4];
    strcpy(buffer, "abcd");
    return buffer[0];
}

/*
 * Semantically safe: i is in [0, 9] and the maximum access is [36, 40).
 * Current widening loses the `i <= 9` upper bound, so this is a known
 * false positive.
 */
int mvp_loop_safe_false_positive(void) {
    int buffer[10];
    for (int i = 0; i <= 9; i++) {
        buffer[i] = i + 1;
    }
    return buffer[0];
}

/*
 * Semantically unsafe at i = 10: [40, 44) exceeds the 40-byte object.
 * Current analysis reports the conservative possible result rather than
 * proving the concrete failing iteration.
 */
int mvp_loop_oob(void) {
    int buffer[10];
    for (int i = 0; i <= 10; i++) {
        buffer[i] = i + 1;
    }
    return buffer[0];
}

/*
 * The else branch is statically unreachable because i == 10 and i >= 10 is
 * always true. Current MVP does not yet prune this edge using the constant
 * comparison, so it produces a false definite Alarm.
 */
int mvp_constant_branch_fp(void) {
    int buffer[10];
    int i = 10;
    if (i >= 10) {
        return 0;
    } else {
        buffer[i] = i + 1;
    }
    return 0;
}

/*
 * Unknown external call. The pointer argument is conservatively marked as
 * escaped and the result must contain an unknown_effect Diagnostic instead
 * of being claimed clean.
 */
void mvp_unknown_effect(void) {
    char buffer[8];
    external_effect(buffer);
}

/*
 * The extractor currently leaves shifts and bitwise-or as unsupported
 * operations rather than guessing their semantics.
 */
unsigned mvp_unsupported_operation(unsigned value) {
    return (value << 1) | (value >> 31);
}
