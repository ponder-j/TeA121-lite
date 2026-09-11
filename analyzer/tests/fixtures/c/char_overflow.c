/*
 * Typed-value overflow demo (CWE-190).
 *
 * Plain ``char`` is signed on the supported targets, so ``ch`` can hold
 * [-128, 127].  Incrementing the maximum leaves the type range.
 */
int main(void) {
    char ch = 127;
    ch++;
    return 0;
}
