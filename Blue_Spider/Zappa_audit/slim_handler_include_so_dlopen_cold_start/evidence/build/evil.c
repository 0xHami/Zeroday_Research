#include <stdio.h>
__attribute__((constructor))
static void _ctor(void) {
    FILE *f = fopen("/tmp/dbf3_marker_d02af01a", "w");
    if (f) { fputs("native-code-executed-via-dlopen-constructor-d02af01a", f); fclose(f); }
}
