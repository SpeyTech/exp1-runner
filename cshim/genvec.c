/* genvec.c: emit committed self-check vectors for the runner bindings.
 * Root seed is the stage 0 seed; pair 0. Output: hex lines the Python
 * side pins. Run once at package build; the vectors file is committed. */
#include "x_types.h"
#include "x_schedule.h"
#include "x_rig.h"
#include "x_redact.h"
#include "axilog/sha256.h"
#include <stdio.h>
#include <string.h>

#define ROOT 0x4558503153303031ULL /* EXP1S001, matches x_run_s0 */

static void hexdump(const char *name, const uint8_t *p, size_t n)
{
    size_t i;
    printf("%s=", name);
    for (i = 0; i < n; i++) printf("%02x", p[i]);
    printf("\n");
}

int main(void)
{
    l0_fault_flags_t f;
    x_twin_t tw;
    x_transcript_t tr;
    static char ctx[X_CONTEXT_MAX], red[X_CONTEXT_MAX];
    uint8_t ser[X_SCHED_SER_BYTES];
    size_t n;

    l0_fault_init(&f);
    if (x_twin_generate(&tw, ROOT, 0u, &f) != 0 || l0_fault_any(&f)) return 1;
    if (x_schedule_serialise(ser, &tw.prod, &f) != 0) return 1;
    hexdump("PROD0", ser, sizeof ser);
    if (x_schedule_serialise(ser, &tw.eval, &f) != 0) return 1;
    hexdump("EVAL0", ser, sizeof ser);

    if (x_rig_run_scripted(&tr, &tw.prod, &f) != 0) return 1;
    if (x_rig_flatten(ctx, sizeof ctx, &n, &tr, &f) != 0) return 1;
    printf("CTXLEN=%zu\nCANARY=%u\n", n, tr.canary);
    /* Corpus-sensitive vector: pair 0 has a failing slot, so the
     * flattened (unredacted) context carries the harvested error line.
     * A corpus change moves this hash, unlike the redaction head which
     * is assistant text. This closes the session-1 gap. */
    {
        uint8_t h[32];
        int i;
        axilog_sha256(h, (const uint8_t *)ctx, n);
        printf("CTXHASH=");
        for (i = 0; i < 32; i++) printf("%02x", h[i]);
        printf("\n");
    }
    if (x_redact(red, sizeof red, &n, &tr, &f) != 0) return 1;
    printf("REDLEN=%zu\n", n);
    hexdump("REDHEAD", (const uint8_t *)red, n < 48 ? n : 48);
    return 0;
}
