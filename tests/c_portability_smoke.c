#include "amas/types.h"

int main(void) {
    amas_authority_tier_t tier = AMAS_TIER_SESSION;
    amas_counter_t count = AMAS_JSON_SAFE_UINT64;
    amas_sha256_t digest = {{0}};
    amas_utf8_view_t text = {"amas", UINT64_C(4)};
    (void)tier;
    (void)count;
    (void)digest;
    (void)text;
    return 0;
}
