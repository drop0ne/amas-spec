#include "amas/types.h"
#include <cstdint>
#include <type_traits>

int main() {
    static_assert(std::is_same<amas_counter_t, std::uint64_t>::value, "counter type must be uint64_t");
    amas_timestamp_view_t timestamp{"2026-08-13T00:00:00Z", UINT64_C(20)};
    amas_side_effect_t effect = AMAS_EFFECT_OBSERVE;
    (void)timestamp;
    (void)effect;
    return 0;
}
