#include <cstdint>

#include "absl/random/random.h"
#include "benchmark/benchmark.h"
#include "net/shadowsocks/hash-filter.h"

namespace net {
namespace shadowsocks {
namespace {

void BM_insert(benchmark::State &state) {
    absl::BitGen gen;
    HashFilter filter;
    int64_t count = 0;
    for (auto _ : state) {
        if (++count >= state.range(0)) {
            filter.clear();
            count = 0;
        }
        filter.insert(absl::Uniform<uint64_t>(gen));
    }
}

void BM_test(benchmark::State &state) {
    absl::BitGen gen;
    HashFilter filter;
    for (int64_t i = 0; i < state.range(0); ++i) {
        filter.insert(absl::Uniform<uint64_t>(gen));
    }
    for (auto _ : state) {
        benchmark::DoNotOptimize(filter.test(absl::Uniform<uint64_t>(gen)));
    }
}

BENCHMARK(BM_insert)
    ->Arg(100000)->Arg(200000)->Arg(400000)->Arg(600000)->Arg(800000)
    ->Arg(900000)->Arg(950000)->Arg(1000000);
BENCHMARK(BM_test)
    ->Arg(0)->Arg(100000)->Arg(200000)->Arg(400000)->Arg(600000)->Arg(800000)
    ->Arg(900000)->Arg(950000)->Arg(1000000);

}  // namespace
}  // namespace shadowsocks
}  // namespace net
