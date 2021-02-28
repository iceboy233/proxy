#include <cstdint>

#include "absl/random/random.h"
#include "benchmark/benchmark.h"
#include "net/shadowsocks/hash-filter.h"

namespace net {
namespace shadowsocks {
namespace {

void BM_insert(benchmark::State &state) {
    absl::BitGen gen;
    for (auto _ : state) {
        HashFilter filter;
        for (int64_t i = 0; i < state.range(0); ++i) {
            filter.insert(absl::Uniform<uint64_t>(gen));
        }
    }
    state.SetItemsProcessed(state.iterations() * state.range(0));
}

void BM_test(benchmark::State &state) {
    absl::BitGen gen;
    HashFilter filter;
    for (auto _ : state) {
        benchmark::DoNotOptimize(filter.test(absl::Uniform<uint64_t>(gen)));
    }
}

BENCHMARK(BM_insert)
    ->Arg(600000)->Arg(700000)->Arg(800000)->Arg(900000)->Arg(950000);
BENCHMARK(BM_test);

}  // namespace
}  // namespace shadowsocks
}  // namespace net
