#include <cstdint>

#include "absl/random/random.h"
#include "benchmark/benchmark.h"
#include "net/shadowsocks/hash-filter.h"

namespace net {
namespace shadowsocks {
namespace {

void BM_clear(benchmark::State &state) {
    HashFilter filter;
    for (auto _ : state) {
        filter.clear();
    }
}

void BM_insert(benchmark::State &state) {
    absl::InsecureBitGen gen;
    HashFilter filter;
    for (auto _ : state) {
        if (filter.size() >= state.range(0)) {
            filter.clear();
        }
        filter.insert(absl::Uniform<uint64_t>(gen));
    }
}

void BM_test(benchmark::State &state) {
    absl::InsecureBitGen gen;
    HashFilter filter;
    while (filter.size() < state.range(0)) {
        filter.insert(absl::Uniform<uint64_t>(gen));
    }
    for (auto _ : state) {
        benchmark::DoNotOptimize(filter.test(absl::Uniform<uint64_t>(gen)));
    }
}

BENCHMARK(BM_clear);
BENCHMARK(BM_insert)
    ->Arg(100000)->Arg(200000)->Arg(400000)->Arg(600000)->Arg(800000)
    ->Arg(900000)->Arg(950000)->Arg(1000000);
BENCHMARK(BM_test)
    ->Arg(0)->Arg(100000)->Arg(200000)->Arg(400000)->Arg(600000)->Arg(800000)
    ->Arg(900000)->Arg(950000)->Arg(1000000);

}  // namespace
}  // namespace shadowsocks
}  // namespace net
