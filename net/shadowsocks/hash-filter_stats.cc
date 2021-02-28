#include <cstdint>
#include <iostream>
#include <vector>

#include "absl/random/random.h"
#include "net/shadowsocks/hash-filter.h"

int main() {
    using net::shadowsocks::HashFilter;

    absl::BitGen gen;
    HashFilter filter;
    std::vector<uint64_t> fingerprints;
    for (int i = 0; i < 950000; ++i) {
        uint64_t fingerprint = absl::Uniform<uint64_t>(gen);
        filter.insert(fingerprint);
        fingerprints.push_back(fingerprint);
    }
    std::cout << "inserted " << filter.size() << std::endl;

    int true_positives = 0;
    int false_negatives = 0;
    for (uint64_t fingerprint : fingerprints) {
        if (filter.test(fingerprint)) {
            ++true_positives;
        } else {
            ++false_negatives;
        }
    }
    std::cout << "true positives " << true_positives << std::endl;
    std::cout << "false negatives " << false_negatives << std::endl;

    int false_positives = 0;
    int true_negatives = 0;
    for (int i = 0; i < 10000000; ++i) {
        uint64_t fingerprint = absl::Uniform<uint64_t>(gen);
        if (filter.test(fingerprint)) {
            ++false_positives;
        } else {
            ++true_negatives;
        }
    }
    std::cout << "false positives " << false_positives << std::endl;
    std::cout << "true negatives " << true_negatives << std::endl;
}
