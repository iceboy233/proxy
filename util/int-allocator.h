#ifndef _UTIL_INT_ALLOCATOR_H
#define _UTIL_INT_ALLOCATOR_H

#include "absl/container/btree_set.h"

namespace util {

template <typename T>
class IntAllocator {
public:
    T allocate();
    void deallocate(T value);

private:
    absl::btree_set<int> spare_;
    T next_ = 1;
};

template <typename T>
T IntAllocator<T>::allocate() {
    auto iter = spare_.begin();
    if (iter == spare_.end()) {
        return next_++;
    }
    int value = *iter;
    spare_.erase(iter);
    return value;
}

template <typename T>
void IntAllocator<T>::deallocate(T value) {
    if (value + 1 != next_) {
        spare_.insert(value);
        return;
    }
    --next_;
    auto iter = spare_.end();
    while (iter != spare_.begin() && *prev(iter) + 1 == next_) {
        --next_;
        iter = spare_.erase(iter);
    }
}

}  // namespace util

#endif  // _UTIL_INT_ALLOCATOR_H
