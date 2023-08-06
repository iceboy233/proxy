#include "util/int-allocator.h"

#include <gtest/gtest.h>

namespace util {
namespace {

TEST(IntAllocatorTest, seq) {
    IntAllocator<int> allocator;
    ASSERT_EQ(allocator.allocate(), 1);
    ASSERT_EQ(allocator.allocate(), 2);
    ASSERT_EQ(allocator.allocate(), 3);
    allocator.deallocate(3);
    allocator.deallocate(2);
    ASSERT_EQ(allocator.allocate(), 2);
    ASSERT_EQ(allocator.allocate(), 3);
    ASSERT_EQ(allocator.allocate(), 4);
    allocator.deallocate(4);
    allocator.deallocate(3);
    allocator.deallocate(2);
    allocator.deallocate(1);
}

TEST(IntAllocatorTest, rseq) {
    IntAllocator<int> allocator;
    ASSERT_EQ(allocator.allocate(), 1);
    ASSERT_EQ(allocator.allocate(), 2);
    ASSERT_EQ(allocator.allocate(), 3);
    allocator.deallocate(1);
    allocator.deallocate(2);
    ASSERT_EQ(allocator.allocate(), 1);
    ASSERT_EQ(allocator.allocate(), 2);
    ASSERT_EQ(allocator.allocate(), 4);
    allocator.deallocate(1);
    allocator.deallocate(2);
    allocator.deallocate(3);
    allocator.deallocate(4);
}

}  // namespace
}  // namespace util
