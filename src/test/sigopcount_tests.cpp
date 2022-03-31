#include <vector>
#include <boost/test/unit_test.hpp>
#include <boost/foreach.hpp>

#include "script.h"
#include "key.h"

using namespace std;

// Helpers:
static std::vector<unsigned char>
Serialize(const CScript& s)
{
    std::vector<unsigned char> sSerialized(s);
    return sSerialized;
}

BOOST_AUTO_TEST_SUITE(sigopcount_tests)

BOOST_AUTO_TEST_CASE(GetSigOpCount)
{
    // Test CScript::GetSigOpCount()
    CScript s1;
    BOOST_CHECK_EQUAL(s1.GetSigOpCount(false), 0);
    BOOST_CHECK_EQUAL(s1.GetSigOpCount(true), 0);

    uint160 dummy;
    s1 << OP_1 << dummy << dummy << OP_2 << OP_CHECKMULTISIG;
    BOOST_CHECK_EQUAL(s1