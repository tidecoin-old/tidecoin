// Copyright (c) 2012-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <key.h>

#include <key_io.h>
#include <script/script.h>
#include <uint256.h>
#include <util/system.h>
#include <util/strencodings.h>
#include <test/test_bitcoin.h>

#include <string>
#include <vector>

#include <boost/test/unit_test.hpp>

static const std::string strSecret1 = "6uGFQ4DSW7zh1viHZi6iiVT17CncvoaV4MHvGvJKPDaLCdymj87";
static const std::string strSecret2 = "6vVo7sPkeLTwVdAntrv4Gbnsyr75H8ChD3P5iyHziwaqe8mCYR5";
static const std::string strSecret1C = "T3gJYmBuZXsdd65E7NQF88ZmUP2MaUanqnZg9GFS94W7kND4Ebjq";
static const std::string strSecret2C = "T986ZKRRdnuuXLeDZuKBRrZW1ujotAncU9WTrFU1n7vMgRW75ZtF";
static const std::string addr1 = "LiUo6Zn39joYJBzPUhssbDwAywhjFcoHE3";
static const std::string addr2 = "LZJvLSP5SGKcFS13MHgdrVhpFUbEMB5XVC";
static const std::string addr1C = "Lh2G82Bi33RNuzz4UfSMZbh54jnWHVnmw8";
static const std::string addr2C = "LWegHWHB5rmaF5rgWYt1YN3StapRdnGJfU";

static const std::string strAddressBad = "Lbi6bpMhSwp2CXkivEeUK9wzyQEFzHDfSr";


BOOST_FIXTURE_TEST_SUITE(key_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(key_test1){

}

BOOST_AUTO_TEST_CASE(key_signature_tests)
{

}

BOOST_AUTO_TEST_SUITE_END()
