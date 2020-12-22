// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>

#include <hash.h>
#include <tinyformat.h>
#include <util/strencodings.h>
#include <crypto/common.h>
#include <crypto/scrypt.h>
#include <crypto/yespower/yespower.h>
#include <streams.h>
#include <logging.h>

uint256 CBlockHeader::GetHash() const
{
    return SerializeHash(*this);
}

uint256 CBlockHeader::GetPoWHash() const
{
    uint256 thash;
    static const yespower_params_t yespower_microbitcoin = {
            .N = 2048,
            .r = 8,
            .pers = (const uint8_t *)"Tidecoin: Post Quantum Security.",
            .perslen = 32
        };
    
        CDataStream powHead(SER_GETHASH, 0);
        powHead << nVersion  << hashPrevBlock << hashMerkleRoot << nTime << nBits << nNonce;
    
        if (yespower_tls((unsigned char *)powHead.data(), powHead.size(), &yespower_microbitcoin, (yespower_binary_t *)thash.begin())) {
            LogPrintf("Error: GetPoWHash: failed to compute PoW hash (out of memory?)\n");
        }
    
    
    return thash;
}

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}
