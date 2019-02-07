// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Earthcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>

#include <hash.h>
#include <tinyformat.h>
#include <util/strencodings.h>
#include <crypto/common.h>

// -- by eac
#define BEGIN(a)            ((char*)&(a))
#define END(a)              ((char*)&((&(a))[1]))

uint256 CBlockHeader::GetHash() const
{
    //printf("CBlockHeader::GetHash: %d , %d \n",nVersion,nNonce);
    //printf("GetHash-begin-end %s\n", (SerializeHash(*this)).ToString().c_str());
    return SerializeHash(*this);

    //printf("GetHash-begin-end nNonce %d ,Hash: %s\n", nNonce, (Hash(BEGIN(nVersion), END(nNonce))).ToString().c_str());
    // -- by eac
    //return Hash(BEGIN(nVersion), END(nNonce));


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
