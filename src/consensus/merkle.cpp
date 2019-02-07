// Copyright (c) 2015-2018 The Earthcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <consensus/merkle.h>
#include <hash.h>
#include <util/strencodings.h>

/*     WARNING! If you're reading this because you're learning about crypto
       and/or designing a new system that will use merkle trees, keep in mind
       that the following merkle tree algorithm has a serious flaw related to
       duplicate txids, resulting in a vulnerability (CVE-2012-2459).

       The reason is that if the number of hashes in the list at a given time
       is odd, the last one is duplicated before computing the next level (which
       is unusual in Merkle trees). This results in certain sequences of
       transactions leading to the same merkle root. For example, these two
       trees:

                    A               A
                  /  \            /   \
                B     C         B       C
               / \    |        / \     / \
              D   E   F       D   E   F   F
             / \ / \ / \     / \ / \ / \ / \
             1 2 3 4 5 6     1 2 3 4 5 6 5 6

       for transaction lists [1,2,3,4,5,6] and [1,2,3,4,5,6,5,6] (where 5 and
       6 are repeated) result in the same root hash A (because the hash of both
       of (F) and (F,F) is C).

       The vulnerability results from being able to send a block with such a
       transaction list, with the same merkle root, and the same block hash as
       the original without duplication, resulting in failed validation. If the
       receiving node proceeds to mark that block as permanently invalid
       however, it will fail to accept further unmodified (and thus potentially
       valid) versions of the same block. We defend against this by detecting
       the case where we would hash two identical hashes at the end of the list
       together, and treating that identically to the block having an invalid
       merkle root. Assuming no double-SHA256 collisions, this will detect all
       known ways of changing the transactions without affecting the merkle
       root.
*/


uint256 ComputeMerkleRoot(std::vector<uint256> hashes, bool* mutated) {
    bool mutation = false;
    /*
        计算所有叶子节点的hash值计算，存储在inner数组
        如果leaves.size()个数如果是2的幂次方，在下面第一个循环一次可获得根的hash值
        ，并且存储在2^k=leaves.size(),inner[k]的位置，假设有8个叶子节点
        那么计算完 inner[3]就是根的hash值，8个叶子节点代码计算过程如下。代码65行 
        1.计算hash(ab) 存储在inner[1]
        2.计算hash(cd) 存储在inner[2]
        3.计算hash(ab+cd=N) 存储在inner[2]  (代码83行 2,3步骤在一个循环执行)
        4.计算hash(ef)  存储在inner[1]，这是会覆盖步骤1
        5.计算hash(gh)  (5,6,7在一个循环连续执行，代码73)
        6.计算hash(ef+gh=M) 
        7.计算hash(M+N) 存储在inner[3]

           abcdefgh 
              /\
          abcd  efgh
           /\     /\
         ab cd ef  gh
         /\  /\  /\  /\
        a b  c d e f g h

    */
    printf("ComputeMerkleRoot hashes.size:%lu,hashes[0]:%s\n",(hashes.size()),hashes[0].ToString().c_str());
    while (hashes.size() > 1) {
        printf("ComputeMerkleRoot hashes.size() > 1\n");
        if (mutated) {
            for (size_t pos = 0; pos + 1 < hashes.size(); pos += 2) {
                if (hashes[pos] == hashes[pos + 1]) mutation = true;
            }
        }
        if (hashes.size() & 1) {
            hashes.push_back(hashes.back());
            printf("ComputeMerkleRoot  hashes.push_back:%s\n",(hashes.back()).ToString().c_str());
        }
        SHA256D64(hashes[0].begin(), hashes[0].begin(), hashes.size() / 2);
        hashes.resize(hashes.size() / 2);
    }
    if (mutated) *mutated = mutation;
    if (hashes.size() == 0) return uint256();
    printf("ComputeMerkleRoot return hashes[0]:%s\n",hashes[0].ToString().c_str());
    return hashes[0];
}


uint256 BlockMerkleRoot(const CBlock& block, bool* mutated)
{
    std::vector<uint256> leaves;
    //获取一个区块交易的数量，也就是merkle的(调用resize设置vector大小，避免)
    //避免在下面赋值需要重新分配内存
    leaves.resize(block.vtx.size());
    for (size_t s = 0; s < block.vtx.size(); s++) {
        leaves[s] = block.vtx[s]->GetHash();//获取每一笔交易的hash值
        printf("BlockMerkleRoot block.vtx[s] : %s\n",(*block.vtx[s]).ToString().c_str());
        printf("BlockMerkleRoot block.vtx[s]->GetHash() : %s\n",(block.vtx[s]->GetHash()).ToString().c_str());
    }
    return ComputeMerkleRoot(std::move(leaves), mutated);
}

uint256 BlockWitnessMerkleRoot(const CBlock& block, bool* mutated)
{
    std::vector<uint256> leaves;
    leaves.resize(block.vtx.size());
    leaves[0].SetNull(); // The witness hash of the coinbase is 0.
    for (size_t s = 1; s < block.vtx.size(); s++) {
        leaves[s] = block.vtx[s]->GetWitnessHash();
    }
    return ComputeMerkleRoot(std::move(leaves), mutated);
}

