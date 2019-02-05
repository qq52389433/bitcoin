// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>

#include <chainparamsseeds.h>
#include <consensus/merkle.h>
#include <tinyformat.h>
#include <util/system.h>
#include <util/strencodings.h>
#include <versionbitsinfo.h>

#include <assert.h>

#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>

// -- by eac 
#include <arith_uint256.h>
#include <pow.h>

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].nValue = genesisReward;   // 0
    txNew.vout[0].scriptPubKey = genesisOutputScript;

    CBlock genesis;
    genesis.nTime    = nTime;   // 1386746168
    genesis.nBits    = nBits;   // 0x1e0ffff0
    genesis.nNonce   = nNonce;  // 12468024
    genesis.nVersion = nVersion;  // 1
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    //const char* pszTimestamp = "The Times 03/Jan/2009 Chancellor on brink of second bailout for banks";
    //const CScript genesisOutputScript = CScript() << ParseHex("04678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5f") << OP_CHECKSIG;
    // -- by eac
    const char* pszTimestamp = " December 19, 2013 \x97 Arrest, strip-search of Indian diplomat in New York triggers uproar.";
    //公钥
    //const CScript genesisOutputScript = CScript() << ParseHex("04dcba12349012341234900abcd12223abcd455abcd77788abcd000000aaaaabbbbbcccccdddddeeeeeff00ff00ff00ff001234567890abcdef0022446688abc11") << OP_CHECKSIG;
    const CScript genesisOutputScript = CScript() << ParseHex("04cf0d66c027f7a51e52a99916e3f76eb2bae54d5f17e529ec529b234d5b5ff66bd98d10d00d62fa90d30761247471f6a240a21f35928c3c3058590f1ccfc43048") << OP_CHECKSIG;
   
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

/**
 * Main network
 */
class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP16Exception = uint256S("0x00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22");
        consensus.BIP34Height = 227931;
        consensus.BIP34Hash = uint256S("0x000000000000024b89b42a942fe0d9fea3bb44ab7bd1b19115dd6a759c0808b8");
        consensus.BIP65Height = 388381; // 000000000000000004c2b624ed5d7756c508d90fd0da2c7c679febfa6c4735f0
        consensus.BIP66Height = 363725; // 00000000000000000379eaa19dce8c9b722d46ae6a57c2f1a988119488b50931
        //consensus.powLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        // -- by eac   00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
        //consensus.powLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.powLimit = uint256S("000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1916; // 95% of 2016
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1462060800; // May 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800; // May 1st, 2017

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1479168000; // November 15th, 2016.
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1510704000; // November 15th, 2017.

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000028822fef1c230963535a90d");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x0000000000000000002e63058c023a9a1de233554f28c7b21380b6c9003f36a8"); //534292

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        //定义消息头， {0xf9, 0xbe, 0xb4, 0xd9}
        // pchMessageStart[0] = 0xf9;
        // pchMessageStart[1] = 0xbe;
        // pchMessageStart[2] = 0xb4;
        // pchMessageStart[3] = 0xd9;
        // -- by eac  {0xc0, 0xdb, 0xf1, 0xfd}
        pchMessageStart[0] = 0xc0;
        pchMessageStart[1] = 0xdb;
        pchMessageStart[2] = 0xf1;
        pchMessageStart[3] = 0xfd;

        //nDefaultPort = 8333;
        //--by eac
        nDefaultPort = 35677;		
        nPruneAfterHeight = 100000;

        //genesis = CreateGenesisBlock(1231006505, 2083236893, 0x1d00ffff, 1, 50 * COIN);
        
        // -- by eac  
        // nTime = 1386746168, nNonce = 12468024, nBits = 0x1e0ffff0, nVersion = 1
        // genesisReward = nValue = 0 * COIN;
        //genesis = CreateGenesisBlock(1386746168, 12468024, 0x1e0ffff0, 1, 0 * COIN);

        //genesis = CreateGenesisBlock(1386746168, 1516312, 0x1e0ffff0, 1, 0 * COIN);

        genesis = CreateGenesisBlock(1386746168, 563, 0x1f0ffff0, 1, 80 * COIN);
        
        
        //  //符合要求的nNonce值。这个值，我通过下面的代码来寻找。 
        //     //这段代码寻找我的nNonce值 
        //     unsigned int i;
        //     //arith_uint256 bnTarget; 
        //     for(i=0;i<0x7fffffff;i++){ //基本上是穷举法 ，让i不断增加
        //         genesis.nNonce = i; //将i赋值给nNonce 
        //         consensus.hashGenesisBlock = genesis.GetHash();//生成 hash值 
        //         //bnTarget.SetCompact(genesis.nBits);

        //         bool fNegative;
        //         bool fOverflow;
        //         arith_uint256 bnTarget;

        //         bnTarget.SetCompact(genesis.nBits, &fNegative, &fOverflow);

        //         // Check range
        //         //if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimit))
        //         //if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(consensus.powLimit))
        //         //    continue;

        //         // Check proof of work matches claimed amount
        //         if (UintToArith256(consensus.hashGenesisBlock) > bnTarget){
        //             printf("UintToArith256 hashGenesisBlock: %s\n",UintToArith256(consensus.hashGenesisBlock).ToString().c_str());
        //             printf("bnTarget: %s\n",bnTarget.ToString().c_str());
        //             continue;
        //         }else{

        //         //将nBits参数转换成256位的最大hash值。挖矿就是要寻找比这个 hash值更小的值。 
        //         //if (consensus.hashGenesisBlock < bnTarget.GetCompact()){
        //         //if (consensus.hashGenesisBlock < consensus.powLimit){
        //         //if (CheckProofOfWork(consensus.hashGenesisBlock, genesis.nBits, Params().GetConsensus())){
                
        //             //判断hash值是否小于最大hash值,如果小于，那就说明我找到了合适的nNonce值。挖矿成功。
        //             //我这里找到的值就是130387，当然，我不会每次都重新挖我的创世区块，
        //             //实际运行的时候，我会把130387直接写入nNonce。
        //             printf("\nfind Nonce! I=%i \n ",i);
        //             printf("consensus.hashGenesisBlock: %s\n",consensus.hashGenesisBlock.ToString().c_str());
        //             printf("consensus.powLimit: %s\n",consensus.powLimit.ToString().c_str());
        //             //cout<<"\nnNonce="<<genesis.nNonce<<"hash="<< consensus.hashGenesisBlock.GetHex(); 
        //             break;
        //             //寻找到了这个值，自然就退出循环。实际上，符合条件的nNonce不会只有一个。
        //         //但是，我们只要找到这个符合条件的值就可以了。
        //         }
        //     }
        //     //------寻找nNonce值代码结束

        printf("start getHash!\n");
        printf("nVersion: %i\n", genesis.nVersion);
        printf("hashPrevBlock: %s\n", genesis.hashPrevBlock.ToString().c_str());
        printf("hashMerkleRoot: %s\n", genesis.hashMerkleRoot.ToString().c_str());
        printf("nTime: %d\n", genesis.nTime);//.ToString().c_str());
        printf("nBits: %d\n", genesis.nBits);//.ToString().c_str());
        printf("nNonce: %d\n", genesis.nNonce);

        //genesis.hashMerkleRoot = uint256S("0x13757c3610411891452ac1f04d7f81946339b0e5b5aba216e6646e81805c4bb1");
        consensus.hashGenesisBlock = genesis.GetHash();
        
        //assert(consensus.hashGenesisBlock == uint256S("0x000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"));
        //assert(genesis.hashMerkleRoot == uint256S("0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"));

        // -- by eac
        //printf("%s\n", genesis.ToString().c_str());
        printf("consensus.hashGenesisBlock: %s\n", consensus.hashGenesisBlock.ToString().c_str());
        printf("genesis.hashMerkleRoot: %s\n", genesis.hashMerkleRoot.ToString().c_str());
        //assert(consensus.hashGenesisBlock == uint256S("0x21717d4df403301c0538f1cb9af718e483ad06728bbcd8cc6c9511e2f9146ced"));
        //assert(genesis.hashMerkleRoot == uint256S("0x13757c3610411891452ac1f04d7f81946339b0e5b5aba216e6646e81805c4bb1"));

        assert(consensus.hashGenesisBlock == uint256S("0x0007e5a233e96f7b8d2413060ec38cf73c6f201bdb72f97b3241cc8ac6950a81"));
        assert(genesis.hashMerkleRoot == uint256S("0x83da06b71556e543092d5349a16c9adfdfc18c78cc3ae1b0f61a532f5a98e5fb"));

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as a oneshot if they don't support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.
        // vSeeds.emplace_back("seed.bitcoin.sipa.be"); // Pieter Wuille, only supports x1, x5, x9, and xd
        // vSeeds.emplace_back("dnsseed.bluematt.me"); // Matt Corallo, only supports x9
        // vSeeds.emplace_back("dnsseed.bitcoin.dashjr.org"); // Luke Dashjr
        // vSeeds.emplace_back("seed.bitcoinstats.com"); // Christian Decker, supports x1 - xf
        // vSeeds.emplace_back("seed.bitcoin.jonasschnelli.ch"); // Jonas Schnelli, only supports x1, x5, x9, and xd
        // vSeeds.emplace_back("seed.btc.petertodd.org"); // Peter Todd, only supports x1, x5, x9, and xd
        // vSeeds.emplace_back("seed.bitcoin.sprovoost.nl"); // Sjors Provoost
        // -- by eac
        vSeeds.emplace_back("148.163.168.167"); 
        //vSeeds.emplace_back("192.168.26.102"); 
        //vSeeds.emplace_back("47.88.218.10"); 
        
        

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,0);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,5);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,128);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4};

        bech32_hrp = "bc";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        // checkpointData = {
        //     {
        //         { 11111, uint256S("0x0000000069e244f73d78e8fd29ba2fd2ed618bd6fa2ee92559f542fdb26e7c1d")},
        //         { 33333, uint256S("0x000000002dd5588a74784eaa7ab0507a18ad16a236e7b1ce69f00d7ddfb5d0a6")},
        //         { 74000, uint256S("0x0000000000573993a3c9e41ce34471c079dcf5f52a0e824a81e7f953b8661a20")},
        //         {105000, uint256S("0x00000000000291ce28027faea320c8d2b054b2e0fe44a773f3eefb151d6bdc97")},
        //         {134444, uint256S("0x00000000000005b12ffd4cd315cd34ffd4a594f430ac814c91184a0d42d2b0fe")},
        //         {168000, uint256S("0x000000000000099e61ea72015e79632f216fe6cb33d7899acb35b75c8303b763")},
        //         {193000, uint256S("0x000000000000059f452a5f7340de6682a977387c17010ff6e6c3bd83ca8b1317")},
        //         {210000, uint256S("0x000000000000048b95347e83192f69cf0366076336c639f9b7228e9ba171342e")},
        //         {216116, uint256S("0x00000000000001b4f4b433e81ee46494af945cf96014816a4e2370f11b23df4e")},
        //         {225430, uint256S("0x00000000000001c108384350f74090433e7fcf79a606b8e797f065b130575932")},
        //         {250000, uint256S("0x000000000000003887df1f29024b06fc2200b55f8af8f35453d7be294df2d214")},
        //         {279000, uint256S("0x0000000000000001ae8c72a0b0c301f67e3afca10e819efa9041e458e9bd7e40")},
        //         {295000, uint256S("0x00000000000000004d9b4ef50f0f9d686fd69db2e03af35a100370c64632a983")},
        //     }
        // };

        // -- by eac
        // checkpointData = {
        //     {
        //         {    100, uint256S("0xc3d91cb4726610d422f8652a5a7cc21bd42e1b8009c00462081c81316d9abad6")},
        //         {  10000, uint256S("0x7b50ea3b42e613e65ec2aca6797a5780e1c545a617e4a610577fb4b040f0035b")},
        //         {  30000, uint256S("0x43e2fe7c700191ddfabe2cd09dfd3fc9eb6331f3c19e59b3e4a87cfa88cac543")},
        //         {  50000, uint256S("0x6a4f705b7a34de7dc1b6573b3595fde05c7b4303b35ede20a3b945244adc6c70")},
        //         {  69500, uint256S("0x8387b49853928fc67d8b8421fd9214184db590eeecd90a200c9d902d8b42e11f")},
        //         {  80000, uint256S("0xa7d7ac0b4b1f5eb56b50ad0693c47f47863b8df81f17514bcb5e59c0a4074eba")},
        //         {  91000, uint256S("0x3f135e0e06ae032de5437ae2b981e3ab84c7d22310224a6e53c6e6e769e8f8f0")},
        //         { 101000, uint256S("0xba5948ef9fce38887df24c54366121437d336bd67a4332508248def0032c5d6e")},
        //         { 111000, uint256S("0xbb9cc6e2d9da343774dc4b49be417731991b90ef53a7fa7eb669cce237223c37")},
        //         { 121000, uint256S("0x1d286956120cf256bed13bcc1f5fe79a98347c80f2225ded92bbbdfc1147b5f5")},
        //         { 136000, uint256S("0xb7c7416c40425bc7976c7b6b87734e2fb84855eecd30e3e9673caf8c7f599b5c")},
        //         { 153000, uint256S("0x9f31abd27721e7eb2b58c0a61a117c324a3a6b8f45c82e8963b1bd14166f6510")},
        //         { 161000, uint256S("0xf7a9069c705516f60878bf6da9bac02c12d0d8984cb90bce03fe34842ba7eb3d")},
        //         { 170000, uint256S("0x827d5ce5ed69153deacab9a2d3c35a7b33cdaa397a6a4a540d538b765182f234")},
        //         { 181000, uint256S("0x69fa48e8b9231f101df79c5b3174feb70bf6da11d88a4ce879a7c9ecb799f46d")},
        //         { 191000, uint256S("0x80a9ea6b375312c376de880b6958459973a95be1dcbf28db1731452a59ef9750")},
        //         { 200000, uint256S("0x003a4cb3bf206cfc23b9477e1c433280ae1b3393a21aa858aa322e8402204cd0")},
        //         { 220000, uint256S("0xbed97c09983d1ee14d5f925c31dc4245b6c9d66af4fdadcf973465cb265b52c3")},
        //         { 240000, uint256S("0xd4e782aae21f551d4a8d7756eb92dfa2cb23d1ede58162382b3bbced4fbee518")},
        //         { 260000, uint256S("0xdfaef016341fab642190a6656b6c52efbdb43ce8a590bace86793f3c1b1276be")},
        //         { 280000, uint256S("0x6b836125e431d3fd31ef55f5fbbdfdadc4d9b98b11db5ee0b7ac8f1f8c3ede32")},
        //         { 301000, uint256S("0xc557d7363393148a630a3fda46ca380a202fe82fa594c5e57f88fbece755bb05")},
        //         { 324000, uint256S("0x8f6cb33fd75e327eb1a1d90b13ba2124e077b4cc5240bc7ec8039aee8a345e85")},
        //         { 347000, uint256S("0xf4bd9894306981ca4c20cdbf0bbd9e9832696701f5b3d3a840d026b893db7337")},
        //         { 383000, uint256S("0xd902cf21480851c35844b0744ea72c1bc2d9318e87a7de63a5e3e3854331a39c")},
        //         { 401000, uint256S("0xe43417eb3b583fd28dfbfb38c65763d990b4c370066ac615a08c4c5c3910ebc9")},
        //         { 420000, uint256S("0x76e0de5adb117e12e85beb264c45e768e47d1720d72a49a24daab57493e07a04")},
        //         { 440000, uint256S("0xbbc6051554e936d0a18adddb95064b16a001ce164d061fb399f26416ce7860f9")},
        //         { 461000, uint256S("0xa60d67991b4963efee5b102c281755afde28803b9bc0b647f0cbc2120b35185b")},
        //         { 480000, uint256S("0xd88e6f5e77a8cb4bcb883168f357a94db31203f1977a15d90b6f6d4c2edebbbb")},
        //         { 500000, uint256S("0xa2989da9f8e785f7040c2e2dfc0177babbf736cfad9f2b401656fea4c3c7c9db")},
        //         { 510000, uint256S("0x7646ee1a99843f1e303d85e14c58dbf2bd65b393b273b379de14534743111b72")},
        //         { 520000, uint256S("0x114f6c2065ad5e668b901dd5ed5e9d302d6153f8e38381fbfd44485d7d499e10")},
        //         { 540000, uint256S("0xd7480699ff87574bfad0038b8697f9bc4df5f0cba31058a637eefbc94e402761")},
        //         { 600000, uint256S("0x85ac8dbbba7a870a45740677be5f35114cb3b70f56d1c93cc2aaf415629037e7")},
        //         { 700000, uint256S("0x450af2f828cdfb29be40d644d39a0858b29fe05b556946db31a7c365cffed705")},
        //         { 800001, uint256S("0xa6d915a25e905d1329e482aac91228b168de6e6efb3838df16c21c3ac3a82ea2")},
        //         { 900000, uint256S("0x7854a46edbdc4311006a9fd27ae601bb1ebd22fc5e8d6f1757e15237080a545b")},
        //         {1000000, uint256S("0xec070022a4fe9b450e02edd08c6ed355047bc8e65ef05e881b51c212d7c0fe95")},
        //         {1010001, uint256S("0xa2cb82b4ae04854108b18c502f1b33e18c6f69b9d4407e8aa205a23242cd4daf")},
        //         {1050000, uint256S("0x3369fa16394aa222736793fd3fd50d7f7a34d5b1ff67b344eaba269daab28a68")},
        //         {1060000, uint256S("0x44e3b2bfbfb9eef5ef34df447c9ea4c4912b8a3819c2c56dfd0dc02db8a84347")},
        //         {1100000, uint256S("0x4173031420285636eeecfab94e4e62e3a3cf6e144b97b2cc3622c683e09102f0")},
        //         {1394462, uint256S("0xef308b7f477903acd8f300e6f0684c4888ce28c491fc32c1c469bfba6abf091b")},
        //         {1400000, uint256S("0x4bc57c3a57cc977db9f3bd6a095f51c0c7cc9c30fa8554505fa8f8e33d9f2b80")},
        //         {1410000, uint256S("0x7512574ec717d46a90b8c36fd923ef819fdc298b8e4be57be631519662f0db59")},
        //         {1573741, uint256S("0x6e4dacfd1684e71a178f29f3e9c714d264e6d385f64c31cdbe532b3204ce4e1d")},
        //         {1574000, uint256S("0xcef389868efd7785b977eb86527e8049a2a5ea472a6ed9bfc0741c6d6b39234b")},
        //         {1579000, uint256S("0x12cb8ae28107d99f4ba24465b9abf21f98fe855d9b09449cf5c8ed98120829c1")},
        //         {1589000, uint256S("0x479746c27e323e233e58af6024bb7b9727a26bc0114c26ff537469e6ada105e1")},
        //         {1600000, uint256S("0xf44cbdcb21fc7716947f763ccca5de5b02ffff7f14beafef0a7486067f6777fa")},
        //         {1650000, uint256S("0x70caabb0720c95f67a02eabfde27253eaa8698dc6ea5716631890876b9df421a")},        
        //         {1700000, uint256S("0x691eb62d25a0961e81f1a8427b8c21e01ade5befe4a94be5826f49cfecc070a0")},
        //         {1750000, uint256S("0x8971f1790e58c6de0ea2854872c6ad03752b65567ab8e5c8458ae4a6eb9fb783")},
        //         {1766666, uint256S("0xffb7d30ec4d20cae926af05252dc39dbc433b068a0807a8f0dfa63521caca6f0")},
        //         {1888888, uint256S("0x89530dba778db5a540aac6b7b8659cee8909ba445fa5a54ba3023e98e045692d")},
        //         {1892222, uint256S("0x685a23cfa75e4e084f32b6a4ae09b3113c9509d84ce0559813627d462df6db88")},
        //         {2227008, uint256S("0x23eb6ca0fc87c887485a1417364dae6c3ae5cc4801c6eef8fc2b6bb83cdf9013")},
        //         {2242222, uint256S("0x98b01e772f0ca3b3ac875857e4f3b6571f8f18b8b896d0cb2feefeca90b69583")},
        //     }
        // };

        checkpointData = {
            {
                {    100, uint256S("0x00047d32d44bd2784a076fdb391eaa42379c8dd2bd79460bd7581abc9511e689")},
            }
        };

        chainTxData = ChainTxData{
            // Data from rpc: getchaintxstats 4096 0000000000000000002e63058c023a9a1de233554f28c7b21380b6c9003f36a8
            /* nTime    */ 1532884444,
            /* nTxCount */ 331282217,
            /* dTxRate  */ 2.4
        };

        /* disable fallback fee on mainnet */
        m_fallback_fee_enabled = false;
    }
};

/**
 * Testnet (v3)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP16Exception = uint256S("0x00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105");
        consensus.BIP34Height = 21111;
        consensus.BIP34Hash = uint256S("0x0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8");
        consensus.BIP65Height = 581885; // 00000000007f6655f22f98e72ed80d8b06dc761d5da09df0fa1dc4be4f861eb6
        consensus.BIP66Height = 330776; // 000000002104c8c45e99a8853285a3b592602a3ccde2b832481da85e9e4ba182
        consensus.powLimit = uint256S("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = false;
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016; // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 1456790400; // March 1st, 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 1493596800; // May 1st, 2017

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 1462060800; // May 1st 2016
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 1493596800; // May 1st 2017

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00000000000000000000000000000000000000000000007dbe94253893cbd463");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x0000000000000037a8cd3e06cd5edbfe9dd1dbcc5dacab279376ef7cfc2b4c75"); //1354312

        pchMessageStart[0] = 0x0b;
        pchMessageStart[1] = 0x11;
        pchMessageStart[2] = 0x09;
        pchMessageStart[3] = 0x07;
        nDefaultPort = 18333;
        nPruneAfterHeight = 1000;


        genesis = CreateGenesisBlock(1296688602, 414098458, 0x1d00ffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        //assert(consensus.hashGenesisBlock == uint256S("0x000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943"));
        //assert(genesis.hashMerkleRoot == uint256S("0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"));
        // -- by eac
        printf("test:consensus.hashGenesisBlock: %s\n", consensus.hashGenesisBlock.ToString().c_str());
        assert(consensus.hashGenesisBlock == uint256S("0x83363991800fcdcb3ac60105cbd724a96823c5191bbc721735c82f7e2fd39d0a"));
        assert(genesis.hashMerkleRoot == uint256S("0xdd8cdfa6c78c83b03e3583d8e2e3ee8739393876e725685a5b341a182cf00b04"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        vSeeds.emplace_back("testnet-seed.bitcoin.jonasschnelli.ch");
        vSeeds.emplace_back("seed.tbtc.petertodd.org");
        vSeeds.emplace_back("seed.testnet.bitcoin.sprovoost.nl");
        vSeeds.emplace_back("testnet-seed.bluematt.me"); // Just a static list of stable node(s), only supports x9

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "tb";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;


        checkpointData = {
            {
                {546, uint256S("000000002a936ca763904c3c35fce2f3556c559c0214345d31b1bcebf76acb70")},
            }
        };

        chainTxData = ChainTxData{
            // Data from rpc: getchaintxstats 4096 0000000000000037a8cd3e06cd5edbfe9dd1dbcc5dacab279376ef7cfc2b4c75
            /* nTime    */ 1531929919,
            /* nTxCount */ 19438708,
            /* dTxRate  */ 0.626
        };

        /* enable fallback fee on testnet */
        m_fallback_fee_enabled = true;
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    explicit CRegTestParams(const ArgsManager& args) {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP16Exception = uint256();
        consensus.BIP34Height = 100000000; // BIP34 has not activated on regtest (far in the future so block v1 are not rejected in tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1351; // BIP65 activated on regtest (Used in rpc activation tests)
        consensus.BIP66Height = 1251; // BIP66 activated on regtest (Used in rpc activation tests)
        consensus.powLimit = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        nDefaultPort = 18444;
        nPruneAfterHeight = 1000;

        UpdateVersionBitsParametersFromArgs(args);

        genesis = CreateGenesisBlock(1296688602, 2, 0x207fffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        //assert(consensus.hashGenesisBlock == uint256S("0x0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"));
        //assert(genesis.hashMerkleRoot == uint256S("0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"));

        // -- by eac
        printf("test:consensus.hashGenesisBlock: %s\n", consensus.hashGenesisBlock.ToString().c_str());
        assert(consensus.hashGenesisBlock == uint256S("0x56b9812bdb698df52e3554531db8bbfefe9ec3884bf953acfbbdbdfe7bfb482d"));
        assert(genesis.hashMerkleRoot == uint256S("0xdd8cdfa6c78c83b03e3583d8e2e3ee8739393876e725685a5b341a182cf00b04"));


        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = {
            {
                {0, uint256S("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")},
            }
        };

        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "bcrt";

        /* enable fallback fee on regtest */
        m_fallback_fee_enabled = true;
    }

    /**
     * Allows modifying the Version Bits regtest parameters.
     */
    void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
    {
        consensus.vDeployments[d].nStartTime = nStartTime;
        consensus.vDeployments[d].nTimeout = nTimeout;
    }
    void UpdateVersionBitsParametersFromArgs(const ArgsManager& args);
};

void CRegTestParams::UpdateVersionBitsParametersFromArgs(const ArgsManager& args)
{
    if (!args.IsArgSet("-vbparams")) return;

    for (const std::string& strDeployment : args.GetArgs("-vbparams")) {
        std::vector<std::string> vDeploymentParams;
        boost::split(vDeploymentParams, strDeployment, boost::is_any_of(":"));
        if (vDeploymentParams.size() != 3) {
            throw std::runtime_error("Version bits parameters malformed, expecting deployment:start:end");
        }
        int64_t nStartTime, nTimeout;
        if (!ParseInt64(vDeploymentParams[1], &nStartTime)) {
            throw std::runtime_error(strprintf("Invalid nStartTime (%s)", vDeploymentParams[1]));
        }
        if (!ParseInt64(vDeploymentParams[2], &nTimeout)) {
            throw std::runtime_error(strprintf("Invalid nTimeout (%s)", vDeploymentParams[2]));
        }
        bool found = false;
        for (int j=0; j < (int)Consensus::MAX_VERSION_BITS_DEPLOYMENTS; ++j) {
            if (vDeploymentParams[0] == VersionBitsDeploymentInfo[j].name) {
                UpdateVersionBitsParameters(Consensus::DeploymentPos(j), nStartTime, nTimeout);
                found = true;
                LogPrintf("Setting version bits activation parameters for %s to start=%ld, timeout=%ld\n", vDeploymentParams[0], nStartTime, nTimeout);
                break;
            }
        }
        if (!found) {
            throw std::runtime_error(strprintf("Invalid deployment (%s)", vDeploymentParams[0]));
        }
    }
}

static std::unique_ptr<const CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<const CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams(gArgs));
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}
