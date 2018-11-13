// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2015 The Dash developers
// Copyright (c) 2015-2017 The PIVX developers
// Copyright (c) 2018 The Flexinodes developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "chainparams.h"

#include "random.h"
#include "util.h"
#include "utilstrencodings.h"
#include "bignum.h"
#include <assert.h>

#include <boost/assign/list_of.hpp>


using namespace std;
using namespace boost::assign;

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

#include "chainparamsseeds.h"

/**
 * Main network
 */

//! Convert the pnSeeds6 array into usable address objects.
static void convertSeed6(std::vector<CAddress>& vSeedsOut, const SeedSpec6* data, unsigned int count)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const int64_t nOneWeek = 7 * 24 * 60 * 60;
    for (unsigned int i = 0; i < count; i++) {
        struct in6_addr ip;
        memcpy(&ip, data[i].addr, sizeof(ip));
        CAddress addr(CService(ip, data[i].port));
        addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

//   What makes a good checkpoint block?
// + Is surrounded by blocks with reasonable timestamps
//   (no blocks before with a timestamp after, none after with
//    timestamp before)
// + Contains no strange transactions

static Checkpoints::MapCheckpoints mapCheckpoints =
    boost::assign::map_list_of(0, uint256("0x00000711a403866ce72d5c3633b93a0269495f34a091a1507bd04cdb71abafe1"))
    (1, uint256("00000362887d306e6e86e1be49d6e9c6ed6f66892277474e0582854bb6cf61c9"))
    (100, uint256("000000cbc9f9b563b7d64a66a21001a7b562c08e7b7cbf31f1e5a67709f0a3a4"))
    (1000, uint256("a3a448df4943418e89ef3957d434fc0f20732d86c027435693100a282c49fba2"))
    (99973, uint256("56d7dfff4adaeac1343767893b179b498a7151ecdd08274647c393b8307d489f"))
    ;
static const Checkpoints::CCheckpointData data = {
    &mapCheckpoints,
    1540104011, // * UNIX timestamp of last checkpoint block
    168028,    // * total number of transactions between genesis and last checkpoint
                //   (the tx=... number in the SetBestChain debug.log lines)
    720        // * estimated number of transactions per day after checkpoint
};

static Checkpoints::MapCheckpoints mapCheckpointsTestnet =
    boost::assign::map_list_of(0, uint256("0x"));
static const Checkpoints::CCheckpointData dataTestnet = {
    &mapCheckpointsTestnet,
    0,
    0,
    0};

static Checkpoints::MapCheckpoints mapCheckpointsRegtest =
    boost::assign::map_list_of(0, uint256("0x"));
static const Checkpoints::CCheckpointData dataRegtest = {
    &mapCheckpointsRegtest,
    0,
    0,
    0};

class CMainParams : public CChainParams
{
public:
    CMainParams()
    {
        networkID = CBaseChainParams::MAIN;
        strNetworkID = "main";
        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 4-byte int at any alignment.
         */
        pchMessageStart[0] = 0x64;
        pchMessageStart[1] = 0x75;
        pchMessageStart[2] = 0x29;
        pchMessageStart[3] = 0x22;
        vAlertPubKey = ParseHex("04266db20be5c52b94818e2e41c9def7af38197280c65e813f682adf2ed501ac186022562dbdf2ce3204d07432660fb61ecad8e78b6b8d39c568fb892db8ecb736");
        nDefaultPort = 25793;
        bnProofOfWorkLimit = ~uint256(0) >> 20;
        bnProofOfStakeLimit = ~uint256(0) >> 16;
        nSubsidyHalvingInterval = 262800;
        nMaxReorganizationDepth = 30000;
        nEnforceBlockUpgradeMajority = 750;
        nRejectBlockOutdatedMajority = 950;
        nToCheckBlockUpgradeMajority = 1000;
        nMinerThreads = 0;
        nTargetTimespan = 5 * 60;
        nTargetSpacing = 2 * 60;
        nLastPOWBlock = 0;
        nMaturity = 10;
        nMasternodeCountDrift = 20;
	    nMasternodeColleteralLimxDev = 4000; //Params().MasternodeColleteralLimxDev()
        nModifierUpdateBlock = 1; // we use the version 2 for dmd
        nMaxMoneyOut = 10000000000 * COIN;
        nMinMnCollateral = 10000 * COIN;
        nMaxMnCollateral = 2600000 * COIN;

        const char* pszTimestamp = "NyTimes.com 15th June 2018 - U.S. Imposes China Tariffs, Escalating Trade Fight.";
        CMutableTransaction txNew;
        txNew.vin.resize(1);
        txNew.vout.resize(1);
        txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew.vout[0].nValue = 0 * COIN;
        txNew.vout[0].scriptPubKey = CScript() << ParseHex("04e928b57880e492fdd2f0cdfd45b52b078a32a5282b4784202ac53b1299837e271f780192a8b014d33b51a6f8bbfc4cfaa3385829452bec7b77bf2f8f97520526") << OP_CHECKSIG;
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime = 1529089192;
        genesis.nBits = 0x1e0ffff0;
        genesis.nNonce = 27257850;

        uint256 hashTarget = CBigNum().SetCompact(genesis.nBits).getuint256();
        while (genesis.GetHash() > hashTarget)
        {
            ++genesis.nNonce;
            if (genesis.nNonce == 0)
            {
                printf("NONCE WRAPPED, incrementing time");
                ++genesis.nTime;
            }
			if (genesis.nNonce % 10000 == 0)
			{
				printf("nonce %08u: hash = %s \n", genesis.nNonce, genesis.GetHash().ToString().c_str());
			}
        }
		
        hashGenesisBlock = genesis.GetHash();
        /*printf("MN nNonce %u\n", genesis.nNonce);
	    printf("MN hashGenesisBlock %s\n", hashGenesisBlock.ToString().c_str());
	    printf("MN hashMerkleRoot %s\n", genesis.hashMerkleRoot.ToString().c_str());
        printf("MN nTime %u\n", genesis.nTime); */
        assert(hashGenesisBlock == uint256("0x00000711a403866ce72d5c3633b93a0269495f34a091a1507bd04cdb71abafe1"));
        assert(genesis.hashMerkleRoot == uint256("0x58e6ef05a528902e903b261900d95e314d2412bf1276e6fe80625a9d0e20835a"));
        
        vFixedSeeds.clear();
        vSeeds.clear();

        vSeeds.push_back(CDNSSeedData("flexinodes-seednode-1.dynu.net:25793", "flexinodes-seednode-1.dynu.net:25793"));
        vSeeds.push_back(CDNSSeedData("flexinodes-seednode-1.dynu.net:25794", "flexinodes-seednode-1.dynu.net:25794"));
        vSeeds.push_back(CDNSSeedData("flexinodes-seednode-1.dynu.net:25795", "flexinodes-seednode-1.dynu.net:25795"));
        vSeeds.push_back(CDNSSeedData("flexinodes-seednode-2.dynu.net:25793", "flexinodes-seednode-2.dynu.net:25793"));
        vSeeds.push_back(CDNSSeedData("flexinodes-seednode-2.dynu.net:25794", "flexinodes-seednode-2.dynu.net:25794"));



        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 35);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 16);
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 193);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x88)(0xB2)(0x1E).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x88)(0xAD)(0xE4).convert_to_container<std::vector<unsigned char> >();
        // 	BIP44 coin type is from https://github.com/satoshilabs/slips/blob/master/slip-0044.md 109 	0x8000006d
        base58Prefixes[EXT_COIN_TYPE] = boost::assign::list_of(0x80)(0x00)(0x00)(0x6d).convert_to_container<std::vector<unsigned char> >();

        //convertSeed6(vFixedSeeds, pnSeed6_main, ARRAYLEN(pnSeed6_main));

        fRequireRPCPassword = true;
        fMiningRequiresPeers = true;
        fAllowMinDifficultyBlocks = false;
        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;
        fSkipProofOfWorkCheck = false;
        fTestnetToBeDeprecatedFieldRPC = false;
        fHeadersFirstSyncingActive = false;

        nPoolMaxTransactions = 3;
        strSporkKey = "043635a66ad599a93face6d23f09c96d2a17d18771ab70538862232aaacb5fe07087e016e5cd935478308e45cc533b4a98739d84a0aa8e7017633347909280b1a9";
        strDarksendPoolDummyAddress = "AcmpqXViWUXNroqVNYRdKjKrFM6PNa1oTM";
        nStartMasternodePayments = 1523967685; 
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return data;
    }
};
static CMainParams mainParams;

/**
 * Testnet (v3)
 */
class CTestNetParams : public CMainParams
{
public:
    CTestNetParams()
    {
        networkID = CBaseChainParams::TESTNET;
        strNetworkID = "test";
        pchMessageStart[0] = 0x64;
        pchMessageStart[1] = 0x75;
        pchMessageStart[2] = 0x29;
        pchMessageStart[3] = 0x22;
        vAlertPubKey = ParseHex("0441286086a0871308bf36091edb18d95bbe9b895abe14ec9b684b5255028ec644bacdbddb98a522a6bcd7ab8e7d3582d7a5b9bf59c427f7eabce447b5ba6de25f");
        nDefaultPort = 25794;
        nEnforceBlockUpgradeMajority = 51;
        nRejectBlockOutdatedMajority = 75;
        nToCheckBlockUpgradeMajority = 100;
        nMinerThreads = 0;
        nTargetTimespan = 1 * 60;
        nTargetSpacing = 1 * 60;
        nLastPOWBlock = 200;
        nSubsidyHalvingInterval = 262800;
        nMaturity = 15;
        nModifierUpdateBlock = 51197; //approx Mon, 30 Apr 2018 04:00:00 GMT
        nMaxMoneyOut = 10000000000 * COIN;

        //! Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nTime = 1529089192;
        genesis.nBits = 0x1e0ffff0;
        genesis.nNonce = 27257850;

        hashGenesisBlock = genesis.GetHash();
        uint256 hashTarget = CBigNum().SetCompact(genesis.nBits).getuint256();
        while (genesis.GetHash() > hashTarget)
        {
            ++genesis.nNonce;
            if (genesis.nNonce == 0)
            {
                printf("NONCE WRAPPED, incrementing time");
                ++genesis.nTime;
            }
			if (genesis.nNonce % 10000 == 0)
			{
				printf("nonce %08u: hash = %s \n", genesis.nNonce, genesis.GetHash().ToString().c_str());
			}
        }
        /*printf("TN nNonce %u\n", genesis.nNonce);
	    printf("TN hashGenesisBlock %s\n", hashGenesisBlock.ToString().c_str());
	    printf("TN hashMerkleRoot %s\n", genesis.hashMerkleRoot.ToString().c_str());
        printf("TN nTime %u\n", genesis.nTime);*/
        assert(hashGenesisBlock == uint256("0x00000711a403866ce72d5c3633b93a0269495f34a091a1507bd04cdb71abafe1"));

        vFixedSeeds.clear();
        vSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 83);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 18);
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 193);
        // Testnet Flexinodes BIP32 pubkeys start with 'DRKV'
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x3a)(0x80)(0x61)(0xa0).convert_to_container<std::vector<unsigned char> >();
        // Testnet Flexinodes BIP32 prvkeys start with 'DRKP'
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x3a)(0x80)(0x58)(0x37).convert_to_container<std::vector<unsigned char> >();
        // Testnet Flexinodes BIP44 coin type is '1' (All coin's testnet default)
        base58Prefixes[EXT_COIN_TYPE] = boost::assign::list_of(0x80)(0x00)(0x00)(0x01).convert_to_container<std::vector<unsigned char> >();

        convertSeed6(vFixedSeeds, pnSeed6_test, ARRAYLEN(pnSeed6_test));

        fRequireRPCPassword = true;
        fMiningRequiresPeers = true;
        fAllowMinDifficultyBlocks = true;
        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;
        fTestnetToBeDeprecatedFieldRPC = true;

        nPoolMaxTransactions = 2;
        strSporkKey = "04363509d5c65f5a9ca7ceedad4887007ae85469d249a6f566b788504ee5e105bcf1bbc515f49a7aac3bceb8864bb2ba84bebd92c66ff9022309e2bfbd5f70d11f";
        strDarksendPoolDummyAddress = "";
        nStartMasternodePayments = 1523967686;
    }
    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataTestnet;
    }
};
static CTestNetParams testNetParams;

/**
 * Regression test
 */
class CRegTestParams : public CTestNetParams
{
public:
    CRegTestParams()
    {
        networkID = CBaseChainParams::REGTEST;
        strNetworkID = "regtest";
        strNetworkID = "regtest";
        pchMessageStart[0] = 0x65;
        pchMessageStart[1] = 0x14;
        pchMessageStart[2] = 0x54;
        pchMessageStart[3] = 0x61;
        nSubsidyHalvingInterval = 150;
        nEnforceBlockUpgradeMajority = 750;
        nRejectBlockOutdatedMajority = 950;
        nToCheckBlockUpgradeMajority = 1000;
        nMinerThreads = 1;
        nTargetTimespan = 24 * 60 * 60;
        nTargetSpacing = 1 * 60;
        bnProofOfWorkLimit = ~uint256(0) >> 1;
        nSubsidyHalvingInterval = 262800;
        genesis.nTime = 1526435548;
        genesis.nBits = 0x207fffff;
        genesis.nNonce = 27257850;

        hashGenesisBlock = genesis.GetHash();
        uint256 hashTarget = CBigNum().SetCompact(genesis.nBits).getuint256();
        while (genesis.GetHash() > hashTarget)
        {
            ++genesis.nNonce;
            if (genesis.nNonce == 0)
            {
                printf("NONCE WRAPPED, incrementing time");
                ++genesis.nTime;
            }
			if (genesis.nNonce % 10000 == 0)
			{
				printf("nonce %08u: hash = %s \n", genesis.nNonce, genesis.GetHash().ToString().c_str());
			}
        }
        /*printf("RT nNonce %u\n", genesis.nNonce);
	    printf("RT hashGenesisBlock %s\n", hashGenesisBlock.ToString().c_str());
	    printf("RT hashMerkleRoot %s\n", genesis.hashMerkleRoot.ToString().c_str());
        printf("RT nTime %u\n", genesis.nTime);*/
		
        hashGenesisBlock = genesis.GetHash();
        nDefaultPort = 22988;
        assert(hashGenesisBlock == uint256("0x24904b56f3bb5bc48a4973cde58f7c16d8a4a9e78195061c5511b262e35d4a2e"));

        vFixedSeeds.clear(); //! Testnet mode doesn't have any fixed seeds.
        vSeeds.clear();      //! Testnet mode doesn't have any DNS seeds.

        fRequireRPCPassword = false;
        fMiningRequiresPeers = false;
        fAllowMinDifficultyBlocks = true;
        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;
        fTestnetToBeDeprecatedFieldRPC = false;
    }
    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        return dataRegtest;
    }
};
static CRegTestParams regTestParams;

/**
 * Unit test
 */
class CUnitTestParams : public CMainParams, public CModifiableParams
{
public:
    CUnitTestParams()
    {
        networkID = CBaseChainParams::UNITTEST;
        strNetworkID = "unittest";
        nDefaultPort = 22888;
        vFixedSeeds.clear(); //! Unit test mode doesn't have any fixed seeds.
        vSeeds.clear();      //! Unit test mode doesn't have any DNS seeds.

        fRequireRPCPassword = false;
        fMiningRequiresPeers = false;
        fDefaultConsistencyChecks = true;
        fAllowMinDifficultyBlocks = false;
        fMineBlocksOnDemand = true;
    }

    const Checkpoints::CCheckpointData& Checkpoints() const
    {
        // UnitTest share the same checkpoints as MAIN
        return data;
    }

    //! Published setters to allow changing values in unit test cases
    virtual void setSubsidyHalvingInterval(int anSubsidyHalvingInterval) { nSubsidyHalvingInterval = anSubsidyHalvingInterval; }
    virtual void setEnforceBlockUpgradeMajority(int anEnforceBlockUpgradeMajority) { nEnforceBlockUpgradeMajority = anEnforceBlockUpgradeMajority; }
    virtual void setRejectBlockOutdatedMajority(int anRejectBlockOutdatedMajority) { nRejectBlockOutdatedMajority = anRejectBlockOutdatedMajority; }
    virtual void setToCheckBlockUpgradeMajority(int anToCheckBlockUpgradeMajority) { nToCheckBlockUpgradeMajority = anToCheckBlockUpgradeMajority; }
    virtual void setDefaultConsistencyChecks(bool afDefaultConsistencyChecks) { fDefaultConsistencyChecks = afDefaultConsistencyChecks; }
    virtual void setAllowMinDifficultyBlocks(bool afAllowMinDifficultyBlocks) { fAllowMinDifficultyBlocks = afAllowMinDifficultyBlocks; }
    virtual void setSkipProofOfWorkCheck(bool afSkipProofOfWorkCheck) { fSkipProofOfWorkCheck = afSkipProofOfWorkCheck; }
};
static CUnitTestParams unitTestParams;


static CChainParams* pCurrentParams = 0;

CModifiableParams* ModifiableParams()
{
    assert(pCurrentParams);
    assert(pCurrentParams == &unitTestParams);
    return (CModifiableParams*)&unitTestParams;
}

const CChainParams& Params()
{
    assert(pCurrentParams);
    return *pCurrentParams;
}

CChainParams& Params(CBaseChainParams::Network network)
{
    switch (network) {
    case CBaseChainParams::MAIN:
        return mainParams;
    case CBaseChainParams::TESTNET:
        return testNetParams;
    case CBaseChainParams::REGTEST:
        return regTestParams;
    case CBaseChainParams::UNITTEST:
        return unitTestParams;
    default:
        assert(false && "Unimplemented network");
        return mainParams;
    }
}

void SelectParams(CBaseChainParams::Network network)
{
    SelectBaseParams(network);
    pCurrentParams = &Params(network);
}

bool SelectParamsFromCommandLine()
{
    CBaseChainParams::Network network = NetworkIdFromCommandLine();
    if (network == CBaseChainParams::MAX_NETWORK_TYPES)
        return false;

    SelectParams(network);
    return true;
}
