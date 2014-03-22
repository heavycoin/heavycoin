// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "alert.h"
#include "checkpoints.h"
#include "db.h"
#include "txdb.h"
#include "net.h"
#include "init.h"
#include "ui_interface.h"
#include "checkqueue.h"
#include "bitcoinrpc.h"

#include <float.h>
#include <boost/algorithm/string/replace.hpp>
#include <boost/filesystem.hpp>
#include <boost/filesystem/fstream.hpp>

using namespace std;
using namespace boost;

//
// Global state
//
bool bGenerate = true;
int nGenerateThreads = 1;

CCriticalSection cs_setpwalletRegistered;
set<CWallet*> setpwalletRegistered;

CCriticalSection cs_main;

CTxMemPool mempool;
unsigned int nTransactionsUpdated = 0;

map<uint256, CBlockIndex*> mapBlockIndex;
uint256 hashGenesisBlock("0x000010fea87dcd9ebd30af1105a16cd438217a1a6d0eff8d589d5d81e7fbcb0d");
static CBigNum bnProofOfWorkLimit(~uint256(0) >> 16); /* Lower difficulty for HEFTY1 */
CBlockIndex* pindexGenesisBlock = NULL;
int nBestHeight = -1;
uint256 nBestChainWork = 0;
uint256 nBestInvalidWork = 0;
uint256 hashBestChain = 0;
CBlockIndex* pindexBest = NULL;
set<CBlockIndex*, CBlockIndexWorkComparator> setBlockIndexValid; // may contain all CBlockIndex*'s that have validness >=BLOCK_VALID_TRANSACTIONS, and must contain those who aren't failed
int64 nTimeBestReceived = 0;
int nScriptCheckThreads = 0;
bool fImporting = false;
bool fReindex = false;
bool fBenchmark = false;
bool fTxIndex = false;
unsigned int nCoinCacheSize = 5000;

/** Fees smaller than this (in satoshi) are considered zero fee (for transaction creation) */
int64 CTransaction::nMinTxFee = 10000;  // Override with -mintxfee
/** Fees smaller than this (in satoshi) are considered zero fee (for relaying) */
int64 CTransaction::nMinRelayTxFee = 10000;

CMedianFilter<int> cPeerBlockCounts(8, 0); // Amount of blocks that other nodes claim to have

map<uint256, CBlock*> mapOrphanBlocks;
multimap<uint256, CBlock*> mapOrphanBlocksByPrev;

map<uint256, CDataStream*> mapOrphanTransactions;
map<uint256, map<uint256, CDataStream*> > mapOrphanTransactionsByPrev;

// Constant stuff for coinbase transactions we create:
CScript COINBASE_FLAGS;

const string strMessageMagic = "Bitcoin Signed Message:\n";

double dHashesPerSec = 0.0;
int64 nHPSTimerStart = 0;

// Settings
int64 nTransactionFee = 0;

//////////////////////////////////////////////////////////////////////////////
//
// dispatching functions
//

// These functions dispatch to one or all registered wallets

void RegisterWallet(CWallet* pwalletIn)
{
    {
        LOCK(cs_setpwalletRegistered);
        setpwalletRegistered.insert(pwalletIn);
    }
}

void UnregisterWallet(CWallet* pwalletIn)
{
    {
        LOCK(cs_setpwalletRegistered);
        setpwalletRegistered.erase(pwalletIn);
    }
}

// get the wallet transaction with the given hash (if it exists)
bool static GetTransaction(const uint256& hashTx, CWalletTx& wtx)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        if (pwallet->GetTransaction(hashTx,wtx))
            return true;
    return false;
}

// erases transaction with the given hash from all wallets
void static EraseFromWallets(uint256 hash)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->EraseFromWallet(hash);
}

// make sure all wallets know about the given transaction, in the given block
void SyncWithWallets(const uint256 &hash, const CTransaction& tx, const CBlock* pblock, bool fUpdate)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->AddToWalletIfInvolvingMe(hash, tx, pblock, fUpdate);
}

// notify wallets about a new best chain
void static SetBestChain(const CBlockLocator& loc)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->SetBestChain(loc);
}

// notify wallets about an updated transaction
void static UpdatedTransaction(const uint256& hashTx)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->UpdatedTransaction(hashTx);
}

// dump all wallets
void static PrintWallets(const CBlock& block)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->PrintWallet(block);
}

// notify wallets about an incoming inventory (for request counts)
void static Inventory(const uint256& hash)
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->Inventory(hash);
}

// ask wallets to resend their transactions
void static ResendWalletTransactions()
{
    BOOST_FOREACH(CWallet* pwallet, setpwalletRegistered)
        pwallet->ResendWalletTransactions();
}







//////////////////////////////////////////////////////////////////////////////
//
// CCoinsView implementations
//

bool CCoinsView::GetCoins(const uint256 &txid, CCoins &coins) { return false; }
bool CCoinsView::SetCoins(const uint256 &txid, const CCoins &coins) { return false; }
bool CCoinsView::HaveCoins(const uint256 &txid) { return false; }
CBlockIndex *CCoinsView::GetBestBlock() { return NULL; }
bool CCoinsView::SetBestBlock(CBlockIndex *pindex) { return false; }
bool CCoinsView::BatchWrite(const std::map<uint256, CCoins> &mapCoins, CBlockIndex *pindex) { return false; }
bool CCoinsView::GetStats(CCoinsStats &stats) { return false; }


CCoinsViewBacked::CCoinsViewBacked(CCoinsView &viewIn) : base(&viewIn) { }
bool CCoinsViewBacked::GetCoins(const uint256 &txid, CCoins &coins) { return base->GetCoins(txid, coins); }
bool CCoinsViewBacked::SetCoins(const uint256 &txid, const CCoins &coins) { return base->SetCoins(txid, coins); }
bool CCoinsViewBacked::HaveCoins(const uint256 &txid) { return base->HaveCoins(txid); }
CBlockIndex *CCoinsViewBacked::GetBestBlock() { return base->GetBestBlock(); }
bool CCoinsViewBacked::SetBestBlock(CBlockIndex *pindex) { return base->SetBestBlock(pindex); }
void CCoinsViewBacked::SetBackend(CCoinsView &viewIn) { base = &viewIn; }
bool CCoinsViewBacked::BatchWrite(const std::map<uint256, CCoins> &mapCoins, CBlockIndex *pindex) { return base->BatchWrite(mapCoins, pindex); }
bool CCoinsViewBacked::GetStats(CCoinsStats &stats) { return base->GetStats(stats); }

CCoinsViewCache::CCoinsViewCache(CCoinsView &baseIn, bool fDummy) : CCoinsViewBacked(baseIn), pindexTip(NULL) { }

bool CCoinsViewCache::GetCoins(const uint256 &txid, CCoins &coins) {
    if (cacheCoins.count(txid)) {
        coins = cacheCoins[txid];
        return true;
    }
    if (base->GetCoins(txid, coins)) {
        cacheCoins[txid] = coins;
        return true;
    }
    return false;
}

std::map<uint256,CCoins>::iterator CCoinsViewCache::FetchCoins(const uint256 &txid) {
    std::map<uint256,CCoins>::iterator it = cacheCoins.lower_bound(txid);
    if (it != cacheCoins.end() && it->first == txid)
        return it;
    CCoins tmp;
    if (!base->GetCoins(txid,tmp))
        return cacheCoins.end();
    std::map<uint256,CCoins>::iterator ret = cacheCoins.insert(it, std::make_pair(txid, CCoins()));
    tmp.swap(ret->second);
    return ret;
}

CCoins &CCoinsViewCache::GetCoins(const uint256 &txid) {
    std::map<uint256,CCoins>::iterator it = FetchCoins(txid);
    assert(it != cacheCoins.end());
    return it->second;
}

bool CCoinsViewCache::SetCoins(const uint256 &txid, const CCoins &coins) {
    cacheCoins[txid] = coins;
    return true;
}

bool CCoinsViewCache::HaveCoins(const uint256 &txid) {
    return FetchCoins(txid) != cacheCoins.end();
}

CBlockIndex *CCoinsViewCache::GetBestBlock() {
    if (pindexTip == NULL)
        pindexTip = base->GetBestBlock();
    return pindexTip;
}

bool CCoinsViewCache::SetBestBlock(CBlockIndex *pindex) {
    pindexTip = pindex;
    return true;
}

bool CCoinsViewCache::BatchWrite(const std::map<uint256, CCoins> &mapCoins, CBlockIndex *pindex) {
    for (std::map<uint256, CCoins>::const_iterator it = mapCoins.begin(); it != mapCoins.end(); it++)
        cacheCoins[it->first] = it->second;
    pindexTip = pindex;
    return true;
}

bool CCoinsViewCache::Flush() {
    bool fOk = base->BatchWrite(cacheCoins, pindexTip);
    if (fOk)
        cacheCoins.clear();
    return fOk;
}

unsigned int CCoinsViewCache::GetCacheSize() {
    return cacheCoins.size();
}

/** CCoinsView that brings transactions from a memorypool into view.
    It does not check for spendings by memory pool transactions. */
CCoinsViewMemPool::CCoinsViewMemPool(CCoinsView &baseIn, CTxMemPool &mempoolIn) : CCoinsViewBacked(baseIn), mempool(mempoolIn) { }

bool CCoinsViewMemPool::GetCoins(const uint256 &txid, CCoins &coins) {
    if (base->GetCoins(txid, coins))
        return true;
    if (mempool.exists(txid)) {
        const CTransaction &tx = mempool.lookup(txid);
        coins = CCoins(tx, MEMPOOL_HEIGHT);
        return true;
    }
    return false;
}

bool CCoinsViewMemPool::HaveCoins(const uint256 &txid) {
    return mempool.exists(txid) || base->HaveCoins(txid);
}

CCoinsViewCache *pcoinsTip = NULL;
CBlockTreeDB *pblocktree = NULL;

//////////////////////////////////////////////////////////////////////////////
//
// mapOrphanTransactions
//

bool AddOrphanTx(const CDataStream& vMsg)
{
    CTransaction tx;
    CDataStream(vMsg) >> tx;
    uint256 hash = tx.GetHash();
    if (mapOrphanTransactions.count(hash))
        return false;

    CDataStream* pvMsg = new CDataStream(vMsg);

    // Ignore big transactions, to avoid a
    // send-big-orphans memory exhaustion attack. If a peer has a legitimate
    // large transaction with a missing parent then we assume
    // it will rebroadcast it later, after the parent transaction(s)
    // have been mined or received.
    // 10,000 orphans, each of which is at most 5,000 bytes big is
    // at most 500 megabytes of orphans:
    if (pvMsg->size() > 5000)
    {
        printf("ignoring large orphan tx (size: %"PRIszu", hash: %s)\n", pvMsg->size(), hash.ToString().c_str());
        delete pvMsg;
        return false;
    }

    mapOrphanTransactions[hash] = pvMsg;
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
        mapOrphanTransactionsByPrev[txin.prevout.hash].insert(make_pair(hash, pvMsg));

    printf("stored orphan tx %s (mapsz %"PRIszu")\n", hash.ToString().c_str(),
        mapOrphanTransactions.size());
    return true;
}

void static EraseOrphanTx(uint256 hash)
{
    if (!mapOrphanTransactions.count(hash))
        return;
    const CDataStream* pvMsg = mapOrphanTransactions[hash];
    CTransaction tx;
    CDataStream(*pvMsg) >> tx;
    BOOST_FOREACH(const CTxIn& txin, tx.vin)
    {
        mapOrphanTransactionsByPrev[txin.prevout.hash].erase(hash);
        if (mapOrphanTransactionsByPrev[txin.prevout.hash].empty())
            mapOrphanTransactionsByPrev.erase(txin.prevout.hash);
    }
    delete pvMsg;
    mapOrphanTransactions.erase(hash);
}

unsigned int LimitOrphanTxSize(unsigned int nMaxOrphans)
{
    unsigned int nEvicted = 0;
    while (mapOrphanTransactions.size() > nMaxOrphans)
    {
        // Evict a random orphan:
        uint256 randomhash = GetRandHash();
        map<uint256, CDataStream*>::iterator it = mapOrphanTransactions.lower_bound(randomhash);
        if (it == mapOrphanTransactions.end())
            it = mapOrphanTransactions.begin();
        EraseOrphanTx(it->first);
        ++nEvicted;
    }
    return nEvicted;
}







//////////////////////////////////////////////////////////////////////////////
//
// CTransaction / CTxOut
//

bool CTxOut::IsDust() const
{
    // "Dust" is defined in terms of CTransaction::nMinRelayTxFee,
    // which has units satoshis-per-kilobyte.
    // If you'd pay more than 1/3 in fees
    // to spend something, then we consider it dust.
    // A typical txout is 33 bytes big, and will
    // need a CTxIn of at least 148 bytes to spend,
    // so dust is a txout less than 54 uBTC
    // (5430 satoshis) with default nMinRelayTxFee
    return ((nValue*1000)/(3*((int)GetSerializeSize(SER_DISK,0)+148)) < CTransaction::nMinRelayTxFee);
}

bool CTransaction::IsStandard() const
{
    if (nVersion > CTransaction::CURRENT_VERSION)
        return false;

    if (!IsFinal())
        return false;

    // Extremely large transactions with lots of inputs can cost the network
    // almost as much to process as they cost the sender in fees, because
    // computing signature hashes is O(ninputs*txsize). Limiting transactions
    // to MAX_STANDARD_TX_SIZE mitigates CPU exhaustion attacks.
    unsigned int sz = this->GetSerializeSize(SER_NETWORK, CTransaction::CURRENT_VERSION);
    if (sz >= MAX_STANDARD_TX_SIZE)
        return false;

    BOOST_FOREACH(const CTxIn& txin, vin)
    {
        // Biggest 'standard' txin is a 3-signature 3-of-3 CHECKMULTISIG
        // pay-to-script-hash, which is 3 ~80-byte signatures, 3
        // ~65-byte public keys, plus a few script ops.
        if (txin.scriptSig.size() > 500)
            return false;
        if (!txin.scriptSig.IsPushOnly())
            return false;
    }
    BOOST_FOREACH(const CTxOut& txout, vout) {
        if (!::IsStandard(txout.scriptPubKey))
            return false;
        if (txout.IsDust())
            return false;
    }
    return true;
}

//
// Check transaction inputs, and make sure any
// pay-to-script-hash transactions are evaluating IsStandard scripts
//
// Why bother? To avoid denial-of-service attacks; an attacker
// can submit a standard HASH... OP_EQUAL transaction,
// which will get accepted into blocks. The redemption
// script can be anything; an attacker could use a very
// expensive-to-check-upon-redemption script like:
//   DUP CHECKSIG DROP ... repeated 100 times... OP_1
//
bool CTransaction::AreInputsStandard(CCoinsViewCache& mapInputs) const
{
    if (IsCoinBase())
        return true; // Coinbases don't use vin normally

    for (unsigned int i = 0; i < vin.size(); i++)
    {
        const CTxOut& prev = GetOutputFor(vin[i], mapInputs);

        vector<vector<unsigned char> > vSolutions;
        txnouttype whichType;
        // get the scriptPubKey corresponding to this input:
        const CScript& prevScript = prev.scriptPubKey;
        if (!Solver(prevScript, whichType, vSolutions))
            return false;
        int nArgsExpected = ScriptSigArgsExpected(whichType, vSolutions);
        if (nArgsExpected < 0)
            return false;

        // Transactions with extra stuff in their scriptSigs are
        // non-standard. Note that this EvalScript() call will
        // be quick, because if there are any operations
        // beside "push data" in the scriptSig the
        // IsStandard() call returns false
        vector<vector<unsigned char> > stack;
        if (!EvalScript(stack, vin[i].scriptSig, *this, i, false, 0))
            return false;

        if (whichType == TX_SCRIPTHASH)
        {
            if (stack.empty())
                return false;
            CScript subscript(stack.back().begin(), stack.back().end());
            vector<vector<unsigned char> > vSolutions2;
            txnouttype whichType2;
            if (!Solver(subscript, whichType2, vSolutions2))
                return false;
            if (whichType2 == TX_SCRIPTHASH)
                return false;

            int tmpExpected;
            tmpExpected = ScriptSigArgsExpected(whichType2, vSolutions2);
            if (tmpExpected < 0)
                return false;
            nArgsExpected += tmpExpected;
        }

        if (stack.size() != (unsigned int)nArgsExpected)
            return false;
    }

    return true;
}

unsigned int CTransaction::GetLegacySigOpCount() const
{
    unsigned int nSigOps = 0;
    BOOST_FOREACH(const CTxIn& txin, vin)
    {
        nSigOps += txin.scriptSig.GetSigOpCount(false);
    }
    BOOST_FOREACH(const CTxOut& txout, vout)
    {
        nSigOps += txout.scriptPubKey.GetSigOpCount(false);
    }
    return nSigOps;
}


int CMerkleTx::SetMerkleBranch(const CBlock* pblock)
{
    CBlock blockTmp;

    if (pblock == NULL) {
        CCoins coins;
        if (pcoinsTip->GetCoins(GetHash(), coins)) {
            CBlockIndex *pindex = FindBlockByHeight(coins.nHeight);
            if (pindex) {
                if (!blockTmp.ReadFromDisk(pindex))
                    return 0;
                pblock = &blockTmp;
            }
        }
    }

    if (pblock) {
        // Update the tx's hashBlock
        hashBlock = pblock->GetHash();

        // Locate the transaction
        for (nIndex = 0; nIndex < (int)pblock->vtx.size(); nIndex++)
            if (pblock->vtx[nIndex] == *(CTransaction*)this)
                break;
        if (nIndex == (int)pblock->vtx.size())
        {
            vMerkleBranch.clear();
            nIndex = -1;
            printf("ERROR: SetMerkleBranch() : couldn't find tx in block\n");
            return 0;
        }

        // Fill in merkle branch
        vMerkleBranch = pblock->GetMerkleBranch(nIndex);
    }

    // Is the tx in a block that's in the main chain
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi == mapBlockIndex.end())
        return 0;
    CBlockIndex* pindex = (*mi).second;
    if (!pindex || !pindex->IsInMainChain())
        return 0;

    return pindexBest->nHeight - pindex->nHeight + 1;
}







bool CTransaction::CheckTransaction(CValidationState &state) const
{
    // Basic checks that don't depend on any context
    if (vin.empty())
        return state.DoS(10, error("CTransaction::CheckTransaction() : vin empty"));
    if (vout.empty())
        return state.DoS(10, error("CTransaction::CheckTransaction() : vout empty"));
    // Size limits
    if (::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION) > MAX_BLOCK_SIZE)
        return state.DoS(100, error("CTransaction::CheckTransaction() : size limits failed"));

    // Check for negative or overflow output values
    int64 nValueOut = 0;
    BOOST_FOREACH(const CTxOut& txout, vout)
    {
        if (txout.nValue < 0)
            return state.DoS(100, error("CTransaction::CheckTransaction() : txout.nValue negative"));
        if (txout.nValue > nMaxSupply*COIN)
            return state.DoS(100, error("CTransaction::CheckTransaction() : txout.nValue too high"));
        nValueOut += txout.nValue;
        if (!MoneyRange(nValueOut))
            return state.DoS(100, error("CTransaction::CheckTransaction() : txout total out of range"));
    }

    // Check for duplicate inputs
    set<COutPoint> vInOutPoints;
    BOOST_FOREACH(const CTxIn& txin, vin)
    {
        if (vInOutPoints.count(txin.prevout))
            return state.DoS(100, error("CTransaction::CheckTransaction() : duplicate inputs"));
        vInOutPoints.insert(txin.prevout);
    }

    if (IsCoinBase())
    {
        if (vin[0].scriptSig.size() < 2 || vin[0].scriptSig.size() > 100)
            return state.DoS(100, error("CTransaction::CheckTransaction() : coinbase script size"));
    }
    else
    {
        BOOST_FOREACH(const CTxIn& txin, vin)
            if (txin.prevout.IsNull())
                return state.DoS(10, error("CTransaction::CheckTransaction() : prevout is null"));
    }

    return true;
}

int64 CTransaction::GetMinFee(unsigned int nBlockSize, bool fAllowFree,
                              enum GetMinFee_mode mode) const
{
    // Base fee is either nMinTxFee or nMinRelayTxFee
    int64 nBaseFee = (mode == GMF_RELAY) ? nMinRelayTxFee : nMinTxFee;

    unsigned int nBytes = ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION);
    unsigned int nNewBlockSize = nBlockSize + nBytes;
    int64 nMinFee = (1 + (int64)nBytes / 1000) * nBaseFee;

    if (fAllowFree)
    {
        if (nBlockSize == 1)
        {
            // Transactions under 10K are free
            // (about 4500 BTC if made of 50 BTC inputs)
            if (nBytes < 10000)
                nMinFee = 0;
        }
        else
        {
            // Free transaction area
            if (nNewBlockSize < 27000)
                nMinFee = 0;
        }
    }

    // To limit dust spam, require base fee if any output is less than 0.01
    if (nMinFee < nBaseFee)
    {
        BOOST_FOREACH(const CTxOut& txout, vout)
            if (txout.nValue < CENT)
                nMinFee = nBaseFee;
    }

    // Raise the price as the block approaches full
    if (nBlockSize != 1 && nNewBlockSize >= MAX_BLOCK_SIZE_GEN/2)
    {
        if (nNewBlockSize >= MAX_BLOCK_SIZE_GEN)
            return nMaxSupply*COIN;
        nMinFee *= MAX_BLOCK_SIZE_GEN / (MAX_BLOCK_SIZE_GEN - nNewBlockSize);
    }

    if (!MoneyRange(nMinFee))
        nMinFee = nMaxSupply*COIN;
    return nMinFee;
}

void CTxMemPool::pruneSpent(const uint256 &hashTx, CCoins &coins)
{
    LOCK(cs);

    std::map<COutPoint, CInPoint>::iterator it = mapNextTx.lower_bound(COutPoint(hashTx, 0));

    // iterate over all COutPoints in mapNextTx whose hash equals the provided hashTx
    while (it != mapNextTx.end() && it->first.hash == hashTx) {
        coins.Spend(it->first.n); // and remove those outputs from coins
        it++;
    }
}

bool CTxMemPool::accept(CValidationState &state, CTransaction &tx, bool fCheckInputs, bool fLimitFree,
                        bool* pfMissingInputs)
{
    if (pfMissingInputs)
        *pfMissingInputs = false;

    if (!tx.CheckTransaction(state))
        return error("CTxMemPool::accept() : CheckTransaction failed");

    // Coinbase is only valid in a block, not as a loose transaction
    if (tx.IsCoinBase())
        return state.DoS(100, error("CTxMemPool::accept() : coinbase as individual tx"));

    // To help v0.1.5 clients who would see it as a negative number
    if ((int64)tx.nLockTime > std::numeric_limits<int>::max())
        return error("CTxMemPool::accept() : not accepting nLockTime beyond 2038 yet");

    // Rather not work on nonstandard transactions (unless -testnet)
    if (!fTestNet && !tx.IsStandard())
        return error("CTxMemPool::accept() : nonstandard transaction type");

    // is it already in the memory pool?
    uint256 hash = tx.GetHash();
    {
        LOCK(cs);
        if (mapTx.count(hash))
            return false;
    }

    // Check for conflicts with in-memory transactions
    CTransaction* ptxOld = NULL;
    for (unsigned int i = 0; i < tx.vin.size(); i++)
    {
        COutPoint outpoint = tx.vin[i].prevout;
        if (mapNextTx.count(outpoint))
        {
            // Disable replacement feature for now
            return false;

            // Allow replacing with a newer version of the same transaction
            if (i != 0)
                return false;
            ptxOld = mapNextTx[outpoint].ptx;
            if (ptxOld->IsFinal())
                return false;
            if (!tx.IsNewerThan(*ptxOld))
                return false;
            for (unsigned int i = 0; i < tx.vin.size(); i++)
            {
                COutPoint outpoint = tx.vin[i].prevout;
                if (!mapNextTx.count(outpoint) || mapNextTx[outpoint].ptx != ptxOld)
                    return false;
            }
            break;
        }
    }

    if (fCheckInputs)
    {
        CCoinsView dummy;
        CCoinsViewCache view(dummy);

        {
        LOCK(cs);
        CCoinsViewMemPool viewMemPool(*pcoinsTip, *this);
        view.SetBackend(viewMemPool);

        // do we already have it?
        if (view.HaveCoins(hash))
            return false;

        // do all inputs exist?
        // Note that this does not check for the presence of actual outputs (see the next check for that),
        // only helps filling in pfMissingInputs (to determine missing vs spent).
        BOOST_FOREACH(const CTxIn txin, tx.vin) {
            if (!view.HaveCoins(txin.prevout.hash)) {
                if (pfMissingInputs)
                    *pfMissingInputs = true;
                return false;
            }
        }

        // are the actual inputs available?
        if (!tx.HaveInputs(view))
            return state.Invalid(error("CTxMemPool::accept() : inputs already spent"));

        // Bring the best block into scope
        view.GetBestBlock();

        // we have all inputs cached now, so switch back to dummy, so we don't need to keep lock on mempool
        view.SetBackend(dummy);
        }

        // Check for non-standard pay-to-script-hash in inputs
        if (!tx.AreInputsStandard(view) && !fTestNet)
            return error("CTxMemPool::accept() : nonstandard transaction input");

        // Note: if you modify this code to accept non-standard transactions, then
        // you should add code here to check that the transaction does a
        // reasonable number of ECDSA signature verifications.

        int64 nFees = tx.GetValueIn(view)-tx.GetValueOut();
        unsigned int nSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);

        // Don't accept it if it can't get into a block
        int64 txMinFee = tx.GetMinFee(1000, true, GMF_RELAY);
        if (fLimitFree && nFees < txMinFee)
            return error("CTxMemPool::accept() : not enough fees %s, %"PRI64d" < %"PRI64d,
                         hash.ToString().c_str(),
                         nFees, txMinFee);

        // Continuously rate-limit free transactions
        // This mitigates 'penny-flooding' -- sending thousands of free transactions just to
        // be annoying or make others' transactions take longer to confirm.
        if (fLimitFree && nFees < CTransaction::nMinRelayTxFee)
        {
            static double dFreeCount;
            static int64 nLastTime;
            int64 nNow = GetTime();

            LOCK(cs);

            // Use an exponentially decaying ~10-minute window:
            dFreeCount *= pow(1.0 - 1.0/600.0, (double)(nNow - nLastTime));
            nLastTime = nNow;
            // -limitfreerelay unit is thousand-bytes-per-minute
            // At default rate it would take over a month to fill 1GB
            if (dFreeCount >= GetArg("-limitfreerelay", 15)*10*1000)
                return error("CTxMemPool::accept() : free transaction rejected by rate limiter");
            if (fDebug)
                printf("Rate limit dFreeCount: %g => %g\n", dFreeCount, dFreeCount+nSize);
            dFreeCount += nSize;
        }

        // Check against previous transactions
        // This is done last to help prevent CPU exhaustion denial-of-service attacks.
        if (!tx.CheckInputs(state, view, true, SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_STRICTENC))
        {
            return error("CTxMemPool::accept() : ConnectInputs failed %s", hash.ToString().c_str());
        }
    }

    // Store transaction in memory
    {
        LOCK(cs);
        if (ptxOld)
        {
            printf("CTxMemPool::accept() : replacing tx %s with new version\n", ptxOld->GetHash().ToString().c_str());
            remove(*ptxOld);
        }
        addUnchecked(hash, tx);
    }

    ///// are we sure this is ok when loading transactions or restoring block txes
    // If updated, erase old tx from wallet
    if (ptxOld)
        EraseFromWallets(ptxOld->GetHash());
    SyncWithWallets(hash, tx, NULL, true);

    printf("CTxMemPool::accept() : accepted %s (poolsz %"PRIszu")\n",
           hash.ToString().c_str(),
           mapTx.size());
    return true;
}

bool CTransaction::AcceptToMemoryPool(CValidationState &state, bool fCheckInputs, bool fLimitFree, bool* pfMissingInputs)
{
    try {
        return mempool.accept(state, *this, fCheckInputs, fLimitFree, pfMissingInputs);
    } catch(std::runtime_error &e) {
        return state.Abort(_("System error: ") + e.what());
    }
}

bool CTxMemPool::addUnchecked(const uint256& hash, CTransaction &tx)
{
    // Add to memory pool without checking anything.  Don't call this directly,
    // call CTxMemPool::accept to properly check the transaction first.
    {
        mapTx[hash] = tx;
        for (unsigned int i = 0; i < tx.vin.size(); i++)
            mapNextTx[tx.vin[i].prevout] = CInPoint(&mapTx[hash], i);
        nTransactionsUpdated++;
    }
    return true;
}


bool CTxMemPool::remove(const CTransaction &tx, bool fRecursive)
{
    // Remove transaction from memory pool
    {
        LOCK(cs);
        uint256 hash = tx.GetHash();
        if (mapTx.count(hash))
        {
            if (fRecursive) {
                for (unsigned int i = 0; i < tx.vout.size(); i++) {
                    std::map<COutPoint, CInPoint>::iterator it = mapNextTx.find(COutPoint(hash, i));
                    if (it != mapNextTx.end())
                        remove(*it->second.ptx, true);
                }
            }
            BOOST_FOREACH(const CTxIn& txin, tx.vin)
                mapNextTx.erase(txin.prevout);
            mapTx.erase(hash);
            nTransactionsUpdated++;
        }
    }
    return true;
}

bool CTxMemPool::removeConflicts(const CTransaction &tx)
{
    // Remove transactions which depend on inputs of tx, recursively
    LOCK(cs);
    BOOST_FOREACH(const CTxIn &txin, tx.vin) {
        std::map<COutPoint, CInPoint>::iterator it = mapNextTx.find(txin.prevout);
        if (it != mapNextTx.end()) {
            const CTransaction &txConflict = *it->second.ptx;
            if (txConflict != tx)
                remove(txConflict, true);
        }
    }
    return true;
}

void CTxMemPool::clear()
{
    LOCK(cs);
    mapTx.clear();
    mapNextTx.clear();
    ++nTransactionsUpdated;
}

void CTxMemPool::queryHashes(std::vector<uint256>& vtxid)
{
    vtxid.clear();

    LOCK(cs);
    vtxid.reserve(mapTx.size());
    for (map<uint256, CTransaction>::iterator mi = mapTx.begin(); mi != mapTx.end(); ++mi)
        vtxid.push_back((*mi).first);
}




int CMerkleTx::GetDepthInMainChain(CBlockIndex* &pindexRet) const
{
    if (hashBlock == 0 || nIndex == -1)
        return 0;

    // Find the block it claims to be in
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashBlock);
    if (mi == mapBlockIndex.end())
        return 0;
    CBlockIndex* pindex = (*mi).second;
    if (!pindex || !pindex->IsInMainChain())
        return 0;

    // Make sure the merkle branch connects to this block
    if (!fMerkleVerified)
    {
        if (CBlock::CheckMerkleBranch(GetHash(), vMerkleBranch, nIndex) != pindex->hashMerkleRoot)
            return 0;
        fMerkleVerified = true;
    }

    pindexRet = pindex;
    return pindexBest->nHeight - pindex->nHeight + 1;
}


int CMerkleTx::GetBlocksToMaturity() const
{
    if (!IsCoinBase())
        return 0;
    return max(0, (COINBASE_MATURITY+2) - GetDepthInMainChain());
}


bool CMerkleTx::AcceptToMemoryPool(bool fCheckInputs, bool fLimitFree)
{
    CValidationState state;
    return CTransaction::AcceptToMemoryPool(state, fCheckInputs, fLimitFree);
}



bool CWalletTx::AcceptWalletTransaction(bool fCheckInputs)
{
    {
        LOCK(mempool.cs);
        // Add previous supporting transactions first
        BOOST_FOREACH(CMerkleTx& tx, vtxPrev)
        {
            if (!tx.IsCoinBase())
            {
                uint256 hash = tx.GetHash();
                if (!mempool.exists(hash) && pcoinsTip->HaveCoins(hash))
                    tx.AcceptToMemoryPool(fCheckInputs, false);
            }
        }
        return AcceptToMemoryPool(fCheckInputs, false);
    }
    return false;
}


// Return transaction in tx, and if it was found inside a block, its hash is placed in hashBlock
bool GetTransaction(const uint256 &hash, CTransaction &txOut, uint256 &hashBlock, bool fAllowSlow)
{
    CBlockIndex *pindexSlow = NULL;
    {
        LOCK(cs_main);
        {
            LOCK(mempool.cs);
            if (mempool.exists(hash))
            {
                txOut = mempool.lookup(hash);
                return true;
            }
        }

        if (fTxIndex) {
            CDiskTxPos postx;
            if (pblocktree->ReadTxIndex(hash, postx)) {
                CAutoFile file(OpenBlockFile(postx, true), SER_DISK, CLIENT_VERSION);
                CBlockHeader header;
                try {
                    file >> header;
                    fseek(file, postx.nTxOffset, SEEK_CUR);
                    file >> txOut;
                } catch (std::exception &e) {
                    return error("%s() : deserialize or I/O error", __PRETTY_FUNCTION__);
                }
                hashBlock = header.GetHash();
                if (txOut.GetHash() != hash)
                    return error("%s() : txid mismatch", __PRETTY_FUNCTION__);
                return true;
            }
        }

        if (fAllowSlow) { // use coin database to locate block that contains transaction, and scan it
            int nHeight = -1;
            {
                CCoinsViewCache &view = *pcoinsTip;
                CCoins coins;
                if (view.GetCoins(hash, coins))
                    nHeight = coins.nHeight;
            }
            if (nHeight > 0)
                pindexSlow = FindBlockByHeight(nHeight);
        }
    }

    if (pindexSlow) {
        CBlock block;
        if (block.ReadFromDisk(pindexSlow)) {
            BOOST_FOREACH(const CTransaction &tx, block.vtx) {
                if (tx.GetHash() == hash) {
                    txOut = tx;
                    hashBlock = pindexSlow->GetBlockHash();
                    return true;
                }
            }
        }
    }

    return false;
}






//////////////////////////////////////////////////////////////////////////////
//
// CBlock and CBlockIndex
//

static CBlockIndex* pblockindexFBBHLast;
CBlockIndex* FindBlockByHeight(int nHeight)
{
    CBlockIndex *pblockindex;
    if (nHeight < nBestHeight / 2)
        pblockindex = pindexGenesisBlock;
    else
        pblockindex = pindexBest;
    if (pblockindexFBBHLast && abs(nHeight - pblockindex->nHeight) > abs(nHeight - pblockindexFBBHLast->nHeight))
        pblockindex = pblockindexFBBHLast;
    while (pblockindex->nHeight > nHeight)
        pblockindex = pblockindex->pprev;
    while (pblockindex->nHeight < nHeight)
        pblockindex = pblockindex->pnext;
    pblockindexFBBHLast = pblockindex;
    return pblockindex;
}

bool CBlock::ReadFromDisk(const CBlockIndex* pindex)
{
    if (!ReadFromDisk(pindex->GetBlockPos()))
        return false;

    if (GetHash() != pindex->GetBlockHash())
        return error("CBlock::ReadFromDisk() : GetHash() doesn't match index");
    return true;
}

uint256 static GetOrphanRoot(const CBlockHeader* pblock)
{
    // Work back to the first block in the orphan chain
    while (mapOrphanBlocks.count(pblock->hashPrevBlock))
        pblock = mapOrphanBlocks[pblock->hashPrevBlock];
    return pblock->GetHash();
}

int64 static GetBlockValue(unsigned int reward, int nHeight, int64 nFees)
{
    int64 nSubsidy = reward * COIN;
    return nSubsidy + nFees;
}

uint16_t nBlockRewardVote = MAX_VOTE/2; // Default to 1/2 limit
uint16_t nBlockRewardVoteLimit = MAX_VOTE;
uint16_t nBlockRewardVoteSpan = 100; // Initial voting interval
uint16_t nPhase = 1; /* 1 = Mint, 2 = Limit, 3 = Sustain */
uint32_t nTarget = PHASE1_MONEY;
uint32_t nMaxSupply = MAX_MONEY/COIN;

void AdjustBlockRewardVoteLimit(CBlockIndex *pindexPrev)
{
    // Check if we should switch to sustain voting.  This will happen
    // at some point in future that is decided democratically by
    // decentralised voting.
    uint16_t nOldVoteLimit = nBlockRewardVoteLimit;

    if (pindexPrev->getSupply() <= PHASE1_MONEY) {
        // Mint phase: votes apply to mining schedule
        nBlockRewardVoteLimit = MAX_VOTE;
        nPhase = 1;
        nTarget = PHASE1_MONEY;
    }
    else {
        // Get the height at PHASE1_MONEY (to be hard-coded in later release)
        if (nPhase == 2)
            nMaxSupply = MAX_MONEY/COIN;
        CBlockIndex *i = pindexBest;
        while (i && i->getSupply() > PHASE1_MONEY) {
            if (nPhase == 2)
                nMaxSupply -= (MAX_VOTE - i->nReward);
            i = i->pprev;
        }
        printf("Vote: height of PHASE1_MONEY = %d\n", i->nHeight);

        int distance = pindexPrev->nHeight - i->nHeight;
        if (distance <= PHASE2_BLOCKS) {
            // Limit phase: votes apply to money supply
            nPhase = 2;
            nTarget = PHASE2_BLOCKS - distance + 1;
            nBlockRewardVoteLimit = MAX_VOTE;
        }
        else {
            // Get the supply at PHASE2_BLOCKS (to be hard-coded in later release)
            CBlockIndex *j = pindexBest;
            while (j && j->nHeight > i->nHeight + PHASE2_BLOCKS)
                j = j->pprev;

            assert(j->nHeight == i->nHeight + PHASE2_BLOCKS);

            uint32_t done = j->getSupply() + MAX_VOTE + nBlockRewardVoteSpan*MAX_VOTE
                            + PHASE3_MONEY - nBlockRewardVoteSpan*8;
            printf("Vote: supply at PHASE2_BLOCKS = %u\n", j->getSupply());

            nPhase = 3;
            nMaxSupply = nTarget = done + nBlockRewardVoteSpan*8;
            if (pindexPrev->getSupply() < done) {
                // Sustain phase: votes apply to long-term sustainment of network
                nBlockRewardVoteLimit = 8;
            }
            else {
                // No reason to vote
                nBlockRewardVoteLimit = 0;
            }
        }
    }

    if (nOldVoteLimit != nBlockRewardVoteLimit) {
        printf("Vote: Adjusted block reward vote limit to %u supply=%d height=%d\n",
               nBlockRewardVoteLimit, pindexPrev->getSupply(), pindexPrev->nHeight);
    }

    if (nBlockRewardVote > nBlockRewardVoteLimit) {
        nBlockRewardVote = nBlockRewardVoteLimit;
        printf("Vote: Capped block reward vote to limit of %u\n", nBlockRewardVoteLimit);
    }
}

uint16_t GetNextBlockReward(CBlockIndex *pindexPrev)
{
    float avg = 0;
    unsigned int count;
    // Don't count genesis block's vote
    for (count = 0 ;
         count < nBlockRewardVoteSpan && pindexPrev && *pindexPrev->phashBlock != hashGenesisBlock
         && pindexPrev->nHeight % nBlockRewardVoteSpan != 0;
         count++) {
        avg += pindexPrev->nVote;
        pindexPrev = pindexPrev->pprev;
    }
    if (!count)
        return 0;

    uint16_t nBlockReward = (uint16_t)round((double)avg/(double)count);

    return nBlockReward;
}

uint16_t GetCurrentBlockReward(CBlockIndex *pindexPrev)
{
    if (pindexPrev->getSupply() >= nMaxSupply)
        return 0;

    // Tally votes after first 100 blocks
    if (pindexPrev->nHeight > 100)
        nBlockRewardVoteSpan = 3600; // Tally votes every 5 days

    // Tally reward votes every nBlockRewardVoteSpan blocks
    if (!pindexPrev->nHeight || pindexPrev->nHeight % nBlockRewardVoteSpan != 0)
        return pindexPrev->nReward;

    printf("Vote: Calculating new block reward based on votes\n");

    float avg = 0;
    unsigned int count;
    // Don't count genesis block's vote
    for (count = 0 ;
         count < nBlockRewardVoteSpan && pindexPrev && *pindexPrev->phashBlock != hashGenesisBlock;
         count++) {
        avg += pindexPrev->nVote;
        pindexPrev = pindexPrev->pprev;
    }
    if (!count)
        return pindexPrev->nReward;

    uint16_t nBlockReward = (uint16_t)round((double)avg/(double)count);
    printf("Vote: Tallied %u votes - average block reward vote is %hu\n", count, nBlockReward);

    return nBlockReward;
}

const int64 nTargetTimespan = 2 * 60; // 2 minutes
const int64 nInterval = 5; // 10 minutes
const int64 nDiffWindow = 30; // 1 hour
const int64 nLifeWindow = 120; // 4 hours
// const int64 nDiffWindow = 10; // 20 min
// const int64 nLifeWindow = 20; // 40 min

int64 AbsTime(int64 t0, int64 t1)
{
    if (t0 > t1)
        return t0 - t1;
    else
        return t1 - t0;
}

void CalcWindowedAvgs(CBlockIndex *pindexPrev, int64 nMax, unsigned int nLastBits,
                      int64 nLastTimespan, CBigNum &bnAvg, float &nAvgTimespan, float &nAvgRatio)
{
    // Calculate averages over window
    CBigNum bnSum;
    bnSum.SetCompact(nLastBits);
    int64 nCount = 1;
    int64 nSum = nLastTimespan;
    while (nCount < nMax && pindexPrev && pindexPrev->pprev
           && *pindexPrev->pprev->phashBlock != hashGenesisBlock) {
        nSum += AbsTime(pindexPrev->GetBlockTime(), pindexPrev->pprev->GetBlockTime());

        CBigNum bnDiff;
        bnDiff.SetCompact(pindexPrev->nBits);
        bnSum += bnDiff;
        nCount++;
        pindexPrev = pindexPrev->pprev;
    }
    nAvgTimespan = (float)nSum/(float)nCount;
    nAvgRatio = (float)nSum/(float)(nCount*nTargetTimespan);
    bnAvg = bnSum/nCount;
}

static void LogBlock(CBlock &block)
{
    CBlockHeader hdr = block.GetBlockHeader();
    if (hdr.hashPrevBlock == hashGenesisBlock)
        return; // Only log from 3rd block

    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hdr.hashPrevBlock);
    if (mi == mapBlockIndex.end())
        printf("Block chain: error (prev block not found)\n");
    else {
        CBlockIndex *pindexPrev = (*mi).second;
        int64 nLastTimespan = AbsTime((int64)hdr.nTime, pindexPrev->GetBlockTime());
        int nHeight = pindexPrev->nHeight + 1;

        // Calculate averages over nDiffWindow
        CBigNum bnAvg;
        float nAvgRatio;
        float nAvgTimespan;
        CalcWindowedAvgs(pindexPrev, nDiffWindow, hdr.nBits, nLastTimespan,
                         bnAvg, nAvgTimespan, nAvgRatio);

        CBigNum bnAvg24;
        float nAvgRatio24;
        float nAvgTimespan24;
        CalcWindowedAvgs(pindexPrev, 720, hdr.nBits, nLastTimespan,
                         bnAvg24, nAvgTimespan24, nAvgRatio24);


        printf("Block chain: %s | %d | last %.8f %08x %.3f | 1hr %.8f %08x %.3f %.3f | 24hr %.8f %08x %.3f %.3f | stats %hu %u %hu | vote %hu | last %"PRI64d"\n",
               DateTimeStrFormat("%Y-%m-%d %H:%M:%S", GetTime()).c_str(),
               nHeight,
               (float)CalcDifficulty(hdr.nBits),
               hdr.nBits,
               (float)nLastTimespan/(float)nTargetTimespan,
               (float)CalcDifficulty(bnAvg.GetCompact()),
               bnAvg.GetCompact(),
               nAvgRatio,
               nAvgTimespan,
               (float)CalcDifficulty(bnAvg24.GetCompact()),
               bnAvg24.GetCompact(),
               nAvgRatio24,
               nAvgTimespan24,
               hdr.nReward, hdr.getSupply(),
               GetNextBlockReward(pindexPrev), hdr.nVote,
               nLastTimespan);
    }
}

//
// minimum amount of work that could possibly be required nTime after
// minimum work required was nBase
//
unsigned int ComputeMinWork(unsigned int nBase, int64 nTime)
{
    // Testnet has min-difficulty blocks
    // after nTargetSpacing*2 time between blocks:
    if (fTestNet && nTime > nTargetTimespan*2)
        return bnProofOfWorkLimit.GetCompact();

    CBigNum bnResult;
    bnResult.SetCompact(nBase);
    while (nTime > 0 && bnResult < bnProofOfWorkLimit)
    {
        // Maximum possible adjustment...
        bnResult *= 4;
        // ... per timespan
        nTime -= nTargetTimespan*4;
    }
    if (bnResult > bnProofOfWorkLimit)
        bnResult = bnProofOfWorkLimit;
    return bnResult.GetCompact();
}

unsigned int static GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock)
{
    static CBigNum bnCurr;
    CBigNum bnLast;
    bnLast.SetCompact(pindexLast->nBits);

    if (bnCurr == 0)
        bnCurr = bnLast;

    // Use measurements over last 4 hours
    unsigned int i;
    CBigNum bnNew = 0;
    unsigned int count = 0;
    int64 now = (int64)pblock->nTime; // Can be out by 2hrs
    const CBlockIndex* pindexFirst = pindexLast;
    for (i = 0; pindexFirst && pindexFirst->pprev &&
         now - pindexFirst->GetBlockTime() < nLifeWindow*nTargetTimespan; i++) {
        if (*pindexFirst->pprev->phashBlock == hashGenesisBlock) {
                static int logged1;
                if (!logged1) {
                    printf("Avoiding retarget against genesis block\n");
                    logged1 = 1;
                }
                break;
        }

        if (count < nDiffWindow) {
            CBigNum bnDiff;
            bnDiff.SetCompact(pindexFirst->nBits);
            int64 nTime = AbsTime(pindexFirst->GetBlockTime(), pindexFirst->pprev->GetBlockTime());

            // Adjusted difficulty
            bnDiff *= nTime;
            bnDiff /= nTargetTimespan;
            bnNew += bnDiff;
            count++;
        }

        pindexFirst = pindexFirst->pprev;
    }

    if (!count) {
        printf("Retarget: Bumping count = 1\n");
        bnNew = bnProofOfWorkLimit;
        count = 1;
    }
    bnNew /= count;

    // Heavycoin Temporal Retargeting - exits "blackhole" in ~3hrs
    if (pindexLast->nHeight > nLifeWindow && count < nLifeWindow/4) {
        int min = nLifeWindow/4 - count;
        printf("Retarget: **** Heavycoin Temporal Retargeting **** %d/%d : factor = %d\n",
               count, (int)nLifeWindow/4, (int)pow(2.0f, min));

        bnNew *= (int)pow(2.0f, min);

        printf("Retarget: heal  = %g %08x %s\n", CalcDifficulty(bnNew.GetCompact()),
               bnNew.GetCompact(), bnNew.getuint256().ToString().c_str());
    }
    else {
        // Soft limit
        if (bnNew < bnLast/2)
            bnNew = bnLast/2;
        else if (bnNew > 4*bnLast)
            bnNew = 4*bnLast;
    }

    // Hard limit
    if (bnNew > bnProofOfWorkLimit)
        bnNew = bnProofOfWorkLimit;

    // Only retarget every nInterval blocks on difficulty increase
    if (bnNew < bnLast && (pindexLast->nHeight + 1) % nInterval != 0) {
        // Sample the current block time over more blocks before
        // increasing the difficulty.

        return pindexLast->nBits;
    }

    if (bnCurr.GetCompact() != bnNew.GetCompact()) {
        printf("Retarget: %g %08x %s\n", CalcDifficulty(bnNew.GetCompact()),
               bnNew.GetCompact(), bnNew.getuint256().ToString().c_str());
        bnCurr = bnNew;
    }

    return bnCurr.GetCompact();
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits)
{
    CBigNum bnTarget;
    bnTarget.SetCompact(nBits);

    // Check range
    if (bnTarget <= 0 || bnTarget > bnProofOfWorkLimit)
        return error("CheckProofOfWork() : nBits below minimum work");

    // Check proof of work matches claimed amount
    if (hash > bnTarget.getuint256())
        return error("CheckProofOfWork() : hash doesn't match nBits");

    return true;
}

// Return maximum amount of blocks that other nodes claim to have
int GetNumBlocksOfPeers()
{
    return std::max(cPeerBlockCounts.median(), Checkpoints::GetTotalBlocksEstimate());
}

bool IsInitialBlockDownload()
{
    if (pindexBest == NULL || fImporting || fReindex || nBestHeight < Checkpoints::GetTotalBlocksEstimate())
        return true;
    static int64 nLastUpdate;
    static CBlockIndex* pindexLastBest;
    if (pindexBest != pindexLastBest)
    {
        pindexLastBest = pindexBest;
        nLastUpdate = GetTime();
    }
    return (GetTime() - nLastUpdate < 10 &&
            pindexBest->GetBlockTime() < GetTime() - 24 * 60 * 60);
}

void static InvalidChainFound(CBlockIndex* pindexNew)
{
    if (pindexNew->nChainWork > nBestInvalidWork)
    {
        nBestInvalidWork = pindexNew->nChainWork;
        pblocktree->WriteBestInvalidWork(CBigNum(nBestInvalidWork));
        uiInterface.NotifyBlocksChanged();
    }
    printf("InvalidChainFound: invalid block=%s  height=%d  log2_work=%.8g  date=%s\n",
      pindexNew->GetBlockHash().ToString().c_str(), pindexNew->nHeight,
      log(pindexNew->nChainWork.getdouble())/log(2.0), DateTimeStrFormat("%Y-%m-%d %H:%M:%S",
      pindexNew->GetBlockTime()).c_str());
    printf("InvalidChainFound:  current best=%s  height=%d  log2_work=%.8g  date=%s\n",
      hashBestChain.ToString().c_str(), nBestHeight, log(nBestChainWork.getdouble())/log(2.0),
      DateTimeStrFormat("%Y-%m-%d %H:%M:%S", pindexBest->GetBlockTime()).c_str());
    if (pindexBest && nBestInvalidWork > nBestChainWork + (pindexBest->GetBlockWork() * 6).getuint256())
        printf("InvalidChainFound: Warning: Displayed transactions may not be correct! You may need to upgrade, or other nodes may need to upgrade.\n");
}

void static InvalidBlockFound(CBlockIndex *pindex) {
    pindex->nStatus |= BLOCK_FAILED_VALID;
    pblocktree->WriteBlockIndex(CDiskBlockIndex(pindex));
    setBlockIndexValid.erase(pindex);
    InvalidChainFound(pindex);
    if (pindex->pnext) {
        CValidationState stateDummy;
        ConnectBestBlock(stateDummy); // reorganise away from the failed block
    }
}

bool ConnectBestBlock(CValidationState &state) {
    do {
        CBlockIndex *pindexNewBest;

        {
            std::set<CBlockIndex*,CBlockIndexWorkComparator>::reverse_iterator it = setBlockIndexValid.rbegin();
            if (it == setBlockIndexValid.rend())
                return true;
            pindexNewBest = *it;
        }

        if (pindexNewBest == pindexBest || (pindexBest && pindexNewBest->nChainWork == pindexBest->nChainWork))
            return true; // nothing to do

        // check ancestry
        CBlockIndex *pindexTest = pindexNewBest;
        std::vector<CBlockIndex*> vAttach;
        do {
            if (pindexTest->nStatus & BLOCK_FAILED_MASK) {
                // mark descendants failed
                CBlockIndex *pindexFailed = pindexNewBest;
                while (pindexTest != pindexFailed) {
                    pindexFailed->nStatus |= BLOCK_FAILED_CHILD;
                    setBlockIndexValid.erase(pindexFailed);
                    pblocktree->WriteBlockIndex(CDiskBlockIndex(pindexFailed));
                    pindexFailed = pindexFailed->pprev;
                }
                InvalidChainFound(pindexNewBest);
                break;
            }

            if (pindexBest == NULL || pindexTest->nChainWork > pindexBest->nChainWork)
                vAttach.push_back(pindexTest);

            if (pindexTest->pprev == NULL || pindexTest->pnext != NULL) {
                reverse(vAttach.begin(), vAttach.end());
                BOOST_FOREACH(CBlockIndex *pindexSwitch, vAttach) {
                    boost::this_thread::interruption_point();
                    try {
                        if (!SetBestChain(state, pindexSwitch))
                            return false;
                    } catch(std::runtime_error &e) {
                        return state.Abort(_("System error: ") + e.what());
                    }
                }
                return true;
            }
            pindexTest = pindexTest->pprev;
        } while(true);
    } while(true);
}

void CBlockHeader::UpdateTime(const CBlockIndex* pindexPrev)
{
    nTime = max(pindexPrev->GetMedianTimePast()+1, GetAdjustedTime());

    // Updating time can change work required on testnet:
    if (fTestNet)
        nBits = GetNextWorkRequired(pindexPrev, this);
}











const CTxOut &CTransaction::GetOutputFor(const CTxIn& input, CCoinsViewCache& view)
{
    const CCoins &coins = view.GetCoins(input.prevout.hash);
    assert(coins.IsAvailable(input.prevout.n));
    return coins.vout[input.prevout.n];
}

int64 CTransaction::GetValueIn(CCoinsViewCache& inputs) const
{
    if (IsCoinBase())
        return 0;

    int64 nResult = 0;
    for (unsigned int i = 0; i < vin.size(); i++)
        nResult += GetOutputFor(vin[i], inputs).nValue;

    return nResult;
}

unsigned int CTransaction::GetP2SHSigOpCount(CCoinsViewCache& inputs) const
{
    if (IsCoinBase())
        return 0;

    unsigned int nSigOps = 0;
    for (unsigned int i = 0; i < vin.size(); i++)
    {
        const CTxOut &prevout = GetOutputFor(vin[i], inputs);
        if (prevout.scriptPubKey.IsPayToScriptHash())
            nSigOps += prevout.scriptPubKey.GetSigOpCount(vin[i].scriptSig);
    }
    return nSigOps;
}

void CTransaction::UpdateCoins(CValidationState &state, CCoinsViewCache &inputs, CTxUndo &txundo, int nHeight, const uint256 &txhash) const
{
    // mark inputs spent
    if (!IsCoinBase()) {
        BOOST_FOREACH(const CTxIn &txin, vin) {
            CCoins &coins = inputs.GetCoins(txin.prevout.hash);
            CTxInUndo undo;
            assert(coins.Spend(txin.prevout, undo));
            txundo.vprevout.push_back(undo);
        }
    }

    // add outputs
    assert(inputs.SetCoins(txhash, CCoins(*this, nHeight)));
}

bool CTransaction::HaveInputs(CCoinsViewCache &inputs) const
{
    if (!IsCoinBase()) {
        // first check whether information about the prevout hash is available
        for (unsigned int i = 0; i < vin.size(); i++) {
            const COutPoint &prevout = vin[i].prevout;
            if (!inputs.HaveCoins(prevout.hash))
                return false;
        }

        // then check whether the actual outputs are available
        for (unsigned int i = 0; i < vin.size(); i++) {
            const COutPoint &prevout = vin[i].prevout;
            const CCoins &coins = inputs.GetCoins(prevout.hash);
            if (!coins.IsAvailable(prevout.n))
                return false;
        }
    }
    return true;
}

bool CScriptCheck::operator()() const {
    const CScript &scriptSig = ptxTo->vin[nIn].scriptSig;
    if (!VerifyScript(scriptSig, scriptPubKey, *ptxTo, nIn, nFlags, nHashType))
        return error("CScriptCheck() : %s VerifySignature failed", ptxTo->GetHash().ToString().c_str());
    return true;
}

bool VerifySignature(const CCoins& txFrom, const CTransaction& txTo, unsigned int nIn, unsigned int flags, int nHashType)
{
    return CScriptCheck(txFrom, txTo, nIn, flags, nHashType)();
}

bool CTransaction::CheckInputs(CValidationState &state, CCoinsViewCache &inputs, bool fScriptChecks, unsigned int flags, std::vector<CScriptCheck> *pvChecks) const
{
    if (!IsCoinBase())
    {
        if (pvChecks)
            pvChecks->reserve(vin.size());

        // This doesn't trigger the DoS code on purpose; if it did, it would make it easier
        // for an attacker to attempt to split the network.
        if (!HaveInputs(inputs))
            return state.Invalid(error("CheckInputs() : %s inputs unavailable", GetHash().ToString().c_str()));

        // While checking, GetBestBlock() refers to the parent block.
        // This is also true for mempool checks.
        int nSpendHeight = inputs.GetBestBlock()->nHeight + 1;
        int64 nValueIn = 0;
        int64 nFees = 0;
        for (unsigned int i = 0; i < vin.size(); i++)
        {
            const COutPoint &prevout = vin[i].prevout;
            const CCoins &coins = inputs.GetCoins(prevout.hash);

            // If prev is coinbase, check that it's matured
            if (coins.IsCoinBase()) {
                if (nSpendHeight - coins.nHeight < COINBASE_MATURITY)
                    return state.Invalid(error("CheckInputs() : tried to spend coinbase at depth %d", nSpendHeight - coins.nHeight));
            }

            // Check for negative or overflow input values
            nValueIn += coins.vout[prevout.n].nValue;
            if (!MoneyRange(coins.vout[prevout.n].nValue) || !MoneyRange(nValueIn))
                return state.DoS(100, error("CheckInputs() : txin values out of range"));

        }

        if (nValueIn < GetValueOut())
            return state.DoS(100, error("CheckInputs() : %s value in < value out", GetHash().ToString().c_str()));

        // Tally transaction fees
        int64 nTxFee = nValueIn - GetValueOut();
        if (nTxFee < 0)
            return state.DoS(100, error("CheckInputs() : %s nTxFee < 0", GetHash().ToString().c_str()));
        nFees += nTxFee;
        if (!MoneyRange(nFees))
            return state.DoS(100, error("CheckInputs() : nFees out of range"));

        // The first loop above does all the inexpensive checks.
        // Only if ALL inputs pass do we perform expensive ECDSA signature checks.
        // Helps prevent CPU exhaustion attacks.

        // Skip ECDSA signature verification when connecting blocks
        // before the last block chain checkpoint. This is safe because block merkle hashes are
        // still computed and checked, and any change will be caught at the next checkpoint.
        if (fScriptChecks) {
            for (unsigned int i = 0; i < vin.size(); i++) {
                const COutPoint &prevout = vin[i].prevout;
                const CCoins &coins = inputs.GetCoins(prevout.hash);

                // Verify signature
                CScriptCheck check(coins, *this, i, flags, 0);
                if (pvChecks) {
                    pvChecks->push_back(CScriptCheck());
                    check.swap(pvChecks->back());
                } else if (!check()) {
                    if (flags & SCRIPT_VERIFY_STRICTENC) {
                        // For now, check whether the failure was caused by non-canonical
                        // encodings or not; if so, don't trigger DoS protection.
                        CScriptCheck check(coins, *this, i, flags & (~SCRIPT_VERIFY_STRICTENC), 0);
                        if (check())
                            return state.Invalid();
                    }
                    return state.DoS(100,false);
                }
            }
        }
    }

    return true;
}




bool CBlock::DisconnectBlock(CValidationState &state, CBlockIndex *pindex, CCoinsViewCache &view, bool *pfClean)
{
    assert(pindex == view.GetBestBlock());

    if (pfClean)
        *pfClean = false;

    bool fClean = true;

    CBlockUndo blockUndo;
    CDiskBlockPos pos = pindex->GetUndoPos();
    if (pos.IsNull())
        return error("DisconnectBlock() : no undo data available");

    if (!blockUndo.ReadFromDisk(pos, pindex->pprev->GetBlockHash()))
        return error("DisconnectBlock() : failure reading undo data");

    if (blockUndo.vtxundo.size() + 1 != vtx.size())
        return error("DisconnectBlock() : block and undo data inconsistent");

    // undo transactions in reverse order
    for (int i = vtx.size() - 1; i >= 0; i--) {
        const CTransaction &tx = vtx[i];
        uint256 hash = tx.GetHash();

        // check that all outputs are available
        if (!view.HaveCoins(hash)) {
            fClean = fClean && error("DisconnectBlock() : outputs still spent? database corrupted");
            view.SetCoins(hash, CCoins());
        }
        CCoins &outs = view.GetCoins(hash);

        CCoins outsBlock = CCoins(tx, pindex->nHeight);
        if (outs != outsBlock)
            fClean = fClean && error("DisconnectBlock() : added transaction mismatch? database corrupted");

        // remove outputs
        outs = CCoins();

        // restore inputs
        if (i > 0) { // not coinbases
            const CTxUndo &txundo = blockUndo.vtxundo[i-1];
            if (txundo.vprevout.size() != tx.vin.size())
                return error("DisconnectBlock() : transaction and undo data inconsistent");
            for (unsigned int j = tx.vin.size(); j-- > 0;) {
                const COutPoint &out = tx.vin[j].prevout;
                const CTxInUndo &undo = txundo.vprevout[j];
                CCoins coins;
                view.GetCoins(out.hash, coins); // this can fail if the prevout was already entirely spent
                if (undo.nHeight != 0) {
                    // undo data contains height: this is the last output of the prevout tx being spent
                    if (!coins.IsPruned())
                        fClean = fClean && error("DisconnectBlock() : undo data overwriting existing transaction");
                    coins = CCoins();
                    coins.fCoinBase = undo.fCoinBase;
                    coins.nHeight = undo.nHeight;
                    coins.nVersion = undo.nVersion;
                } else {
                    if (!undo.fCoinBase && coins.IsPruned())
                        fClean = fClean && error("DisconnectBlock() : undo data adding output to missing transaction");
                }
                if (coins.IsAvailable(out.n))
                    fClean = fClean && error("DisconnectBlock() : undo data overwriting existing output");
                if (coins.vout.size() < out.n+1)
                    coins.vout.resize(out.n+1);
                coins.vout[out.n] = undo.txout;
                if (!view.SetCoins(out.hash, coins))
                    return error("DisconnectBlock() : cannot restore coin inputs");
            }
        }
    }

    // move best block pointer to prevout block
    view.SetBestBlock(pindex->pprev);

    if (pfClean) {
        *pfClean = fClean;
        return true;
    } else {
        return fClean;
    }
}

void static FlushBlockFile(bool fFinalize = false)
{
    LOCK(cs_LastBlockFile);

    CDiskBlockPos posOld(nLastBlockFile, 0);

    FILE *fileOld = OpenBlockFile(posOld);
    if (fileOld) {
        if (fFinalize)
            TruncateFile(fileOld, infoLastBlockFile.nSize);
        FileCommit(fileOld);
        fclose(fileOld);
    }

    fileOld = OpenUndoFile(posOld);
    if (fileOld) {
        if (fFinalize)
            TruncateFile(fileOld, infoLastBlockFile.nUndoSize);
        FileCommit(fileOld);
        fclose(fileOld);
    }
}

bool FindUndoPos(CValidationState &state, int nFile, CDiskBlockPos &pos, unsigned int nAddSize);

static CCheckQueue<CScriptCheck> scriptcheckqueue(128);

void ThreadScriptCheck() {
    RenameThread("heavycoin-scriptch");
    scriptcheckqueue.Thread();
}

bool CBlock::ConnectBlock(CValidationState &state, CBlockIndex* pindex, CCoinsViewCache &view, bool fJustCheck)
{
    // Check it again in case a previous version let a bad block in
    if (!CheckBlock(state, !fJustCheck, !fJustCheck))
        return false;

    // verify that the view's current state corresponds to the previous block
    assert(pindex->pprev == view.GetBestBlock());

    bool fScriptChecks = pindex->nHeight >= Checkpoints::GetTotalBlocksEstimate();

    // Do not allow blocks that contain transactions which 'overwrite' older transactions,
    // unless those are already completely spent.
    // If such overwrites are allowed, coinbases and transactions depending upon those
    // can be duplicated to remove the ability to spend the first instance -- even after
    // being sent to another address.
    // See BIP30 and http://r6.ca/blog/20120206T005236Z.html for more information.
    // This logic is not necessary for memory pool transactions, as AcceptToMemoryPool
    // already refuses previously-known transaction ids entirely.
    // This rule was originally applied all blocks whose timestamp was after March 15, 2012, 0:00 UTC.
    // Now that the whole chain is irreversibly beyond that time it is applied to all blocks except the
    // two in the chain that violate it. This prevents exploiting the issue against nodes in their
    // initial block download.
    bool fEnforceBIP30 = (!pindex->phashBlock) || // Enforce on CreateNewBlock invocations which don't have a hash.
                          !((pindex->nHeight==91842 && pindex->GetBlockHash() == uint256("0x00000000000a4d0a398161ffc163c503763b1f4360639393e0e4c8e300e0caec")) ||
                           (pindex->nHeight==91880 && pindex->GetBlockHash() == uint256("0x00000000000743f190a18c5577a3c2d2a1f610ae9601ac046a38084ccb7cd721")));
    if (fEnforceBIP30) {
        for (unsigned int i=0; i<vtx.size(); i++) {
            uint256 hash = GetTxHash(i);
            if (view.HaveCoins(hash) && !view.GetCoins(hash).IsPruned())
                return state.DoS(100, error("ConnectBlock() : tried to overwrite transaction"));
        }
    }

    // BIP16 didn't become active until Apr 1 2012
    int64 nBIP16SwitchTime = 1333238400;
    bool fStrictPayToScriptHash = (pindex->nTime >= nBIP16SwitchTime);

    unsigned int flags = SCRIPT_VERIFY_NOCACHE |
                         (fStrictPayToScriptHash ? SCRIPT_VERIFY_P2SH : SCRIPT_VERIFY_NONE);

    CBlockUndo blockundo;

    CCheckQueueControl<CScriptCheck> control(fScriptChecks && nScriptCheckThreads ? &scriptcheckqueue : NULL);

    int64 nStart = GetTimeMicros();
    int64 nFees = 0;
    int nInputs = 0;
    unsigned int nSigOps = 0;
    CDiskTxPos pos(pindex->GetBlockPos(), GetSizeOfCompactSize(vtx.size()));
    std::vector<std::pair<uint256, CDiskTxPos> > vPos;
    vPos.reserve(vtx.size());
    for (unsigned int i=0; i<vtx.size(); i++)
    {
        const CTransaction &tx = vtx[i];

        nInputs += tx.vin.size();
        nSigOps += tx.GetLegacySigOpCount();
        if (nSigOps > MAX_BLOCK_SIGOPS)
            return state.DoS(100, error("ConnectBlock() : too many sigops"));

        if (!tx.IsCoinBase())
        {
            if (!tx.HaveInputs(view))
                return state.DoS(100, error("ConnectBlock() : inputs missing/spent"));

            if (fStrictPayToScriptHash)
            {
                // Add in sigops done by pay-to-script-hash inputs;
                // this is to prevent a "rogue miner" from creating
                // an incredibly-expensive-to-validate block.
                nSigOps += tx.GetP2SHSigOpCount(view);
                if (nSigOps > MAX_BLOCK_SIGOPS)
                     return state.DoS(100, error("ConnectBlock() : too many sigops"));
            }

            nFees += tx.GetValueIn(view)-tx.GetValueOut();

            std::vector<CScriptCheck> vChecks;
            if (!tx.CheckInputs(state, view, fScriptChecks, flags, nScriptCheckThreads ? &vChecks : NULL))
                return false;
            control.Add(vChecks);
        }

        CTxUndo txundo;
        tx.UpdateCoins(state, view, txundo, pindex->nHeight, GetTxHash(i));
        CCoins coins;
        view.GetCoins(GetTxHash(i), coins);
        if (!tx.IsCoinBase())
            blockundo.vtxundo.push_back(txundo);

        vPos.push_back(std::make_pair(GetTxHash(i), pos));
        pos.nTxOffset += ::GetSerializeSize(tx, SER_DISK, CLIENT_VERSION);
    }
    int64 nTime = GetTimeMicros() - nStart;
    if (fBenchmark)
        printf("- Connect %u transactions: %.2fms (%.3fms/tx, %.3fms/txin)\n", (unsigned)vtx.size(), 0.001 * nTime, 0.001 * nTime / vtx.size(), nInputs <= 1 ? 0 : 0.001 * nTime / (nInputs-1));

    if (GetHash() != hashGenesisBlock) {
        // Genesis block is special
        if (vtx[0].GetValueOut() > GetBlockValue(pindex->nReward, pindex->nHeight, nFees))
            return state.DoS(100, error("ConnectBlock() : coinbase pays too much (actual=%"PRI64d" vs limit=%"PRI64d")", vtx[0].GetValueOut(), GetBlockValue(pindex->nReward, pindex->nHeight, nFees)));
    }

    if (!control.Wait())
        return state.DoS(100, false);
    int64 nTime2 = GetTimeMicros() - nStart;
    if (fBenchmark)
        printf("- Verify %u txins: %.2fms (%.3fms/txin)\n", nInputs - 1, 0.001 * nTime2, nInputs <= 1 ? 0 : 0.001 * nTime2 / (nInputs-1));

    if (fJustCheck)
        return true;

    // Write undo information to disk
    if (pindex->GetUndoPos().IsNull() || (pindex->nStatus & BLOCK_VALID_MASK) < BLOCK_VALID_SCRIPTS)
    {
        if (pindex->GetUndoPos().IsNull() && *pindex->phashBlock != hashGenesisBlock) {
            CDiskBlockPos pos;
            if (!FindUndoPos(state, pindex->nFile, pos, ::GetSerializeSize(blockundo, SER_DISK, CLIENT_VERSION) + 40))
                return error("ConnectBlock() : FindUndoPos failed");
            if (!blockundo.WriteToDisk(pos, pindex->pprev->GetBlockHash()))
                return state.Abort(_("Failed to write undo data"));

            // update nUndoPos in block index
            pindex->nUndoPos = pos.nPos;
            pindex->nStatus |= BLOCK_HAVE_UNDO;
        }

        pindex->nStatus = (pindex->nStatus & ~BLOCK_VALID_MASK) | BLOCK_VALID_SCRIPTS;

        CDiskBlockIndex blockindex(pindex);
        if (!pblocktree->WriteBlockIndex(blockindex))
            return state.Abort(_("Failed to write block index"));
    }

    if (fTxIndex)
        if (!pblocktree->WriteTxIndex(vPos))
            return state.Abort(_("Failed to write transaction index"));

    // add this block to the view's block chain
    assert(view.SetBestBlock(pindex));

    // Watch for transactions paying to me
    for (unsigned int i=0; i<vtx.size(); i++)
        SyncWithWallets(GetTxHash(i), vtx[i], this, true);

    return true;
}

bool SetBestChain(CValidationState &state, CBlockIndex* pindexNew)
{
    // All modifications to the coin state will be done in this cache.
    // Only when all have succeeded, we push it to pcoinsTip.
    CCoinsViewCache view(*pcoinsTip, true);

    // Find the fork (typically, there is none)
    CBlockIndex* pfork = view.GetBestBlock();
    CBlockIndex* plonger = pindexNew;
    while (pfork && pfork != plonger)
    {
        while (plonger->nHeight > pfork->nHeight) {
            plonger = plonger->pprev;
            assert(plonger != NULL);
        }
        if (pfork == plonger)
            break;
        pfork = pfork->pprev;
        assert(pfork != NULL);
    }

    // List of what to disconnect (typically nothing)
    vector<CBlockIndex*> vDisconnect;
    for (CBlockIndex* pindex = view.GetBestBlock(); pindex != pfork; pindex = pindex->pprev)
        vDisconnect.push_back(pindex);

    // List of what to connect (typically only pindexNew)
    vector<CBlockIndex*> vConnect;
    for (CBlockIndex* pindex = pindexNew; pindex != pfork; pindex = pindex->pprev)
        vConnect.push_back(pindex);
    reverse(vConnect.begin(), vConnect.end());

    if (vDisconnect.size() > 0) {
        printf("REORGANIZE: Disconnect %"PRIszu" blocks; %s..\n", vDisconnect.size(), pfork->GetBlockHash().ToString().c_str());
        printf("REORGANIZE: Connect %"PRIszu" blocks; ..%s\n", vConnect.size(), pindexNew->GetBlockHash().ToString().c_str());
    }

    // Disconnect shorter branch
    vector<CTransaction> vResurrect;
    BOOST_FOREACH(CBlockIndex* pindex, vDisconnect) {
        CBlock block;
        if (!block.ReadFromDisk(pindex))
            return state.Abort(_("Failed to read block"));
        int64 nStart = GetTimeMicros();
        if (!block.DisconnectBlock(state, pindex, view))
            return error("SetBestBlock() : DisconnectBlock %s failed", pindex->GetBlockHash().ToString().c_str());
        if (fBenchmark)
            printf("- Disconnect: %.2fms\n", (GetTimeMicros() - nStart) * 0.001);

        // Queue memory transactions to resurrect.
        // We only do this for blocks after the last checkpoint (reorganisation before that
        // point should only happen with -reindex/-loadblock, or a misbehaving peer.
        BOOST_FOREACH(const CTransaction& tx, block.vtx)
            if (!tx.IsCoinBase() && pindex->nHeight > Checkpoints::GetTotalBlocksEstimate())
                vResurrect.push_back(tx);
    }

    // Connect longer branch
    vector<CTransaction> vDelete;
    BOOST_FOREACH(CBlockIndex *pindex, vConnect) {
        CBlock block;
        if (!block.ReadFromDisk(pindex))
            return state.Abort(_("Failed to read block"));
        int64 nStart = GetTimeMicros();
        if (!block.ConnectBlock(state, pindex, view)) {
            if (state.IsInvalid()) {
                InvalidChainFound(pindexNew);
                InvalidBlockFound(pindex);
            }
            return error("SetBestBlock() : ConnectBlock %s failed", pindex->GetBlockHash().ToString().c_str());
        }
        if (fBenchmark)
            printf("- Connect: %.2fms\n", (GetTimeMicros() - nStart) * 0.001);

        // Queue memory transactions to delete
        BOOST_FOREACH(const CTransaction& tx, block.vtx)
            vDelete.push_back(tx);
    }

    // Flush changes to global coin state
    int64 nStart = GetTimeMicros();
    int nModified = view.GetCacheSize();
    assert(view.Flush());
    int64 nTime = GetTimeMicros() - nStart;
    if (fBenchmark)
        printf("- Flush %i transactions: %.2fms (%.4fms/tx)\n", nModified, 0.001 * nTime, 0.001 * nTime / nModified);

    // Make sure it's successfully written to disk before changing memory structure
    bool fIsInitialDownload = IsInitialBlockDownload();
    if (!fIsInitialDownload || pcoinsTip->GetCacheSize() > nCoinCacheSize) {
        // Typical CCoins structures on disk are around 100 bytes in size.
        // Pushing a new one to the database can cause it to be written
        // twice (once in the log, and once in the tables). This is already
        // an overestimation, as most will delete an existing entry or
        // overwrite one. Still, use a conservative safety factor of 2.
        if (!CheckDiskSpace(100 * 2 * 2 * pcoinsTip->GetCacheSize()))
            return state.Error();
        FlushBlockFile();
        pblocktree->Sync();
        if (!pcoinsTip->Flush())
            return state.Abort(_("Failed to write to coin database"));
    }

    // At this point, all changes have been done to the database.
    // Proceed by updating the memory structures.

    // Disconnect shorter branch
    BOOST_FOREACH(CBlockIndex* pindex, vDisconnect)
        if (pindex->pprev)
            pindex->pprev->pnext = NULL;

    // Connect longer branch
    BOOST_FOREACH(CBlockIndex* pindex, vConnect)
        if (pindex->pprev)
            pindex->pprev->pnext = pindex;

    // Resurrect memory transactions that were in the disconnected branch
    BOOST_FOREACH(CTransaction& tx, vResurrect) {
        // ignore validation errors in resurrected transactions
        CValidationState stateDummy;
        tx.AcceptToMemoryPool(stateDummy, true, false);
    }

    // Delete redundant memory transactions that are in the connected branch
    BOOST_FOREACH(CTransaction& tx, vDelete) {
        mempool.remove(tx);
        mempool.removeConflicts(tx);
    }

    // Update best block in wallet (so we can detect restored wallets)
    if ((pindexNew->nHeight % 20160) == 0 || (!fIsInitialDownload && (pindexNew->nHeight % 144) == 0))
    {
        const CBlockLocator locator(pindexNew);
        ::SetBestChain(locator);
    }

    // New best block
    hashBestChain = pindexNew->GetBlockHash();
    pindexBest = pindexNew;
    pblockindexFBBHLast = NULL;
    nBestHeight = pindexBest->nHeight;
    nBestChainWork = pindexNew->nChainWork;
    nTimeBestReceived = GetTime();
    nTransactionsUpdated++;
    printf("SetBestChain: new best=%s  height=%d  log2_work=%.8g  tx=%lu  date=%s progress=%f\n",
      hashBestChain.ToString().c_str(), nBestHeight, log(nBestChainWork.getdouble())/log(2.0), (unsigned long)pindexNew->nChainTx,
      DateTimeStrFormat("%Y-%m-%d %H:%M:%S", pindexBest->GetBlockTime()).c_str(),
      Checkpoints::GuessVerificationProgress(pindexBest));

    // Check the version of the last 100 blocks to see if we need to upgrade:
    if (!fIsInitialDownload)
    {
        int nUpgraded = 0;
        const CBlockIndex* pindex = pindexBest;
        for (int i = 0; i < 100 && pindex != NULL; i++)
        {
            if (pindex->getVersion() > CBlock::CURRENT_VERSION)
                ++nUpgraded;
            pindex = pindex->pprev;
        }
        if (nUpgraded > 0)
            printf("SetBestChain: %d of last 100 blocks above version %d\n", nUpgraded, CBlock::CURRENT_VERSION);
        if (nUpgraded > 100/2)
            // strMiscWarning is read by GetWarnings(), called by Qt and the JSON-RPC code to warn the user:
            strMiscWarning = _("Warning: This version is obsolete, upgrade required!");
    }

    std::string strCmd = GetArg("-blocknotify", "");

    if (!fIsInitialDownload && !strCmd.empty())
    {
        boost::replace_all(strCmd, "%s", hashBestChain.GetHex());
        boost::thread t(runCommand, strCmd); // thread runs free
    }

    return true;
}


bool CBlock::AddToBlockIndex(CValidationState &state, const CDiskBlockPos &pos)
{
    // Check for duplicate
    uint256 hash = GetHash();
    if (mapBlockIndex.count(hash))
        return state.Invalid(error("AddToBlockIndex() : %s already exists", hash.ToString().c_str()));

    // Construct new block index object
    CBlockIndex* pindexNew = new CBlockIndex(*this);
    assert(pindexNew);
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.insert(make_pair(hash, pindexNew)).first;
    pindexNew->phashBlock = &((*mi).first);
    map<uint256, CBlockIndex*>::iterator miPrev = mapBlockIndex.find(hashPrevBlock);
    if (miPrev != mapBlockIndex.end())
    {
        pindexNew->pprev = (*miPrev).second;
        pindexNew->nHeight = pindexNew->pprev->nHeight + 1;
    }
    pindexNew->nTx = vtx.size();
    pindexNew->nChainWork = (pindexNew->pprev ? pindexNew->pprev->nChainWork : 0) + pindexNew->GetBlockWork().getuint256();
    pindexNew->nChainTx = (pindexNew->pprev ? pindexNew->pprev->nChainTx : 0) + pindexNew->nTx;
    pindexNew->nFile = pos.nFile;
    pindexNew->nDataPos = pos.nPos;
    pindexNew->nUndoPos = 0;
    pindexNew->nStatus = BLOCK_VALID_TRANSACTIONS | BLOCK_HAVE_DATA;
    setBlockIndexValid.insert(pindexNew);

    if (!pblocktree->WriteBlockIndex(CDiskBlockIndex(pindexNew)))
        return state.Abort(_("Failed to write block index"));

    // New best?
    if (!ConnectBestBlock(state))
        return false;

    if (pindexNew == pindexBest)
    {
        // Notify UI to display prev block's coinbase if it was ours
        static uint256 hashPrevBestCoinBase;
        UpdatedTransaction(hashPrevBestCoinBase);
        hashPrevBestCoinBase = GetTxHash(0);
    }

    if (!pblocktree->Flush())
        return state.Abort(_("Failed to sync block index"));

    uiInterface.NotifyBlocksChanged();
    return true;
}


bool FindBlockPos(CValidationState &state, CDiskBlockPos &pos, unsigned int nAddSize, unsigned int nHeight, uint64 nTime, bool fKnown = false)
{
    bool fUpdatedLast = false;

    LOCK(cs_LastBlockFile);

    if (fKnown) {
        if (nLastBlockFile != pos.nFile) {
            nLastBlockFile = pos.nFile;
            infoLastBlockFile.SetNull();
            pblocktree->ReadBlockFileInfo(nLastBlockFile, infoLastBlockFile);
            fUpdatedLast = true;
        }
    } else {
        while (infoLastBlockFile.nSize + nAddSize >= MAX_BLOCKFILE_SIZE) {
            printf("Leaving block file %i: %s\n", nLastBlockFile, infoLastBlockFile.ToString().c_str());
            FlushBlockFile(true);
            nLastBlockFile++;
            infoLastBlockFile.SetNull();
            pblocktree->ReadBlockFileInfo(nLastBlockFile, infoLastBlockFile); // check whether data for the new file somehow already exist; can fail just fine
            fUpdatedLast = true;
        }
        pos.nFile = nLastBlockFile;
        pos.nPos = infoLastBlockFile.nSize;
    }

    infoLastBlockFile.nSize += nAddSize;
    infoLastBlockFile.AddBlock(nHeight, nTime);

    if (!fKnown) {
        unsigned int nOldChunks = (pos.nPos + BLOCKFILE_CHUNK_SIZE - 1) / BLOCKFILE_CHUNK_SIZE;
        unsigned int nNewChunks = (infoLastBlockFile.nSize + BLOCKFILE_CHUNK_SIZE - 1) / BLOCKFILE_CHUNK_SIZE;
        if (nNewChunks > nOldChunks) {
            if (CheckDiskSpace(nNewChunks * BLOCKFILE_CHUNK_SIZE - pos.nPos)) {
                FILE *file = OpenBlockFile(pos);
                if (file) {
                    printf("Pre-allocating up to position 0x%x in blk%05u.dat\n", nNewChunks * BLOCKFILE_CHUNK_SIZE, pos.nFile);
                    AllocateFileRange(file, pos.nPos, nNewChunks * BLOCKFILE_CHUNK_SIZE - pos.nPos);
                    fclose(file);
                }
            }
            else
                return state.Error();
        }
    }

    if (!pblocktree->WriteBlockFileInfo(nLastBlockFile, infoLastBlockFile))
        return state.Abort(_("Failed to write file info"));
    if (fUpdatedLast)
        pblocktree->WriteLastBlockFile(nLastBlockFile);

    return true;
}

bool FindUndoPos(CValidationState &state, int nFile, CDiskBlockPos &pos, unsigned int nAddSize)
{
    pos.nFile = nFile;

    LOCK(cs_LastBlockFile);

    unsigned int nNewSize;
    if (nFile == nLastBlockFile) {
        pos.nPos = infoLastBlockFile.nUndoSize;
        nNewSize = (infoLastBlockFile.nUndoSize += nAddSize);
        if (!pblocktree->WriteBlockFileInfo(nLastBlockFile, infoLastBlockFile))
            return state.Abort(_("Failed to write block info"));
    } else {
        CBlockFileInfo info;
        if (!pblocktree->ReadBlockFileInfo(nFile, info))
            return state.Abort(_("Failed to read block info"));
        pos.nPos = info.nUndoSize;
        nNewSize = (info.nUndoSize += nAddSize);
        if (!pblocktree->WriteBlockFileInfo(nFile, info))
            return state.Abort(_("Failed to write block info"));
    }

    unsigned int nOldChunks = (pos.nPos + UNDOFILE_CHUNK_SIZE - 1) / UNDOFILE_CHUNK_SIZE;
    unsigned int nNewChunks = (nNewSize + UNDOFILE_CHUNK_SIZE - 1) / UNDOFILE_CHUNK_SIZE;
    if (nNewChunks > nOldChunks) {
        if (CheckDiskSpace(nNewChunks * UNDOFILE_CHUNK_SIZE - pos.nPos)) {
            FILE *file = OpenUndoFile(pos);
            if (file) {
                printf("Pre-allocating up to position 0x%x in rev%05u.dat\n", nNewChunks * UNDOFILE_CHUNK_SIZE, pos.nFile);
                AllocateFileRange(file, pos.nPos, nNewChunks * UNDOFILE_CHUNK_SIZE - pos.nPos);
                fclose(file);
            }
        }
        else
            return state.Error();
    }

    return true;
}


bool CBlock::CheckBlock(CValidationState &state, bool fCheckPOW, bool fCheckMerkleRoot) const
{
    // These are checks that are independent of context
    // that can be verified before saving an orphan block.

    // Size limits
    if (vtx.empty() || vtx.size() > MAX_BLOCK_SIZE || ::GetSerializeSize(*this, SER_NETWORK, PROTOCOL_VERSION) > MAX_BLOCK_SIZE)
        return state.DoS(100, error("CheckBlock() : size limits failed"));

    // Special short-term limits to avoid 10,000 BDB lock limit:
    if (GetBlockTime() >= 1363867200 && // start enforcing 21 March 2013, noon GMT
        GetBlockTime() < 1368576000)  // stop enforcing 15 May 2013 00:00:00
    {
        // Rule is: #unique txids referenced <= 4,500
        // ... to prevent 10,000 BDB lock exhaustion on old clients
        set<uint256> setTxIn;
        for (size_t i = 0; i < vtx.size(); i++)
        {
            setTxIn.insert(vtx[i].GetHash());
            if (i == 0) continue; // skip coinbase txin
            BOOST_FOREACH(const CTxIn& txin, vtx[i].vin)
                setTxIn.insert(txin.prevout.hash);
        }
        size_t nTxids = setTxIn.size();
        if (nTxids > 4500)
            return error("CheckBlock() : 15 May maxlocks violation");
    }

    // Check proof of work matches claimed amount
    if (fCheckPOW && !CheckProofOfWork(GetHash(), nBits))
        return state.DoS(50, error("CheckBlock() : proof of work failed"));

    // Check timestamp
    if (GetBlockTime() > GetAdjustedTime() + 2 * 60 * 60)
        return state.Invalid(error("CheckBlock() : block timestamp too far in the future"));

    // First transaction must be coinbase, the rest must not be
    if (vtx.empty() || !vtx[0].IsCoinBase())
        return state.DoS(100, error("CheckBlock() : first tx is not coinbase"));
    if (GetHash() != hashGenesisBlock) { // Genesis may have multiple coinbases
        for (unsigned int i = 1; i < vtx.size(); i++)
            if (vtx[i].IsCoinBase())
                return state.DoS(100, error("CheckBlock() : more than one coinbase"));
    }

    // Check transactions
    BOOST_FOREACH(const CTransaction& tx, vtx)
        if (!tx.CheckTransaction(state))
            return error("CheckBlock() : CheckTransaction failed");

    // Build the merkle tree already. We need it anyway later, and it makes the
    // block cache the transaction hashes, which means they don't need to be
    // recalculated many times during this block's validation.
    BuildMerkleTree();

    // Check for duplicate txids. This is caught by ConnectInputs(),
    // but catching it earlier avoids a potential DoS attack:
    set<uint256> uniqueTx;
    for (unsigned int i=0; i<vtx.size(); i++) {
        uniqueTx.insert(GetTxHash(i));
    }
    if (uniqueTx.size() != vtx.size())
        return state.DoS(100, error("CheckBlock() : duplicate transaction"));

    unsigned int nSigOps = 0;
    BOOST_FOREACH(const CTransaction& tx, vtx)
    {
        nSigOps += tx.GetLegacySigOpCount();
    }
    if (nSigOps > MAX_BLOCK_SIGOPS)
        return state.DoS(100, error("CheckBlock() : out-of-bounds SigOpCount"));

    // Check merkle root
    if (fCheckMerkleRoot && hashMerkleRoot != BuildMerkleTree())
        return state.DoS(100, error("CheckBlock() : hashMerkleRoot mismatch"));

    return true;
}

bool CBlock::AcceptBlock(CValidationState &state, CDiskBlockPos *dbp)
{
    // Check for duplicate
    uint256 hash = GetHash();
    if (mapBlockIndex.count(hash))
        return state.Invalid(error("AcceptBlock() : block already in mapBlockIndex"));

    // Get prev block index
    CBlockIndex* pindexPrev = NULL;
    int nHeight = 0;
    if (hash != hashGenesisBlock) {
        map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashPrevBlock);
        if (mi == mapBlockIndex.end())
            return state.DoS(10, error("AcceptBlock() : prev block not found"));
        pindexPrev = (*mi).second;
        nHeight = pindexPrev->nHeight+1;

        // Check proof of work
        if (nBits != GetNextWorkRequired(pindexPrev, this))
            return state.DoS(100, error("AcceptBlock() : incorrect proof of work"));

        // Check block vote
        if (nVote > nBlockRewardVoteLimit)
            return state.DoS(100, error("AcceptBlock() : incorrect block reward vote"));

        // Check block reward
        if (nReward != GetCurrentBlockReward(pindexPrev))
            return state.DoS(100, error("AcceptBlock() : incorrect block reward"));

        // Check supply
        if (getSupply() != pindexPrev->getSupply() + GetCurrentBlockReward(pindexPrev))
            return state.DoS(100, error("AcceptBlock() : incorrect block reward (supply check)"));

        // Check max possible supply
        if (nReward + pindexPrev->getSupply() > MAX_MONEY/COIN)
            return state.DoS(100, error("AcceptBlock() : incorrect block reward (exceeds max possible money)"));

        // Check max supply
        if (nReward + pindexPrev->getSupply() > nMaxSupply)
            return state.DoS(100, error("AcceptBlock() : incorrect block reward (exceeds max money)"));

        // Check timestamp against prev
        if (GetBlockTime() <= pindexPrev->GetMedianTimePast())
            return state.Invalid(error("AcceptBlock() : block's timestamp is too early"));

        // Check that all transactions are finalized
        BOOST_FOREACH(const CTransaction& tx, vtx)
            if (!tx.IsFinal(nHeight, GetBlockTime()))
                return state.DoS(10, error("AcceptBlock() : contains a non-final transaction"));

        // Check that the block chain matches the known block chain up to a checkpoint
        if (!Checkpoints::CheckBlock(nHeight, hash))
            return state.DoS(100, error("AcceptBlock() : rejected by checkpoint lock-in at %d", nHeight));

        // Reject block.nVersion=1 blocks when 95% (75% on testnet) of the network has upgraded:
        if (getVersion() < 2)
        {
            if ((!fTestNet && CBlockIndex::IsSuperMajority(2, pindexPrev, 950, 1000)) ||
                (fTestNet && CBlockIndex::IsSuperMajority(2, pindexPrev, 75, 100)))
            {
                return state.Invalid(error("AcceptBlock() : rejected nVersion=1 block"));
            }
        }
        // Enforce block.nVersion=2 rule that the coinbase starts with serialized block height
        if (getVersion() >= 2)
        {
            // if 750 of the last 1,000 blocks are version 2 or greater (51/100 if testnet):
            if ((!fTestNet && CBlockIndex::IsSuperMajority(2, pindexPrev, 750, 1000)) ||
                (fTestNet && CBlockIndex::IsSuperMajority(2, pindexPrev, 51, 100)))
            {
                CScript expect = CScript() << nHeight;
                if (!std::equal(expect.begin(), expect.end(), vtx[0].vin[0].scriptSig.begin()))
                    return state.DoS(100, error("AcceptBlock() : block height mismatch in coinbase"));
            }
        }
    }

    // Write block to history file
    try {
        unsigned int nBlockSize = ::GetSerializeSize(*this, SER_DISK, CLIENT_VERSION);
        CDiskBlockPos blockPos;
        if (dbp != NULL)
            blockPos = *dbp;
        if (!FindBlockPos(state, blockPos, nBlockSize+8, nHeight, nTime, dbp != NULL))
            return error("AcceptBlock() : FindBlockPos failed");
        if (dbp == NULL)
            if (!WriteToDisk(blockPos))
                return state.Abort(_("Failed to write block"));
        if (!AddToBlockIndex(state, blockPos))
            return error("AcceptBlock() : AddToBlockIndex failed");
    } catch(std::runtime_error &e) {
        return state.Abort(_("System error: ") + e.what());
    }

    // Relay inventory, but don't relay old inventory during initial block download
    int nBlockEstimate = Checkpoints::GetTotalBlocksEstimate();
    if (hashBestChain == hash)
    {
        LOCK(cs_vNodes);
        BOOST_FOREACH(CNode* pnode, vNodes)
            if (nBestHeight > (pnode->nStartingHeight != -1 ? pnode->nStartingHeight - 2000 : nBlockEstimate))
                pnode->PushInventory(CInv(MSG_BLOCK, hash));
    }

    return true;
}

bool CBlockIndex::IsSuperMajority(int minVersion, const CBlockIndex* pstart, unsigned int nRequired, unsigned int nToCheck)
{
    unsigned int nFound = 0;
    for (unsigned int i = 0; i < nToCheck && nFound < nRequired && pstart != NULL; i++)
    {
        if (pstart->nVersion >= minVersion)
            ++nFound;
        pstart = pstart->pprev;
    }
    return (nFound >= nRequired);
}

bool ProcessBlock(CValidationState &state, CNode* pfrom, CBlock* pblock, CDiskBlockPos *dbp)
{
    // Check for duplicate
    uint256 hash = pblock->GetHash();
    if (mapBlockIndex.count(hash))
        return state.Invalid(error("ProcessBlock() : already have block %d %s", mapBlockIndex[hash]->nHeight, hash.ToString().c_str()));
    if (mapOrphanBlocks.count(hash))
        return state.Invalid(error("ProcessBlock() : already have block (orphan) %s", hash.ToString().c_str()));

    // Preliminary checks
    if (!pblock->CheckBlock(state))
        return error("ProcessBlock() : CheckBlock FAILED");

    CBlockIndex* pcheckpoint = Checkpoints::GetLastCheckpoint(mapBlockIndex);
    if (pcheckpoint && pblock->hashPrevBlock != hashBestChain)
    {
        // Extra checks to prevent "fill up memory by spamming with bogus blocks"
        int64 deltaTime = pblock->GetBlockTime() - pcheckpoint->nTime;
        if (deltaTime < 0)
        {
            return state.DoS(100, error("ProcessBlock() : block with timestamp before last checkpoint"));
        }

        CBigNum bnNewBlock;
        bnNewBlock.SetCompact(pblock->nBits);
        CBigNum bnRequired;
        bnRequired.SetCompact(ComputeMinWork(pcheckpoint->nBits, deltaTime));
        if (bnNewBlock > bnRequired)
        {
            return state.DoS(100, error("ProcessBlock() : block with too little proof-of-work"));
        }
    }


    // If we don't already have its previous block, shunt it off to holding area until we get it
    if (pblock->hashPrevBlock != 0 && !mapBlockIndex.count(pblock->hashPrevBlock))
    {
        printf("ProcessBlock: ORPHAN BLOCK, prev=%s\n", pblock->hashPrevBlock.ToString().c_str());

        // Accept orphans as long as there is a node to request its parents from
        if (pfrom) {
            CBlock* pblock2 = new CBlock(*pblock);
            mapOrphanBlocks.insert(make_pair(hash, pblock2));
            mapOrphanBlocksByPrev.insert(make_pair(pblock2->hashPrevBlock, pblock2));

            // Ask this guy to fill in what we're missing
            pfrom->PushGetBlocks(pindexBest, GetOrphanRoot(pblock2));
        }
        return true;
    }

    // Store to disk
    if (!pblock->AcceptBlock(state, dbp))
        return error("ProcessBlock() : AcceptBlock FAILED");

    // Recursively process any orphan blocks that depended on this one
    vector<uint256> vWorkQueue;
    vWorkQueue.push_back(hash);
    for (unsigned int i = 0; i < vWorkQueue.size(); i++)
    {
        uint256 hashPrev = vWorkQueue[i];
        for (multimap<uint256, CBlock*>::iterator mi = mapOrphanBlocksByPrev.lower_bound(hashPrev);
             mi != mapOrphanBlocksByPrev.upper_bound(hashPrev);
             ++mi)
        {
            CBlock* pblockOrphan = (*mi).second;
            // Use a dummy CValidationState so someone can't setup nodes to counter-DoS based on orphan resolution (that is, feeding people an invalid block based on LegitBlockX in order to get anyone relaying LegitBlockX banned)
            CValidationState stateDummy;
            if (pblockOrphan->AcceptBlock(stateDummy))
                vWorkQueue.push_back(pblockOrphan->GetHash());
            mapOrphanBlocks.erase(pblockOrphan->GetHash());
            delete pblockOrphan;
        }
        mapOrphanBlocksByPrev.erase(hashPrev);
    }

    printf("ProcessBlock: ACCEPTED\n");
    return true;
}








CMerkleBlock::CMerkleBlock(const CBlock& block, CBloomFilter& filter)
{
    header = block.GetBlockHeader();

    vector<bool> vMatch;
    vector<uint256> vHashes;

    vMatch.reserve(block.vtx.size());
    vHashes.reserve(block.vtx.size());

    for (unsigned int i = 0; i < block.vtx.size(); i++)
    {
        uint256 hash = block.vtx[i].GetHash();
        if (filter.IsRelevantAndUpdate(block.vtx[i], hash))
        {
            vMatch.push_back(true);
            vMatchedTxn.push_back(make_pair(i, hash));
        }
        else
            vMatch.push_back(false);
        vHashes.push_back(hash);
    }

    txn = CPartialMerkleTree(vHashes, vMatch);
}








uint256 CPartialMerkleTree::CalcHash(int height, unsigned int pos, const std::vector<uint256> &vTxid) {
    if (height == 0) {
        // hash at height 0 is the txids themself
        return vTxid[pos];
    } else {
        // calculate left hash
        uint256 left = CalcHash(height-1, pos*2, vTxid), right;
        // calculate right hash if not beyong the end of the array - copy left hash otherwise1
        if (pos*2+1 < CalcTreeWidth(height-1))
            right = CalcHash(height-1, pos*2+1, vTxid);
        else
            right = left;
        // combine subhashes
        return Hash(BEGIN(left), END(left), BEGIN(right), END(right));
    }
}

void CPartialMerkleTree::TraverseAndBuild(int height, unsigned int pos, const std::vector<uint256> &vTxid, const std::vector<bool> &vMatch) {
    // determine whether this node is the parent of at least one matched txid
    bool fParentOfMatch = false;
    for (unsigned int p = pos << height; p < (pos+1) << height && p < nTransactions; p++)
        fParentOfMatch |= vMatch[p];
    // store as flag bit
    vBits.push_back(fParentOfMatch);
    if (height==0 || !fParentOfMatch) {
        // if at height 0, or nothing interesting below, store hash and stop
        vHash.push_back(CalcHash(height, pos, vTxid));
    } else {
        // otherwise, don't store any hash, but descend into the subtrees
        TraverseAndBuild(height-1, pos*2, vTxid, vMatch);
        if (pos*2+1 < CalcTreeWidth(height-1))
            TraverseAndBuild(height-1, pos*2+1, vTxid, vMatch);
    }
}

uint256 CPartialMerkleTree::TraverseAndExtract(int height, unsigned int pos, unsigned int &nBitsUsed, unsigned int &nHashUsed, std::vector<uint256> &vMatch) {
    if (nBitsUsed >= vBits.size()) {
        // overflowed the bits array - failure
        fBad = true;
        return 0;
    }
    bool fParentOfMatch = vBits[nBitsUsed++];
    if (height==0 || !fParentOfMatch) {
        // if at height 0, or nothing interesting below, use stored hash and do not descend
        if (nHashUsed >= vHash.size()) {
            // overflowed the hash array - failure
            fBad = true;
            return 0;
        }
        const uint256 &hash = vHash[nHashUsed++];
        if (height==0 && fParentOfMatch) // in case of height 0, we have a matched txid
            vMatch.push_back(hash);
        return hash;
    } else {
        // otherwise, descend into the subtrees to extract matched txids and hashes
        uint256 left = TraverseAndExtract(height-1, pos*2, nBitsUsed, nHashUsed, vMatch), right;
        if (pos*2+1 < CalcTreeWidth(height-1))
            right = TraverseAndExtract(height-1, pos*2+1, nBitsUsed, nHashUsed, vMatch);
        else
            right = left;
        // and combine them before returning
        return Hash(BEGIN(left), END(left), BEGIN(right), END(right));
    }
}

CPartialMerkleTree::CPartialMerkleTree(const std::vector<uint256> &vTxid, const std::vector<bool> &vMatch) : nTransactions(vTxid.size()), fBad(false) {
    // reset state
    vBits.clear();
    vHash.clear();

    // calculate height of tree
    int nHeight = 0;
    while (CalcTreeWidth(nHeight) > 1)
        nHeight++;

    // traverse the partial tree
    TraverseAndBuild(nHeight, 0, vTxid, vMatch);
}

CPartialMerkleTree::CPartialMerkleTree() : nTransactions(0), fBad(true) {}

uint256 CPartialMerkleTree::ExtractMatches(std::vector<uint256> &vMatch) {
    vMatch.clear();
    // An empty set will not work
    if (nTransactions == 0)
        return 0;
    // check for excessively high numbers of transactions
    if (nTransactions > MAX_BLOCK_SIZE / 60) // 60 is the lower bound for the size of a serialized CTransaction
        return 0;
    // there can never be more hashes provided than one for every txid
    if (vHash.size() > nTransactions)
        return 0;
    // there must be at least one bit per node in the partial tree, and at least one node per hash
    if (vBits.size() < vHash.size())
        return 0;
    // calculate height of tree
    int nHeight = 0;
    while (CalcTreeWidth(nHeight) > 1)
        nHeight++;
    // traverse the partial tree
    unsigned int nBitsUsed = 0, nHashUsed = 0;
    uint256 hashMerkleRoot = TraverseAndExtract(nHeight, 0, nBitsUsed, nHashUsed, vMatch);
    // verify that no problems occured during the tree traversal
    if (fBad)
        return 0;
    // verify that all bits were consumed (except for the padding caused by serializing it as a byte sequence)
    if ((nBitsUsed+7)/8 != (vBits.size()+7)/8)
        return 0;
    // verify that all hashes were consumed
    if (nHashUsed != vHash.size())
        return 0;
    return hashMerkleRoot;
}







bool AbortNode(const std::string &strMessage) {
    strMiscWarning = strMessage;
    printf("*** %s\n", strMessage.c_str());
    uiInterface.ThreadSafeMessageBox(strMessage, "", CClientUIInterface::MSG_ERROR);
    StartShutdown();
    return false;
}

bool CheckDiskSpace(uint64 nAdditionalBytes)
{
    uint64 nFreeBytesAvailable = filesystem::space(GetDataDir()).available;

    // Check for nMinDiskSpace bytes (currently 50MB)
    if (nFreeBytesAvailable < nMinDiskSpace + nAdditionalBytes)
        return AbortNode(_("Error: Disk space is low!"));

    return true;
}

CCriticalSection cs_LastBlockFile;
CBlockFileInfo infoLastBlockFile;
int nLastBlockFile = 0;

FILE* OpenDiskFile(const CDiskBlockPos &pos, const char *prefix, bool fReadOnly)
{
    if (pos.IsNull())
        return NULL;
    boost::filesystem::path path = GetDataDir() / "blocks" / strprintf("%s%05u.dat", prefix, pos.nFile);
    boost::filesystem::create_directories(path.parent_path());
    FILE* file = fopen(path.string().c_str(), "rb+");
    if (!file && !fReadOnly)
        file = fopen(path.string().c_str(), "wb+");
    if (!file) {
        printf("Unable to open file %s\n", path.string().c_str());
        return NULL;
    }
    if (pos.nPos) {
        if (fseek(file, pos.nPos, SEEK_SET)) {
            printf("Unable to seek to position %u of %s\n", pos.nPos, path.string().c_str());
            fclose(file);
            return NULL;
        }
    }
    return file;
}

FILE* OpenBlockFile(const CDiskBlockPos &pos, bool fReadOnly) {
    return OpenDiskFile(pos, "blk", fReadOnly);
}

FILE* OpenUndoFile(const CDiskBlockPos &pos, bool fReadOnly) {
    return OpenDiskFile(pos, "rev", fReadOnly);
}

CBlockIndex * InsertBlockIndex(uint256 hash)
{
    if (hash == 0)
        return NULL;

    // Return existing
    map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hash);
    if (mi != mapBlockIndex.end())
        return (*mi).second;

    // Create new
    CBlockIndex* pindexNew = new CBlockIndex();
    if (!pindexNew)
        throw runtime_error("LoadBlockIndex() : new CBlockIndex failed");
    mi = mapBlockIndex.insert(make_pair(hash, pindexNew)).first;
    pindexNew->phashBlock = &((*mi).first);

    return pindexNew;
}

bool static LoadBlockIndexDB()
{
    if (!pblocktree->LoadBlockIndexGuts())
        return false;

    boost::this_thread::interruption_point();

    // Calculate nChainWork
    vector<pair<int, CBlockIndex*> > vSortedByHeight;
    vSortedByHeight.reserve(mapBlockIndex.size());
    BOOST_FOREACH(const PAIRTYPE(uint256, CBlockIndex*)& item, mapBlockIndex)
    {
        CBlockIndex* pindex = item.second;
        vSortedByHeight.push_back(make_pair(pindex->nHeight, pindex));
    }
    sort(vSortedByHeight.begin(), vSortedByHeight.end());
    BOOST_FOREACH(const PAIRTYPE(int, CBlockIndex*)& item, vSortedByHeight)
    {
        CBlockIndex* pindex = item.second;
        pindex->nChainWork = (pindex->pprev ? pindex->pprev->nChainWork : 0) + pindex->GetBlockWork().getuint256();
        pindex->nChainTx = (pindex->pprev ? pindex->pprev->nChainTx : 0) + pindex->nTx;
        if ((pindex->nStatus & BLOCK_VALID_MASK) >= BLOCK_VALID_TRANSACTIONS && !(pindex->nStatus & BLOCK_FAILED_MASK))
            setBlockIndexValid.insert(pindex);
    }

    // Load block file info
    pblocktree->ReadLastBlockFile(nLastBlockFile);
    printf("LoadBlockIndexDB(): last block file = %i\n", nLastBlockFile);
    if (pblocktree->ReadBlockFileInfo(nLastBlockFile, infoLastBlockFile))
        printf("LoadBlockIndexDB(): last block file info: %s\n", infoLastBlockFile.ToString().c_str());

    // Load nBestInvalidWork, OK if it doesn't exist
    CBigNum bnBestInvalidWork;
    pblocktree->ReadBestInvalidWork(bnBestInvalidWork);
    nBestInvalidWork = bnBestInvalidWork.getuint256();

    // Check whether we need to continue reindexing
    bool fReindexing = false;
    pblocktree->ReadReindexing(fReindexing);
    fReindex |= fReindexing;

    // Check whether we have a transaction index
    pblocktree->ReadFlag("txindex", fTxIndex);
    printf("LoadBlockIndexDB(): transaction index %s\n", fTxIndex ? "enabled" : "disabled");

    // Load hashBestChain pointer to end of best chain
    pindexBest = pcoinsTip->GetBestBlock();
    if (pindexBest == NULL)
        return true;
    hashBestChain = pindexBest->GetBlockHash();
    nBestHeight = pindexBest->nHeight;
    nBestChainWork = pindexBest->nChainWork;

    // set 'next' pointers in best chain
    CBlockIndex *pindex = pindexBest;
    while(pindex != NULL && pindex->pprev != NULL) {
         CBlockIndex *pindexPrev = pindex->pprev;
         pindexPrev->pnext = pindex;
         pindex = pindexPrev;
    }
    printf("LoadBlockIndexDB(): hashBestChain=%s  height=%d date=%s\n",
        hashBestChain.ToString().c_str(), nBestHeight,
        DateTimeStrFormat("%Y-%m-%d %H:%M:%S", pindexBest->GetBlockTime()).c_str());

    return true;
}

bool VerifyDB() {
    if (pindexBest == NULL || pindexBest->pprev == NULL)
        return true;

    // Verify blocks in the best chain
    int nCheckLevel = GetArg("-checklevel", 3);
    int nCheckDepth = GetArg( "-checkblocks", 288);
    if (nCheckDepth == 0)
        nCheckDepth = 1000000000; // suffices until the year 19000
    if (nCheckDepth > nBestHeight)
        nCheckDepth = nBestHeight;
    nCheckLevel = std::max(0, std::min(4, nCheckLevel));
    printf("Verifying last %i blocks at level %i\n", nCheckDepth, nCheckLevel);
    CCoinsViewCache coins(*pcoinsTip, true);
    CBlockIndex* pindexState = pindexBest;
    CBlockIndex* pindexFailure = NULL;
    int nGoodTransactions = 0;
    CValidationState state;
    for (CBlockIndex* pindex = pindexBest; pindex && pindex->pprev; pindex = pindex->pprev)
    {
        boost::this_thread::interruption_point();
        if (pindex->nHeight < nBestHeight-nCheckDepth)
            break;
        CBlock block;
        // check level 0: read from disk
        if (!block.ReadFromDisk(pindex))
            return error("VerifyDB() : *** block.ReadFromDisk failed at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString().c_str());
        // check level 1: verify block validity
        if (nCheckLevel >= 1 && !block.CheckBlock(state))
            return error("VerifyDB() : *** found bad block at %d, hash=%s\n", pindex->nHeight, pindex->GetBlockHash().ToString().c_str());
        // check level 2: verify undo validity
        if (nCheckLevel >= 2 && pindex) {
            CBlockUndo undo;
            CDiskBlockPos pos = pindex->GetUndoPos();
            if (!pos.IsNull()) {
                if (!undo.ReadFromDisk(pos, pindex->pprev->GetBlockHash()))
                    return error("VerifyDB() : *** found bad undo data at %d, hash=%s\n", pindex->nHeight, pindex->GetBlockHash().ToString().c_str());
            }
        }
        // check level 3: check for inconsistencies during memory-only disconnect of tip blocks
        if (nCheckLevel >= 3 && pindex == pindexState && (coins.GetCacheSize() + pcoinsTip->GetCacheSize()) <= 2*nCoinCacheSize + 32000) {
            bool fClean = true;
            if (!block.DisconnectBlock(state, pindex, coins, &fClean))
                return error("VerifyDB() : *** irrecoverable inconsistency in block data at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString().c_str());
            pindexState = pindex->pprev;
            if (!fClean) {
                nGoodTransactions = 0;
                pindexFailure = pindex;
            } else
                nGoodTransactions += block.vtx.size();
        }
    }
    if (pindexFailure)
        return error("VerifyDB() : *** coin database inconsistencies found (last %i blocks, %i good transactions before that)\n", pindexBest->nHeight - pindexFailure->nHeight + 1, nGoodTransactions);

    // check level 4: try reconnecting blocks
    if (nCheckLevel >= 4) {
        CBlockIndex *pindex = pindexState;
        while (pindex != pindexBest) {
            boost::this_thread::interruption_point();
            pindex = pindex->pnext;
            CBlock block;
            if (!block.ReadFromDisk(pindex))
                return error("VerifyDB() : *** block.ReadFromDisk failed at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString().c_str());
            if (!block.ConnectBlock(state, pindex, coins))
                return error("VerifyDB() : *** found unconnectable block at %d, hash=%s", pindex->nHeight, pindex->GetBlockHash().ToString().c_str());
        }
    }

    printf("No coin database inconsistencies in last %i blocks (%i transactions)\n", pindexBest->nHeight - pindexState->nHeight, nGoodTransactions);

    return true;
}

void UnloadBlockIndex()
{
    mapBlockIndex.clear();
    setBlockIndexValid.clear();
    pindexGenesisBlock = NULL;
    nBestHeight = 0;
    nBestChainWork = 0;
    nBestInvalidWork = 0;
    hashBestChain = 0;
    pindexBest = NULL;
}

bool LoadBlockIndex()
{
    if (fTestNet)
    {
        pchMessageStart[0] = 0x0b;
        pchMessageStart[1] = 0x11;
        pchMessageStart[2] = 0x09;
        pchMessageStart[3] = 0x07;
        hashGenesisBlock = uint256("0x000019c52ec022481459cca4397f9e103d3d1832a14533a7194423adace0e0d1");
    }

    //
    // Load block index from databases
    //
    if (!fReindex && !LoadBlockIndexDB())
        return false;

    return true;
}


bool InitBlockIndex() {
    // Check whether we're already initialized
    if (pindexGenesisBlock != NULL)
        return true;

    // Use the provided setting for -txindex in the new database
    fTxIndex = GetBoolArg("-txindex", false);
    pblocktree->WriteFlag("txindex", fTxIndex);
    printf("Initializing databases...\n");

    // Only add the genesis block if not reindexing (in which case we reuse the one already on disk)
    if (!fReindex) {
        // Genesis Block:
        // CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
        //   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
        //     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
        //     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
        //   vMerkleTree: 4a5e1e

        // Genesis block
        const char* pszTimestamp = "BTC tx cf3bf21b50cfa59a008a1f6b1fca7293940a9cb1fd317dd3d6c8ebafa58fcc53 2014-03-08 10:06:26";
        CTransaction txNew[179];

        txNew[0].vin.resize(1);
        txNew[0].vout.resize(1);
        txNew[0].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[0].vout[0].nValue = 28760.79686627 * COIN;
        txNew[0].vout[0].scriptPubKey = CScript() << ParseHex("0434374dec40a10ed26d0e09f9e214c33eeb60f29cba3ebe0e6fe8fe9deaf972b1947020491be6cd51a5e199ee9cc39ef35ec17131c44cdc537f85625810a2d4a3") << OP_CHECKSIG;

        txNew[1].vin.resize(1);
        txNew[1].vout.resize(1);
        txNew[1].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[1].vout[0].nValue = 28760.79686627 * COIN;
        txNew[1].vout[0].scriptPubKey = CScript() << ParseHex("0481b663eb18b875091d8f71b44d32d325e374fc7bd1aa785072124a5adc9c88f9fca53ed79cd796a61ebbc4f20ad4ecf41a6eff6bf5f4f3a84aed521cd94f29d4") << OP_CHECKSIG;

        txNew[2].vin.resize(1);
        txNew[2].vout.resize(1);
        txNew[2].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[2].vout[0].nValue = 63273.7531058 * COIN;
        txNew[2].vout[0].scriptPubKey = CScript() << ParseHex("04506de84205025cd32a711e90486a33d0971cb4aab3f689e261ca60d56c7ade4857949cc90daeadfac03dba88c4e6d9c001901d8ebc4bad0d48fb2ac30a397396") << OP_CHECKSIG;

        txNew[3].vin.resize(1);
        txNew[3].vout.resize(1);
        txNew[3].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[3].vout[0].nValue = 57521.59373255 * COIN;
        txNew[3].vout[0].scriptPubKey = CScript() << ParseHex("04122ab9b83f0b960a8391b2983b5401a9d4385a74af28ebcb5f7bbd269c137bd9c5355b147db1640c5c2b496d80b3e0498ff3b07de98c480444862437b68460eb") << OP_CHECKSIG;

        txNew[4].vin.resize(1);
        txNew[4].vout.resize(1);
        txNew[4].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[4].vout[0].nValue = 32528.46125576 * COIN;
        txNew[4].vout[0].scriptPubKey = CScript() << ParseHex("0457946931a8ea01f120d9df57230c3cf5cf18b8ff68572cf6914b6420e48f79b88fd8d45fb7f7d197f0a090507101215a6d467d342d2d4f814adc5a54a7e79c35") << OP_CHECKSIG;

        txNew[5].vin.resize(1);
        txNew[5].vout.resize(1);
        txNew[5].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[5].vout[0].nValue = 6586.22248238 * COIN;
        txNew[5].vout[0].scriptPubKey = CScript() << ParseHex("0410de30c0489d922da0c1ca805565f139730cd9b69bded0f3378e9dfe7ac277bf48002e9f014d6084cf1074d2994033ad4c11dd0f7b9f8e5bfb4a723d82a1e675") << OP_CHECKSIG;

        txNew[6].vin.resize(1);
        txNew[6].vout.resize(1);
        txNew[6].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[6].vout[0].nValue = 8628.23905988 * COIN;
        txNew[6].vout[0].scriptPubKey = CScript() << ParseHex("04e542e7856f1427942f550acb028ef68a13e42d7380c1bb1554279cf68410aac6770bc6b2fe7db863c3718aea989ce5d53d586f7be5f086a58b897adc1198ef7f") << OP_CHECKSIG;

        txNew[7].vin.resize(1);
        txNew[7].vout.resize(1);
        txNew[7].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[7].vout[0].nValue = 7190.19921657 * COIN;
        txNew[7].vout[0].scriptPubKey = CScript() << ParseHex("04f2af866c7dacc894381ef0b2ef69eb2e391d9ab589143d5d494e630a4978629ab66540f92e327c35e21f0fd4bbd877fe5979a386e7946e4bd2839d6f5c9b8c34") << OP_CHECKSIG;

        txNew[8].vin.resize(1);
        txNew[8].vout.resize(1);
        txNew[8].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[8].vout[0].nValue = 1438.03984331 * COIN;
        txNew[8].vout[0].scriptPubKey = CScript() << ParseHex("047c227a9ca0ed31ab1f30821dc92e4712f47f791fb8118bae8d52b66d444bf4208cbbebdad1fce451297502f1c744376dd43165248ee7cf4aad316132306ac43c") << OP_CHECKSIG;

        txNew[9].vin.resize(1);
        txNew[9].vout.resize(1);
        txNew[9].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[9].vout[0].nValue = 1668.12621824 * COIN;
        txNew[9].vout[0].scriptPubKey = CScript() << ParseHex("0482e0f289223082f255fcb7aafb852dda1743f92922f30089f0d806d8d59da3cefd682e2639cac1dc0fc728d2115ccd70729ba9d9cb09ded19ebadcb5ac52c538") << OP_CHECKSIG;

        txNew[10].vin.resize(1);
        txNew[10].vout.resize(1);
        txNew[10].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[10].vout[0].nValue = 10641.49484052 * COIN;
        txNew[10].vout[0].scriptPubKey = CScript() << ParseHex("04488b734534668ca6155436bdf021f0c431b58c6b0cc7527ce62dd0bc8b8be320789e6368920350014459278bb3eb9c755ddd90ba9f02477adbf86d3029675aba") << OP_CHECKSIG;

        txNew[11].vin.resize(1);
        txNew[11].vout.resize(1);
        txNew[11].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[11].vout[0].nValue = 5737.77897482 * COIN;
        txNew[11].vout[0].scriptPubKey = CScript() << ParseHex("046947fe6f5535802dd8eec0c4a2b4ec18b1cf75c9b797dc543fdae9fc6f2205cf8e0608fbcb5238e98efdc94beec68fade5aede52a9f8c5de5bc7397a04564f3a") << OP_CHECKSIG;

        txNew[12].vin.resize(1);
        txNew[12].vout.resize(1);
        txNew[12].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[12].vout[0].nValue = 25597.10921098 * COIN;
        txNew[12].vout[0].scriptPubKey = CScript() << ParseHex("04bbf608ffdf698690cb44ee72d66fd82c50564767d29680d5ecf6985771b8d11a962f8fbeca2ca21a2aeabac98dbc53f33757e283de34dcba58b5caeb738ad5c5") << OP_CHECKSIG;

        txNew[13].vin.resize(1);
        txNew[13].vout.resize(1);
        txNew[13].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[13].vout[0].nValue = 3480.05642082 * COIN;
        txNew[13].vout[0].scriptPubKey = CScript() << ParseHex("0483e631640981c765e4e5a34d3138e000b43c17ff181427ba6f74a89597f4a8e2664623672e5e3ab8f9596c38c9f61e6d943efcad5bb3433a44657837db49de30") << OP_CHECKSIG;

        txNew[14].vin.resize(1);
        txNew[14].vout.resize(1);
        txNew[14].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[14].vout[0].nValue = 5283.35838433 * COIN;
        txNew[14].vout[0].scriptPubKey = CScript() << ParseHex("0404790163471e1121bcce870567f3331feb787603f3d26939a1aebc975052897cdad6fa4aa9850bb30beefcde7fb686a130bab870c8dbc1861d49112d5bf09859") << OP_CHECKSIG;

        txNew[15].vin.resize(1);
        txNew[15].vout.resize(1);
        txNew[15].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[15].vout[0].nValue = 7190.19921657 * COIN;
        txNew[15].vout[0].scriptPubKey = CScript() << ParseHex("044a043444f9127df71006e423034e0ad3a63ab1b77da28a80b47e273eefc5e8712f3a6c6ca7823e71155593ab76278815bbee3d73228c432d5eacdee6e0f41eba") << OP_CHECKSIG;

        txNew[16].vin.resize(1);
        txNew[16].vout.resize(1);
        txNew[16].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[16].vout[0].nValue = 4711.24084766 * COIN;
        txNew[16].vout[0].scriptPubKey = CScript() << ParseHex("04d290468d5931f2fea8f77535e7764991dfceffdddc2cb4f76f5970e2eb01d830c0a327a0dc4ad55273dbe8d00bd7fe24215b0fd4dce91637551038d1639477a1") << OP_CHECKSIG;

        txNew[17].vin.resize(1);
        txNew[17].vout.resize(1);
        txNew[17].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[17].vout[0].nValue = 1438.03984331 * COIN;
        txNew[17].vout[0].scriptPubKey = CScript() << ParseHex("045fdf3a1602be579761ca5c3f1e6104a18c684a1474f05eb96ce505d9acca83390eaf888f688249de9d6054b753182a4b9387560dc239352b618beea5da2d1148") << OP_CHECKSIG;

        txNew[18].vin.resize(1);
        txNew[18].vout.resize(1);
        txNew[18].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[18].vout[0].nValue = 7889.08658042 * COIN;
        txNew[18].vout[0].scriptPubKey = CScript() << ParseHex("049cb411a156f8480d82176c1a9a64940447b16220edd44502c4f79ff79a9019947183b73894b57bf6aba99f99aa16709914b7b2f9cb71f431aa5b463089581dda") << OP_CHECKSIG;

        txNew[19].vin.resize(1);
        txNew[19].vout.resize(1);
        txNew[19].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[19].vout[0].nValue = 36952.1249088 * COIN;
        txNew[19].vout[0].scriptPubKey = CScript() << ParseHex("0408653714ef7b925bc9253a315bdc50ee1d69cedc7d621b6d26ccd90a864a2e2d150c6167dfc8669b6c34dc93afad0489217d774f68520f89add9bb6b63b55e28") << OP_CHECKSIG;

        txNew[20].vin.resize(1);
        txNew[20].vout.resize(1);
        txNew[20].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[20].vout[0].nValue = 43141.19529941 * COIN;
        txNew[20].vout[0].scriptPubKey = CScript() << ParseHex("0454380b3e001d99867b26d6f87eaa0b9385183a08bbfcd94d2f9dea1ee3264168bc6d207a45016c99fc397611d76bfdb32bc84c477d47eb5bfaad3986ccacd803") << OP_CHECKSIG;

        txNew[21].vin.resize(1);
        txNew[21].vout.resize(1);
        txNew[21].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[21].vout[0].nValue = 287607.96866274 * COIN;
        txNew[21].vout[0].scriptPubKey = CScript() << ParseHex("0431af43fa783a8cb517eb2e176ce2374794388adc45fd08e7a2107ac8025b0e427e3b9b0f8bcc898fc5a73464d23f705a3181e0fdea5f745df059a4f68826703c") << OP_CHECKSIG;

        txNew[22].vin.resize(1);
        txNew[22].vout.resize(1);
        txNew[22].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[22].vout[0].nValue = 603.97673419 * COIN;
        txNew[22].vout[0].scriptPubKey = CScript() << ParseHex("04104e9c43c1082c1c0184f24cf23acc00577d4ba51b4b95ac76731d04a16e01c3de7e73babfe0e6fb5deea2a16cc06894b84759ff626c3dbc5a7ed4356e536f89") << OP_CHECKSIG;

        txNew[23].vin.resize(1);
        txNew[23].vout.resize(1);
        txNew[23].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[23].vout[0].nValue = 57521.59373255 * COIN;
        txNew[23].vout[0].scriptPubKey = CScript() << ParseHex("045d1c9d519e35930b659aab08f3f589e75704c59aecf30c10ca6f6b42a46e91085f0b99f58d533b9acfea7836bf1511a4c9a99776ec746972a01c945f967c39aa") << OP_CHECKSIG;

        txNew[24].vin.resize(1);
        txNew[24].vout.resize(1);
        txNew[24].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[24].vout[0].nValue = 2876.07968663 * COIN;
        txNew[24].vout[0].scriptPubKey = CScript() << ParseHex("04efbbb10e189123cf921aa7f7b1ab91deaf1ea8c2d3602ef9d9d13d778d8241dd38c31e6ed6e7f7720a644b71a80c6fafa9b8283c84e9c5878207c3bbc990e539") << OP_CHECKSIG;

        txNew[25].vin.resize(1);
        txNew[25].vout.resize(1);
        txNew[25].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[25].vout[0].nValue = 2876.07968663 * COIN;
        txNew[25].vout[0].scriptPubKey = CScript() << ParseHex("043a2e7c741b194fa988b11dea060b8e7e8bc1ca49a82338958a14f650a30b9a67c6d81a5233b55f0f59444815e22be1a0c05e998d05d8e8515bf5139b35000bd8") << OP_CHECKSIG;

        txNew[26].vin.resize(1);
        txNew[26].vout.resize(1);
        txNew[26].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[26].vout[0].nValue = 86282.39059882 * COIN;
        txNew[26].vout[0].scriptPubKey = CScript() << ParseHex("04ced134f2b48280bd0066d85257f02b36dcd820c9db8ce627f8d9e6b03d1ffb09ffe7c2b88b06657c88e4ebd742047c6f04051da8e15a0dea394284af8340579f") << OP_CHECKSIG;

        txNew[27].vin.resize(1);
        txNew[27].vout.resize(1);
        txNew[27].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[27].vout[0].nValue = 2876.07968663 * COIN;
        txNew[27].vout[0].scriptPubKey = CScript() << ParseHex("04b5475e5650e72e48da6d639e8dbda423782d1f3445bb06bfac69fbe7cc548ab986e98bbbb111cb0d42c647704462241e9152574ba3f04becebd32f27acf15082") << OP_CHECKSIG;

        txNew[28].vin.resize(1);
        txNew[28].vout.resize(1);
        txNew[28].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[28].vout[0].nValue = 4050.06061414 * COIN;
        txNew[28].vout[0].scriptPubKey = CScript() << ParseHex("04945018f2589025aece51e8f45fee0f1998076cbaaa3d715e77bd9abb378be8cb7b23dda28d71af993aa2262807ffdfd0bfcae3846366c34f8b86556927c5e58e") << OP_CHECKSIG;

        txNew[29].vin.resize(1);
        txNew[29].vout.resize(1);
        txNew[29].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[29].vout[0].nValue = 1955.73418691 * COIN;
        txNew[29].vout[0].scriptPubKey = CScript() << ParseHex("04d9c39d55aa779412490e7d6efbf1c3d5aa10e2fb6f9e2efe70da72c2e9285618f8f88680d83978593684b469d831f6373836fc10de94bae76bfc626dedf570e0") << OP_CHECKSIG;

        txNew[30].vin.resize(1);
        txNew[30].vout.resize(1);
        txNew[30].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[30].vout[0].nValue = 5752.15937325 * COIN;
        txNew[30].vout[0].scriptPubKey = CScript() << ParseHex("04e6c7d30fe35aae7094de2b2b3cfdea71a501d489315564315a36b6b5bddf6f6b665fd527c1c9acddbf1c944c432ff7434327eaa145fbaa5d8b41ceb620851086") << OP_CHECKSIG;

        txNew[31].vin.resize(1);
        txNew[31].vout.resize(1);
        txNew[31].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[31].vout[0].nValue = 3451.29562395 * COIN;
        txNew[31].vout[0].scriptPubKey = CScript() << ParseHex("044e4cfe1627ecb1e14d4b2c16f3fc0ae0c6b82e395a6fb23be98089863fd41688a1bd32792964f85915c65620233b59e057d560f96826e2b52a14635e8e1f8efc") << OP_CHECKSIG;

        txNew[32].vin.resize(1);
        txNew[32].vout.resize(1);
        txNew[32].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[32].vout[0].nValue = 287636.7294596 * COIN;
        txNew[32].vout[0].scriptPubKey = CScript() << ParseHex("042f84fb3a969acff39f5a1fd9487a828526d5082e3b03cb12c42c6c43be882e510ca6afe9ca17eeb97d9b1c7494ce06162ff80cd49abaa99940669d65b12dcc86") << OP_CHECKSIG;

        txNew[33].vin.resize(1);
        txNew[33].vout.resize(1);
        txNew[33].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[33].vout[0].nValue = 14383.27451282 * COIN;
        txNew[33].vout[0].scriptPubKey = CScript() << ParseHex("040d52d040141b7ba0a871e462843b78530ee7a21464df86bf1809aefa153d93fd7eebcfeb24ecbb30b713838ad305ff3ab077d011e531b249f21dff203b577504") << OP_CHECKSIG;

        txNew[34].vin.resize(1);
        txNew[34].vout.resize(1);
        txNew[34].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[34].vout[0].nValue = 39692.77575514 * COIN;
        txNew[34].vout[0].scriptPubKey = CScript() << ParseHex("04bbf608ffdf698690cb44ee72d66fd82c50564767d29680d5ecf6985771b8d11a962f8fbeca2ca21a2aeabac98dbc53f33757e283de34dcba58b5caeb738ad5c5") << OP_CHECKSIG;

        txNew[35].vin.resize(1);
        txNew[35].vout.resize(1);
        txNew[35].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[35].vout[0].nValue = 28760.79686627 * COIN;
        txNew[35].vout[0].scriptPubKey = CScript() << ParseHex("045747f00a53766afc9a22e36af6f25be8c5a4807ffd5fb4ba09c2dbf4f425ef76e44f776ff7c001366c1efc8000be42051618f631b6f4cf7be0923dcb5cd0ea77") << OP_CHECKSIG;

        txNew[36].vin.resize(1);
        txNew[36].vout.resize(1);
        txNew[36].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[36].vout[0].nValue = 86282.39059882 * COIN;
        txNew[36].vout[0].scriptPubKey = CScript() << ParseHex("045b1afd6815107f4d6f5da84f391621669661c92029695682f46298fb9cf49f28ed135f9a7eb2dfe56dbe375463c8f6da4afe36d8c79eeb6eb7a0465b1e9a5545") << OP_CHECKSIG;

        txNew[37].vin.resize(1);
        txNew[37].vout.resize(1);
        txNew[37].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[37].vout[0].nValue = 57521.59373255 * COIN;
        txNew[37].vout[0].scriptPubKey = CScript() << ParseHex("04de10de0ac1f1418586ef7deee1d7125cbdda7ce0404c410f0a6ab967e6c51684e3fae6c388ac8faf6f466a79c62a2435cb0dd94e7f2c41bc6a24fffd1220dfb6") << OP_CHECKSIG;

        txNew[38].vin.resize(1);
        txNew[38].vout.resize(1);
        txNew[38].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[38].vout[0].nValue = 8394.72180949 * COIN;
        txNew[38].vout[0].scriptPubKey = CScript() << ParseHex("048efac43c7e64009db3715f602762a393332502c8cd6c201ce7bcef07304e2280733935034ceb42ec0483aa4d290c220267d78e4e4d8c1361196dfa837a7a61b3") << OP_CHECKSIG;

        txNew[39].vin.resize(1);
        txNew[39].vout.resize(1);
        txNew[39].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[39].vout[0].nValue = 1049.83437263 * COIN;
        txNew[39].vout[0].scriptPubKey = CScript() << ParseHex("04e35be5288273e39084498bee3c021a642166a92018626a8250b7c21c9dcb98fc89faaec32829584e039105310c49af2d305f15e0e6e5b049a7a54d9512a9c7ef") << OP_CHECKSIG;

        txNew[40].vin.resize(1);
        txNew[40].vout.resize(1);
        txNew[40].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[40].vout[0].nValue = 6316.93945544 * COIN;
        txNew[40].vout[0].scriptPubKey = CScript() << ParseHex("04103327b2d7e2af499e3c09325d5e928487d21faca41199fa9c4449576fda047d4ce39654725caeec43611d53ae422061826e3dc688aced64abd61c7e947f6321") << OP_CHECKSIG;

        txNew[41].vin.resize(1);
        txNew[41].vout.resize(1);
        txNew[41].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[41].vout[0].nValue = 20477.68736879 * COIN;
        txNew[41].vout[0].scriptPubKey = CScript() << ParseHex("041a6fbdb57d7831640ebe5ee332ea5fc9db25d76882ed8f9cc128fb7a0426c99bd238d90356e27356ebd6c52068705e45822447a0543c6cb9e8f4d326dfd8d1f1") << OP_CHECKSIG;

        txNew[42].vin.resize(1);
        txNew[42].vout.resize(1);
        txNew[42].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[42].vout[0].nValue = 4314.11952994 * COIN;
        txNew[42].vout[0].scriptPubKey = CScript() << ParseHex("049d3edc696b971915ba8ed89dc3ca0d2277d7e846afc8bd7f3e903272b037eb5f6adbd6b4c5e8833cceb701de63280739467f5aa2928105260b9242416e4a95f4") << OP_CHECKSIG;

        txNew[43].vin.resize(1);
        txNew[43].vout.resize(1);
        txNew[43].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[43].vout[0].nValue = 25884.71717965 * COIN;
        txNew[43].vout[0].scriptPubKey = CScript() << ParseHex("04d11ba73b248a3aaf51ba787177592b88bc522bb1a2123371a14d94911855811b3569fca4dc17857163e18b19072e7af1471a8a8495fda23c8e04ebdb866836b0") << OP_CHECKSIG;

        txNew[44].vin.resize(1);
        txNew[44].vout.resize(1);
        txNew[44].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[44].vout[0].nValue = 16221.08943258 * COIN;
        txNew[44].vout[0].scriptPubKey = CScript() << ParseHex("04a44aa0f33ce22135dd255ee16c2928a0d19172bffba2ce31c0c84f051fda34ebd1d75ce0c610513b416a356c40abeac6b7b8e903b7d12519124f26000390ac61") << OP_CHECKSIG;

        txNew[45].vin.resize(1);
        txNew[45].vout.resize(1);
        txNew[45].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[45].vout[0].nValue = 19916.63037176 * COIN;
        txNew[45].vout[0].scriptPubKey = CScript() << ParseHex("04945018f2589025aece51e8f45fee0f1998076cbaaa3d715e77bd9abb378be8cb7b23dda28d71af993aa2262807ffdfd0bfcae3846366c34f8b86556927c5e58e") << OP_CHECKSIG;

        txNew[46].vin.resize(1);
        txNew[46].vout.resize(1);
        txNew[46].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[46].vout[0].nValue = 4314.11952994 * COIN;
        txNew[46].vout[0].scriptPubKey = CScript() << ParseHex("04f21275016fd7b4ad989693e8bd9516f4e517c22f1a6335ae5fd6d75f437bd1c1c2b91b2f03e3f63430ea4373cc9eab5fd9dc322e981233f830e550535005b6aa") << OP_CHECKSIG;

        txNew[47].vin.resize(1);
        txNew[47].vout.resize(1);
        txNew[47].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[47].vout[0].nValue = 100662.78903196 * COIN;
        txNew[47].vout[0].scriptPubKey = CScript() << ParseHex("0439871a7f0d445d2e3ee56e000ce051b23a5a0cc3459137547ede0441da0f884c3887ad0ff9dfc9416b1331d301511b4c25b6d86c33775a2148dbb5bde7f30263") << OP_CHECKSIG;

        txNew[48].vin.resize(1);
        txNew[48].vout.resize(1);
        txNew[48].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[48].vout[0].nValue = 198664.9774311 * COIN;
        txNew[48].vout[0].scriptPubKey = CScript() << ParseHex("048713ddf7763abeb8ffd35166082589789fe4a9b4148b9120c83f38bd247046d3e132d2252c0118e87e18f556e1a424b535f5fede4c4fde6fa66d48fe31e92144") << OP_CHECKSIG;

        txNew[49].vin.resize(1);
        txNew[49].vout.resize(1);
        txNew[49].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[49].vout[0].nValue = 1869.45179631 * COIN;
        txNew[49].vout[0].scriptPubKey = CScript() << ParseHex("045eed3ac90a6fc196419acb0826e1e43c89b9b7cf6b52c0792d7c19b5ffaa86572862ccb390e85586998d2fc3195749aaba55bc81926e1bbc8e5bc9d662ec29c9") << OP_CHECKSIG;

        txNew[50].vin.resize(1);
        txNew[50].vout.resize(1);
        txNew[50].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[50].vout[0].nValue = 143803.98433137 * COIN;
        txNew[50].vout[0].scriptPubKey = CScript() << ParseHex("04413cbf5327d7d0309098c8c6a38d7ed968ccdcd113fc663eb9a0639456dbb02f8fed0698337cf1f910e9c47a93b345f895f691433744de7187ea3dbe8d50d1a4") << OP_CHECKSIG;

        txNew[51].vin.resize(1);
        txNew[51].vout.resize(1);
        txNew[51].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[51].vout[0].nValue = 2876.07968663 * COIN;
        txNew[51].vout[0].scriptPubKey = CScript() << ParseHex("04e2b91e5bfde20c62cbcf623c282d5cd50562f527ad79fb9189f42d9eccb8ef459896a626721c20c2d67d498850c0ac30da40828da58eb089f0c8f2bad7aede34") << OP_CHECKSIG;

        txNew[52].vin.resize(1);
        txNew[52].vout.resize(1);
        txNew[52].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[52].vout[0].nValue = 11504.31874651 * COIN;
        txNew[52].vout[0].scriptPubKey = CScript() << ParseHex("041f2661b75bb2fce7daa092c267c082f52c5109a695e005fb73aec4d18dae9e4820b24c29eb646fc829974a0852cc85a6970fbd4fb625a5c4bfe223b3a77f9530") << OP_CHECKSIG;

        txNew[53].vin.resize(1);
        txNew[53].vout.resize(1);
        txNew[53].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[53].vout[0].nValue = 5910.66961585 * COIN;
        txNew[53].vout[0].scriptPubKey = CScript() << ParseHex("045e51f188c7a7378f2bbc9e4f584f439d001624deb6f928eed73f7815cc6acc6ea6afe8be81f6c386fdb16ea701b2f5c9d55c2d74963d06b4ba4ec4b657b75fd1") << OP_CHECKSIG;

        txNew[54].vin.resize(1);
        txNew[54].vout.resize(1);
        txNew[54].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[54].vout[0].nValue = 28760.79686627 * COIN;
        txNew[54].vout[0].scriptPubKey = CScript() << ParseHex("042cc53999404da414b7b32d6015d73b97d7d2dfa0b17a2c39fc8ad62ab988bdafcbc77c7688e192e2b56ddab44e5c33ebfeb24ecdf99338c293014255b2e43c7e") << OP_CHECKSIG;

        txNew[55].vin.resize(1);
        txNew[55].vout.resize(1);
        txNew[55].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[55].vout[0].nValue = 7190.19921657 * COIN;
        txNew[55].vout[0].scriptPubKey = CScript() << ParseHex("040cb424d5ab0cddf891d6026517418e0bd8298a7bf1fa7c253ee4d7779420b6f6f03102feea12e6045d53f3f1e3b83128826584997a995abd449fa2e9c4ef32bb") << OP_CHECKSIG;

        txNew[56].vin.resize(1);
        txNew[56].vout.resize(1);
        txNew[56].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[56].vout[0].nValue = 14322.8768394 * COIN;
        txNew[56].vout[0].scriptPubKey = CScript() << ParseHex("046460f3b13cd5b011150ea59693148a6ad7ea4349232b746653e51f4f9fd16be3d96e879994d48d3ae078cc7aaddd3fb00c1e921810496e18363109414079a3ca") << OP_CHECKSIG;

        txNew[57].vin.resize(1);
        txNew[57].vout.resize(1);
        txNew[57].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[57].vout[0].nValue = 5752.15937325 * COIN;
        txNew[57].vout[0].scriptPubKey = CScript() << ParseHex("04936566a5b373fff0d774eff30024d200141dabb279bd182473eef44171868e99c82dbeeeb5414cba3d263539eb649b64b8a816a68213d2d500c7def37301dde1") << OP_CHECKSIG;

        txNew[58].vin.resize(1);
        txNew[58].vout.resize(1);
        txNew[58].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[58].vout[0].nValue = 5752.15937325 * COIN;
        txNew[58].vout[0].scriptPubKey = CScript() << ParseHex("0408a757d29e30a49240d091686854270e38717c2a4d357df0953f38c79ca57b080f805a51bb399942716d1e757fb8ee1a474f75de0b3338012d1b26af305f7461") << OP_CHECKSIG;

        txNew[59].vin.resize(1);
        txNew[59].vout.resize(1);
        txNew[59].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[59].vout[0].nValue = 5752.15937325 * COIN;
        txNew[59].vout[0].scriptPubKey = CScript() << ParseHex("04745322c8cd37a946794bb6644beb3226dd4c56ba9f17fd3af0902baa662a5dc61a2fec3c1a37d197f2567d1a0b1c82e3bdc5df499108e9b651c153766ae8fb80") << OP_CHECKSIG;

        txNew[60].vin.resize(1);
        txNew[60].vout.resize(1);
        txNew[60].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[60].vout[0].nValue = 4116.28321175 * COIN;
        txNew[60].vout[0].scriptPubKey = CScript() << ParseHex("04327591c6f9a41571128cb83c88ed671c32988f784585638e9fc5cd7ddd803af1bfb1ec10af62f7c20dc226903db12d27204224a77038302c68efe48f5837f69c") << OP_CHECKSIG;

        txNew[61].vin.resize(1);
        txNew[61].vout.resize(1);
        txNew[61].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[61].vout[0].nValue = 74778.07185231 * COIN;
        txNew[61].vout[0].scriptPubKey = CScript() << ParseHex("040615d64e8991da9fc16a64464cc1febccb4822ee0e794553896427f74a92bd9a30899c3e17fdf09632b04f1feb77a833cd36cd0f9a53f94f1845e6a083cbf664") << OP_CHECKSIG;

        txNew[62].vin.resize(1);
        txNew[62].vout.resize(1);
        txNew[62].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[62].vout[0].nValue = 28760.79686627 * COIN;
        txNew[62].vout[0].scriptPubKey = CScript() << ParseHex("0487a81bff971561b333b5fbacb7bea217dc5d7428118f8604b1ea9d659c14d57825c44d58fb8bc110bf58c55c348da1de233fe8853c85740ed3e2160bc70649cb") << OP_CHECKSIG;

        txNew[63].vin.resize(1);
        txNew[63].vout.resize(1);
        txNew[63].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[63].vout[0].nValue = 4739.81958868 * COIN;
        txNew[63].vout[0].scriptPubKey = CScript() << ParseHex("0471b9dd895f41cf7b82eff237dd29ca258369f67844d9824e9ea0f5919a3d65525c9aededea170bba18fed97b45d05a359fd5a9f9d0087ddd71de753fec8ad99c") << OP_CHECKSIG;

        txNew[64].vin.resize(1);
        txNew[64].vout.resize(1);
        txNew[64].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[64].vout[0].nValue = 2876.07968663 * COIN;
        txNew[64].vout[0].scriptPubKey = CScript() << ParseHex("04a6bbe31021e1a36805cfb0a845dee85f058c4af6ab17499f548a4ae30281f2f23ab39419db0e0b9d3a5144d7b52d52c46336a224c35633650c75e5f0098492e5") << OP_CHECKSIG;

        txNew[65].vin.resize(1);
        txNew[65].vout.resize(1);
        txNew[65].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[65].vout[0].nValue = 2876.07968663 * COIN;
        txNew[65].vout[0].scriptPubKey = CScript() << ParseHex("04ba75968101a7bf95a7a43b5587860e9a1f5e3e21c799ff4672d6a417b72e3dd30725054c705b363b9d0b254d6226141f02d80631a43c41b62480ebe7b3eb659f") << OP_CHECKSIG;

        txNew[66].vin.resize(1);
        txNew[66].vout.resize(1);
        txNew[66].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[66].vout[0].nValue = 2588.47171796 * COIN;
        txNew[66].vout[0].scriptPubKey = CScript() << ParseHex("04b3bfaf86aab8c5db2c945af098bbcf434a6597feb052e7379ed13e1e849809ea86ba3c63f27342a33165da8695b850302a553f4da56575be62d4081c5a009127") << OP_CHECKSIG;

        txNew[67].vin.resize(1);
        txNew[67].vout.resize(1);
        txNew[67].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[67].vout[0].nValue = 3163.68765529 * COIN;
        txNew[67].vout[0].scriptPubKey = CScript() << ParseHex("04b3bfaf86aab8c5db2c945af098bbcf434a6597feb052e7379ed13e1e849809ea86ba3c63f27342a33165da8695b850302a553f4da56575be62d4081c5a009127") << OP_CHECKSIG;

        txNew[68].vin.resize(1);
        txNew[68].vout.resize(1);
        txNew[68].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[68].vout[0].nValue = 10093.52544411 * COIN;
        txNew[68].vout[0].scriptPubKey = CScript() << ParseHex("04d290468d5931f2fea8f77535e7764991dfceffdddc2cb4f76f5970e2eb01d830c0a327a0dc4ad55273dbe8d00bd7fe24215b0fd4dce91637551038d1639477a1") << OP_CHECKSIG;

        txNew[69].vin.resize(1);
        txNew[69].vout.resize(1);
        txNew[69].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[69].vout[0].nValue = 52051.86538452 * COIN;
        txNew[69].vout[0].scriptPubKey = CScript() << ParseHex("044aabea4802df8bd2a670fb79842af3100d727a69eaed1c0fce70cc2c9488014152e62fe3674bc6c95f441ff5552bb0647db77c2403997a48838bf115e528468b") << OP_CHECKSIG;

        txNew[70].vin.resize(1);
        txNew[70].vout.resize(1);
        txNew[70].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[70].vout[0].nValue = 44809.32151765 * COIN;
        txNew[70].vout[0].scriptPubKey = CScript() << ParseHex("0490c0271e4387a3804d81b210278a82f7705d0ec8c320840c2b2bb05a55ae17abcfe7575b0b9e79838b48ecd44b015033b2d228b6e2fc1e5ac5a73736901b5d49") << OP_CHECKSIG;

        txNew[71].vin.resize(1);
        txNew[71].vout.resize(1);
        txNew[71].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[71].vout[0].nValue = 19033.8953661 * COIN;
        txNew[71].vout[0].scriptPubKey = CScript() << ParseHex("041689b41c103cce3ccb8e551c1de2d506e57d423818103783afcff48aad8868f24cd3bf6f81e8fce544932ad6bec1713c13ad64fd6aadc50fd86e85c3dc4f7bcc") << OP_CHECKSIG;

        txNew[72].vin.resize(1);
        txNew[72].vout.resize(1);
        txNew[72].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[72].vout[0].nValue = 5752.15937325 * COIN;
        txNew[72].vout[0].scriptPubKey = CScript() << ParseHex("0406afbe6de717d6611639305b89ad1693928026626169cfc44a181832c0089dc876969c11e5b830369d182c1f7a4373acb2a0571556a23fcc76b45717559abb81") << OP_CHECKSIG;

        txNew[73].vin.resize(1);
        txNew[73].vout.resize(1);
        txNew[73].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[73].vout[0].nValue = 301.9883671 * COIN;
        txNew[73].vout[0].scriptPubKey = CScript() << ParseHex("043c0c1e7d9c80b78d379be0b4a23b952444648887dc49cd50088a4884ba65eed669043bd229b2a7f7b0cf9c1f4dc00ae93c8bad2b29d40de06a078545ac13b7a8") << OP_CHECKSIG;

        txNew[74].vin.resize(1);
        txNew[74].vout.resize(1);
        txNew[74].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[74].vout[0].nValue = 7046.39523224 * COIN;
        txNew[74].vout[0].scriptPubKey = CScript() << ParseHex("048f9d62fc83a990ca141bfa63d4771420a33f9b75af197cde980173ae395ecb5147297a9d4b59d6d3c705468e45beef70d43a4d8e302a9343ed69c7506f6ec549") << OP_CHECKSIG;

        txNew[75].vin.resize(1);
        txNew[75].vout.resize(1);
        txNew[75].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[75].vout[0].nValue = 115043.18746509 * COIN;
        txNew[75].vout[0].scriptPubKey = CScript() << ParseHex("04576a329b40aea0bd0cf116d9bff88bc5ba475bb36e5918b30f532e029faaceeefdbae0f876e7ce97d70dcafeea482dad9b1fb299af4cd9faf8222aaa32e11327") << OP_CHECKSIG;

        txNew[76].vin.resize(1);
        txNew[76].vout.resize(1);
        txNew[76].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[76].vout[0].nValue = 14380.39843314 * COIN;
        txNew[76].vout[0].scriptPubKey = CScript() << ParseHex("04f861181f808e2da904fc44e04076926da43dd17d866c8e1aeb48511f19bb71ef5d151b487486cb291a339a3b9c418678727f460c23e141b31d31dc6f365ba425") << OP_CHECKSIG;

        txNew[77].vin.resize(1);
        txNew[77].vout.resize(1);
        txNew[77].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[77].vout[0].nValue = 1758.25680346 * COIN;
        txNew[77].vout[0].scriptPubKey = CScript() << ParseHex("048df96594e1e6197ba347c0ed32141bc6846c8268baed22cc1c5bc2c4986fe8a75ebef159a9b008b55c1a10c07a9606b9ef1e11d753dff94d26f5dbe187c8b6aa") << OP_CHECKSIG;

        txNew[78].vin.resize(1);
        txNew[78].vout.resize(1);
        txNew[78].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[78].vout[0].nValue = 86282.39059882 * COIN;
        txNew[78].vout[0].scriptPubKey = CScript() << ParseHex("04c122bd2baf87b99f5e67b62405e585dc3f9a438f092839d4ed6a3f02ff8006132f3b949714918684d014c1fbd0cacaeb972883dff6dec2ea8ed58add5628561c") << OP_CHECKSIG;

        txNew[79].vin.resize(1);
        txNew[79].vout.resize(1);
        txNew[79].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[79].vout[0].nValue = 3106.79966191 * COIN;
        txNew[79].vout[0].scriptPubKey = CScript() << ParseHex("04b89a781361013d40672312f6064250ee52d2fa1baadb94272816d482957bc7454b2bd0afc8a734bdb6c8f4d5104ec976db3694d0a3c632a8c8c75a45eb6962c3") << OP_CHECKSIG;

        txNew[80].vin.resize(1);
        txNew[80].vout.resize(1);
        txNew[80].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[80].vout[0].nValue = 14380.39843314 * COIN;
        txNew[80].vout[0].scriptPubKey = CScript() << ParseHex("04eab7aa9d256d707f9572b5293cc7934f68f7ea356f2e255673cc2f1cef7ad65bc2bf42d41f6f5e47e8716f24bfac061da7977f2cc6cd1950ddf226dc6df8ef6b") << OP_CHECKSIG;

        txNew[81].vin.resize(1);
        txNew[81].vout.resize(1);
        txNew[81].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[81].vout[0].nValue = 14380.39843314 * COIN;
        txNew[81].vout[0].scriptPubKey = CScript() << ParseHex("044d1b19c71c517fbc2ccb6d00a9034b688bccec3a92d6ae05f234fff29730b95677b5dac415f9c8d855b0d361db374af240b8a47c1fbc7c54af5d263d68358d33") << OP_CHECKSIG;

        txNew[82].vin.resize(1);
        txNew[82].vout.resize(1);
        txNew[82].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[82].vout[0].nValue = 2876.07968663 * COIN;
        txNew[82].vout[0].scriptPubKey = CScript() << ParseHex("04e25410ea422ea7e9e645dec40962ac0a39ab6b2e7d2ee4f7fbebcb7dbad7c1f349d0e621f8ec7a9f51fbd613698b0aa483225e051ff6ec55a556e479f3094458") << OP_CHECKSIG;

        txNew[83].vin.resize(1);
        txNew[83].vout.resize(1);
        txNew[83].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[83].vout[0].nValue = 5752.15937325 * COIN;
        txNew[83].vout[0].scriptPubKey = CScript() << ParseHex("04e2b8a841d6518e63aa5f489eec405f506e8742067101948f4fe3c21a27c7f439aba1408be3cfddcac27962c8be28222bbe03dde0c61b5bd8d3ca9788273ff4be") << OP_CHECKSIG;

        txNew[84].vin.resize(1);
        txNew[84].vout.resize(1);
        txNew[84].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[84].vout[0].nValue = 28760.79686627 * COIN;
        txNew[84].vout[0].scriptPubKey = CScript() << ParseHex("04afeaeb4e1acc9ad8b11296a08b88effe83f6040a69c6ca68cc0fc8e9ff7aca6879ed786483e7495e2245464b58cbf9b3d074f5f1a662a19a3f272fe5ac627635") << OP_CHECKSIG;

        txNew[85].vin.resize(1);
        txNew[85].vout.resize(1);
        txNew[85].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[85].vout[0].nValue = 14380.39843314 * COIN;
        txNew[85].vout[0].scriptPubKey = CScript() << ParseHex("04bde2a1750003f00309889f8f63460fc531e68e4a92d8d8f31e80879f3bab855150425fd457adeff09b79369cf0fd452e62a835c60b06bf5d43d887a23d35a1f3") << OP_CHECKSIG;

        txNew[86].vin.resize(1);
        txNew[86].vout.resize(1);
        txNew[86].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[86].vout[0].nValue = 4314.11952994 * COIN;
        txNew[86].vout[0].scriptPubKey = CScript() << ParseHex("04e99252843b403225430bff8b24a92222cb20158d43b48bc278e538616e9b6f4482e2e8fa41192c211b3a625bb017948956711213a669c3e51bbbf85d44965233") << OP_CHECKSIG;

        txNew[87].vin.resize(1);
        txNew[87].vout.resize(1);
        txNew[87].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[87].vout[0].nValue = 3399.52618959 * COIN;
        txNew[87].vout[0].scriptPubKey = CScript() << ParseHex("044aefabdfca43c84211ac73317bf455cb8caae588abd2aaf0ad4d8b3fe44ad5133f902b39b82c676d602f3574e7841817be82eba7c624da717a42292621ff6baa") << OP_CHECKSIG;

        txNew[88].vin.resize(1);
        txNew[88].vout.resize(1);
        txNew[88].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[88].vout[0].nValue = 33218.72038055 * COIN;
        txNew[88].vout[0].scriptPubKey = CScript() << ParseHex("04a89ec1621c670908051dbd84c17ed1c7a087a1239ad07fdf611493084b20548bde0d6fd0e6bd7a4d099797147b89536c21c23c4c27c155e8e9c4455f4c406070") << OP_CHECKSIG;

        txNew[89].vin.resize(1);
        txNew[89].vout.resize(1);
        txNew[89].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[89].vout[0].nValue = 2876.07968663 * COIN;
        txNew[89].vout[0].scriptPubKey = CScript() << ParseHex("04b7a0042c6a88ac29a9a226689ea41ff038bbe43ee2abcad4bcd753b2cb81591fc9e0dee897de1c21e717400fa6cadc01324ff1d114d1f0c647f62ea83687d6b0") << OP_CHECKSIG;

        txNew[90].vin.resize(1);
        txNew[90].vout.resize(1);
        txNew[90].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[90].vout[0].nValue = 359.50996083 * COIN;
        txNew[90].vout[0].scriptPubKey = CScript() << ParseHex("04bc0c8d0cbece047c9ed27c718a0b1cdcebb8f590bcf768bd8ad106615921a33e8d4f1491a61e5f5d20b5c4cec90d8b8cd91b74d5ba1a0e6b53aa9e77252b0eeb") << OP_CHECKSIG;

        txNew[91].vin.resize(1);
        txNew[91].vout.resize(1);
        txNew[91].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[91].vout[0].nValue = 5749.28329357 * COIN;
        txNew[91].vout[0].scriptPubKey = CScript() << ParseHex("047dd4e2553f40bf7d0c7570db1ca7213a20571011c5638222e9175e33af4f5bd14e10149d7374cb7871a2bf014b64e1d1647c16fa48114b9ee7293aa0aee6030e") << OP_CHECKSIG;

        txNew[92].vin.resize(1);
        txNew[92].vout.resize(1);
        txNew[92].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[92].vout[0].nValue = 28760.79686627 * COIN;
        txNew[92].vout[0].scriptPubKey = CScript() << ParseHex("049b6c931fb060bd4023d2f96e1fe954131d4cc6223ee81cb79de9ea861cd796bb618ce3f6ae683887cd18cdea18bb90d1685a031d8fe7447034ac4129f241efed") << OP_CHECKSIG;

        txNew[93].vin.resize(1);
        txNew[93].vout.resize(1);
        txNew[93].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[93].vout[0].nValue = 4314.11952994 * COIN;
        txNew[93].vout[0].scriptPubKey = CScript() << ParseHex("04fdbe7ae486f4fd3710f6416bd7bcdbee50dc04970311292f5f9b7f1004b8c2cee329cee722aef0baa0ee3107b33c92483fe96c215c630954a6a371eadf22e3de") << OP_CHECKSIG;

        txNew[94].vin.resize(1);
        txNew[94].vout.resize(1);
        txNew[94].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[94].vout[0].nValue = 7768.29123358 * COIN;
        txNew[94].vout[0].scriptPubKey = CScript() << ParseHex("0400cec8e13e464403b5026c2f2ed22e9c8adeed87533342be381c34a7a0833d6fad10a54dab5a9e159d851aa0e0c1ded23449a95f0cdb383262418f68440c1142") << OP_CHECKSIG;

        txNew[95].vin.resize(1);
        txNew[95].vout.resize(1);
        txNew[95].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[95].vout[0].nValue = 250229.14684598 * COIN;
        txNew[95].vout[0].scriptPubKey = CScript() << ParseHex("0466ee0fb3d34d2b106012319d525612260a1ceebed716e87e2b3c7c5190d2ecb9cdcfb71270b4455e99a3d4ec6a29ba15f596261efeb02d5976ec4bb04e763d64") << OP_CHECKSIG;

        txNew[96].vin.resize(1);
        txNew[96].vout.resize(1);
        txNew[96].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[96].vout[0].nValue = 14380.39843314 * COIN;
        txNew[96].vout[0].scriptPubKey = CScript() << ParseHex("048a435c1e48285b9e8a407983cc1a632ea51751e885e9c6abb1c55b59955c3b7fd43a169a9dbc6d30128820983a0b64179d1b9e98b64bf81c9a8e005e7b64cbde") << OP_CHECKSIG;

        txNew[97].vin.resize(1);
        txNew[97].vout.resize(1);
        txNew[97].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[97].vout[0].nValue = 1725.64781198 * COIN;
        txNew[97].vout[0].scriptPubKey = CScript() << ParseHex("049623f8b2d1d4cb7eeea8f4e9ce78cc6a7057dff96eaba7585a1a2be4057b17de3b5bffac29eda3b29df85efb7a597ddc2e331f9d38a3638c857352e3712412f8") << OP_CHECKSIG;

        txNew[98].vin.resize(1);
        txNew[98].vout.resize(1);
        txNew[98].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[98].vout[0].nValue = 115043.18746509 * COIN;
        txNew[98].vout[0].scriptPubKey = CScript() << ParseHex("04af381a9194cdc80393e3faaadf0c876e2fbdd9e01af85f18c5f3803642cde97a218af80489f98aff0ce5d069a79200b30b46992319f740922351543d636b7e58") << OP_CHECKSIG;

        txNew[99].vin.resize(1);
        txNew[99].vout.resize(1);
        txNew[99].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[99].vout[0].nValue = 23636.35338894 * COIN;
        txNew[99].vout[0].scriptPubKey = CScript() << ParseHex("04abc4916b3aaf2ef91512d44f95ee4f82c36769865ae396d4e55a7888dfd955b2ad0bc65aacee5dff3848ba803a227dc9915978a3caa3f9bee933f6a654bc3e0a") << OP_CHECKSIG;

        txNew[100].vin.resize(1);
        txNew[100].vout.resize(1);
        txNew[100].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[100].vout[0].nValue = 2300.8637493 * COIN;
        txNew[100].vout[0].scriptPubKey = CScript() << ParseHex("04014f524ac398f01e8124a697141a8466e67cef06246718844a6ed7d36e826483c6d58a1f33c4785a9641c55818c7818b1b95cbb2c8ee6d6c1b8f4d8d5fcf89f2") << OP_CHECKSIG;

        txNew[101].vin.resize(1);
        txNew[101].vout.resize(1);
        txNew[101].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[101].vout[0].nValue = 4314.11952994 * COIN;
        txNew[101].vout[0].scriptPubKey = CScript() << ParseHex("047bc402f700e8b1ced157288c2de0c6e93043cd1da6b530cbca100d20412e8fbf92c3359ec398ae1041f7c5dbfe0db8e8dfdd869f36144c29af81a658bf671934") << OP_CHECKSIG;

        txNew[102].vin.resize(1);
        txNew[102].vout.resize(1);
        txNew[102].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[102].vout[0].nValue = 55508.33795191 * COIN;
        txNew[102].vout[0].scriptPubKey = CScript() << ParseHex("04b5e9919977240dda52639ddb0d4d7d5ee94868f41847853af1b55f9927d32c286cc28a9832f9b62ec21563c4449de090385045a8ee726e5378ac35e9fbbb7b7f") << OP_CHECKSIG;

        txNew[103].vin.resize(1);
        txNew[103].vout.resize(1);
        txNew[103].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[103].vout[0].nValue = 28760.79686627 * COIN;
        txNew[103].vout[0].scriptPubKey = CScript() << ParseHex("04bbf608ffdf698690cb44ee72d66fd82c50564767d29680d5ecf6985771b8d11a962f8fbeca2ca21a2aeabac98dbc53f33757e283de34dcba58b5caeb738ad5c5") << OP_CHECKSIG;

        txNew[104].vin.resize(1);
        txNew[104].vout.resize(1);
        txNew[104].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[104].vout[0].nValue = 10257.84996939 * COIN;
        txNew[104].vout[0].scriptPubKey = CScript() << ParseHex("04d108fef1b0288571039a0229b1f7656e6f36f5f740dbad24e53c39e913b1985840609bc3003ac8d37e27a04abb5d47d8a3338ae817e916118d9b038cd79fd1df") << OP_CHECKSIG;

        txNew[105].vin.resize(1);
        txNew[105].vout.resize(1);
        txNew[105].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[105].vout[0].nValue = 75094.24677007 * COIN;
        txNew[105].vout[0].scriptPubKey = CScript() << ParseHex("042f6f9fdac0d845d3378d9a28d0a7e0200586484e54773e529391275da3f639f468a131ff215798b31ec1a93be917ca299de40bac970490089bf000a3a792c4a2") << OP_CHECKSIG;

        txNew[106].vin.resize(1);
        txNew[106].vout.resize(1);
        txNew[106].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[106].vout[0].nValue = 14377.52235345 * COIN;
        txNew[106].vout[0].scriptPubKey = CScript() << ParseHex("0401cad95aee4bc86074ce1d6592dd1a401130ca415950091a37eebb5092b3660a39fbff9f97bf8e934852ce1093be851ace60279c65844f9367eeaa4e785727a5") << OP_CHECKSIG;

        txNew[107].vin.resize(1);
        txNew[107].vout.resize(1);
        txNew[107].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[107].vout[0].nValue = 43138.31921972 * COIN;
        txNew[107].vout[0].scriptPubKey = CScript() << ParseHex("04bbf608ffdf698690cb44ee72d66fd82c50564767d29680d5ecf6985771b8d11a962f8fbeca2ca21a2aeabac98dbc53f33757e283de34dcba58b5caeb738ad5c5") << OP_CHECKSIG;

        txNew[108].vin.resize(1);
        txNew[108].vout.resize(1);
        txNew[108].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[108].vout[0].nValue = 575.21593733 * COIN;
        txNew[108].vout[0].scriptPubKey = CScript() << ParseHex("041b31aabb31ff5edbf221bb73a2741cf0a13f6894dba0c0516728ee440d8c1b66ca48d21fa59403e259acccd7de9247fb2bf141c10daa6cb960a8a5648461ab6a") << OP_CHECKSIG;

        txNew[109].vin.resize(1);
        txNew[109].vout.resize(1);
        txNew[109].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[109].vout[0].nValue = 568.31334608 * COIN;
        txNew[109].vout[0].scriptPubKey = CScript() << ParseHex("04be7bc4d9d329da22df9144c80973637674a331b9126bab2853ef950e8886d68727e35288797394e68201e79f564652807f50efcf7adb4cda5e7576bb246d2eed") << OP_CHECKSIG;

        txNew[110].vin.resize(1);
        txNew[110].vout.resize(1);
        txNew[110].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[110].vout[0].nValue = 5752.15937325 * COIN;
        txNew[110].vout[0].scriptPubKey = CScript() << ParseHex("04d77f7c2caac8392cf661f41e2e1332ef8765d2bc50d37f54f08cf3715d5a5fc5f5baf4573e040ce91e821e65e009beaee5984b1b92b9f8b960aa4951a76a73c4") << OP_CHECKSIG;

        txNew[111].vin.resize(1);
        txNew[111].vout.resize(1);
        txNew[111].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[111].vout[0].nValue = 287.60796866 * COIN;
        txNew[111].vout[0].scriptPubKey = CScript() << ParseHex("04f0eebc714807ff448d187f3b4a902fd33b382a98b1b4ad2737dab139a1644e8c167f32bb56f6163bcec0512d7d8e177931332d351b0c926f38e0fa3e04a6a06c") << OP_CHECKSIG;

        txNew[112].vin.resize(1);
        txNew[112].vout.resize(1);
        txNew[112].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[112].vout[0].nValue = 2588.47171796 * COIN;
        txNew[112].vout[0].scriptPubKey = CScript() << ParseHex("04f7e7d5ea360867464fc82edc6d2918a7966239742bb6a353a62c4b0e0446ac19c585aea558540673e4a72718e34eb8b7a85b330012d9ea364eef583a2f8c4d55") << OP_CHECKSIG;

        txNew[113].vin.resize(1);
        txNew[113].vout.resize(1);
        txNew[113].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[113].vout[0].nValue = 287.60796866 * COIN;
        txNew[113].vout[0].scriptPubKey = CScript() << ParseHex("044b062ff545eb9d0b474c5c690742a7f4aaef6383496b7229ee698a93582818c09ad9b74170e2cd0d140da5767a177adf026019a0b763424a373d25a8e35be75e") << OP_CHECKSIG;

        txNew[114].vin.resize(1);
        txNew[114].vout.resize(1);
        txNew[114].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[114].vout[0].nValue = 14380.39843314 * COIN;
        txNew[114].vout[0].scriptPubKey = CScript() << ParseHex("04041f5b116351b98b1d16002975f553e1734774a928d12b9f11ce4a1a81597467595b7021e2ec53a1428d08a176146fd73734f1ab9e5b7a422a3c8e0fb29abfe3") << OP_CHECKSIG;

        txNew[115].vin.resize(1);
        txNew[115].vout.resize(1);
        txNew[115].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[115].vout[0].nValue = 1150.43187465 * COIN;
        txNew[115].vout[0].scriptPubKey = CScript() << ParseHex("04b77e057b7bb7f905aa8501af55170645e4c96f26d1ca386d58a60d8b42b1db31237250e9b7ba5ad3f191838aaf5aa21dd1aae0fd83813091d1d7867c7debc6f4") << OP_CHECKSIG;

        txNew[116].vin.resize(1);
        txNew[116].vout.resize(1);
        txNew[116].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[116].vout[0].nValue = 28760.79686627 * COIN;
        txNew[116].vout[0].scriptPubKey = CScript() << ParseHex("040fe9445f845efcc1d82b85ea633b2962012f7bd13c3cafedcf7c605222e9f1e7b5837900d21f69f82fcf928420fc5cd933bac480bab2d1258f78e634225df93f") << OP_CHECKSIG;

        txNew[117].vin.resize(1);
        txNew[117].vout.resize(1);
        txNew[117].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[117].vout[0].nValue = 2876.07968663 * COIN;
        txNew[117].vout[0].scriptPubKey = CScript() << ParseHex("04dfec09f1bec174a646e8782e52eb2a044f881023013ea4f25ad1f7c186a1a4c316be432488cff230e565fcd3747173d62f680b29299a3c3bf62540a87e8fd785") << OP_CHECKSIG;

        txNew[118].vin.resize(1);
        txNew[118].vout.resize(1);
        txNew[118].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[118].vout[0].nValue = 143803.98433137 * COIN;
        txNew[118].vout[0].scriptPubKey = CScript() << ParseHex("0414cc5cbbd72cb37ff7a1d41b81fdd0e9414d143210c5d7e2c5940280f358e87d55277775c5aeba39b0670a7d148f2d4bc0448c13133a000c54753a56da52332d") << OP_CHECKSIG;

        txNew[119].vin.resize(1);
        txNew[119].vout.resize(1);
        txNew[119].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[119].vout[0].nValue = 115043.18746509 * COIN;
        txNew[119].vout[0].scriptPubKey = CScript() << ParseHex("04a5fab59775fc46b215e3154406b90c42486a4795b4b78d1f8fd3e6c1af9c3e01c83edc39f8cd0c2abbd1cb6b9bf0eba2be08498ea53031db995862177d1762be") << OP_CHECKSIG;

        txNew[120].vin.resize(1);
        txNew[120].vout.resize(1);
        txNew[120].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[120].vout[0].nValue = 16733.58238606 * COIN;
        txNew[120].vout[0].scriptPubKey = CScript() << ParseHex("04756f7138af81a53299affc8ab48fb8a1ed910dd371bf782ae6d0c440d020890aac058c98fed175bb1c357a4cd27d18e5d62765e14fae55a8f31d2a0c2d647a8c") << OP_CHECKSIG;

        txNew[121].vin.resize(1);
        txNew[121].vout.resize(1);
        txNew[121].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[121].vout[0].nValue = 6419.40986055 * COIN;
        txNew[121].vout[0].scriptPubKey = CScript() << ParseHex("043e34540cb6e3002c6515d1178efbaa82909aa1a2cc989b8c09892b794ad0c244da9c2cc8d9954f10022e0e168f99a87a11db33fef002d68380fee3f4cb8210e5") << OP_CHECKSIG;

        txNew[122].vin.resize(1);
        txNew[122].vout.resize(1);
        txNew[122].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[122].vout[0].nValue = 8896.73921793 * COIN;
        txNew[122].vout[0].scriptPubKey = CScript() << ParseHex("049b6ce35f48f67521fc6dec29dc8ecb25506674a2fd53cb392494b1d76ddc38b11b2ae093531f7c0fd5bd67b217c84e2a9f781e0fa6b0bc121d5cbf634e6c9176") << OP_CHECKSIG;

        txNew[123].vin.resize(1);
        txNew[123].vout.resize(1);
        txNew[123].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[123].vout[0].nValue = 28760.79686627 * COIN;
        txNew[123].vout[0].scriptPubKey = CScript() << ParseHex("0498fe884e25f93f8c91b337f2500e2d4b882f4b2c2c66bb6ff502b0ed02794f1432b6572a069e7afbe1777cde1465d32f35a6ec5747bc064f929688d4034d0e19") << OP_CHECKSIG;

        txNew[124].vin.resize(1);
        txNew[124].vout.resize(1);
        txNew[124].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[124].vout[0].nValue = 28922.43254466 * COIN;
        txNew[124].vout[0].scriptPubKey = CScript() << ParseHex("04ebfb8ba437ec725d5368ec65123a188dd1d8e7fea189044ae0f5496ce6f6a9f825c8440212472448e52e170928dd6093c3737c4c0d56d0b55a6460c31e6c45b7") << OP_CHECKSIG;

        txNew[125].vin.resize(1);
        txNew[125].vout.resize(1);
        txNew[125].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[125].vout[0].nValue = 267475.41085634 * COIN;
        txNew[125].vout[0].scriptPubKey = CScript() << ParseHex("04c96ddce0a8a87820f77802d7484c4b7e24a158a4357cbd87792ed224464442bb29e419cf2e5cc131d108eda43331ed523219697b535636e91ccda7173575e884") << OP_CHECKSIG;

        txNew[126].vin.resize(1);
        txNew[126].vout.resize(1);
        txNew[126].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[126].vout[0].nValue = 24788.93081904 * COIN;
        txNew[126].vout[0].scriptPubKey = CScript() << ParseHex("0405d4501caf1d252a342dff84afcb35e57883f0158fcb424e60b2b78026c4ff97fcb2c0e8cdc14b1696483b319943c6e70b51875420584efd9b9d747171d1958b") << OP_CHECKSIG;

        txNew[127].vin.resize(1);
        txNew[127].vout.resize(1);
        txNew[127].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[127].vout[0].nValue = 2947.98167879 * COIN;
        txNew[127].vout[0].scriptPubKey = CScript() << ParseHex("04477bd65703279a8437d2c211a516bd6dbc6e84292dcbaef055a13d0919a4a7e25821f763e5fd2c562bf28ad98ef1b1b923d99453d6d4bee6c6936f630266fe36") << OP_CHECKSIG;

        txNew[128].vin.resize(1);
        txNew[128].vout.resize(1);
        txNew[128].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[128].vout[0].nValue = 2876.07968663 * COIN;
        txNew[128].vout[0].scriptPubKey = CScript() << ParseHex("0400a91279ebf40af49f4f2867e65ce8a5364505c8c70ce1d5baafdcc0d90c55570b356599dbda367f3713cc25add7f846032823a453ec0ea22fcf32614035854f") << OP_CHECKSIG;

        txNew[129].vin.resize(1);
        txNew[129].vout.resize(1);
        txNew[129].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[129].vout[0].nValue = 1150.43187465 * COIN;
        txNew[129].vout[0].scriptPubKey = CScript() << ParseHex("048dbee5ef060ba4986ef279de47bdda6f49e1c54116ba533d99735bf803b2fed609e33c111d4f6120d7dac751d48cc58364256f4de34b94b3a5d97137a5adbc36") << OP_CHECKSIG;

        txNew[130].vin.resize(1);
        txNew[130].vout.resize(1);
        txNew[130].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[130].vout[0].nValue = 1639.36542138 * COIN;
        txNew[130].vout[0].scriptPubKey = CScript() << ParseHex("04e7a5dba7eaf851fa77529493ca6cbeafcf573abed87c4864c830c2b0d0a913111739a7581c993e4256b59872d7e45bf894554b4b4520a4339de898ab4fab9284") << OP_CHECKSIG;

        txNew[131].vin.resize(1);
        txNew[131].vout.resize(1);
        txNew[131].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[131].vout[0].nValue = 100662.78903196 * COIN;
        txNew[131].vout[0].scriptPubKey = CScript() << ParseHex("04e8ca8906663f47b1706ea5fd880ffc4f01a0e63ef676eb893bde5efb676cd44795b75812e146245c54c9e47d90ce1ae4762a57cab691ab1cd463f6dd67e2203f") << OP_CHECKSIG;

        txNew[132].vin.resize(1);
        txNew[132].vout.resize(1);
        txNew[132].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[132].vout[0].nValue = 67875.48060441 * COIN;
        txNew[132].vout[0].scriptPubKey = CScript() << ParseHex("044e0c6fa6fb923fb0a99671aa69dc7978db612fa7c2d3f40f99bda1d0b6943a68526c0ec2c799fb330a09b2cf65fd68d0dc7d6c3af1765588d094cdb7723a6a4c") << OP_CHECKSIG;

        txNew[133].vin.resize(1);
        txNew[133].vout.resize(1);
        txNew[133].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[133].vout[0].nValue = 14380.39843314 * COIN;
        txNew[133].vout[0].scriptPubKey = CScript() << ParseHex("04e8ca8906663f47b1706ea5fd880ffc4f01a0e63ef676eb893bde5efb676cd44795b75812e146245c54c9e47d90ce1ae4762a57cab691ab1cd463f6dd67e2203f") << OP_CHECKSIG;

        txNew[134].vin.resize(1);
        txNew[134].vout.resize(1);
        txNew[134].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[134].vout[0].nValue = 10411.40846559 * COIN;
        txNew[134].vout[0].scriptPubKey = CScript() << ParseHex("04531f47502eb2cbdded88867247c97803db43a478b1267b14b30ce8c2604335fddc4b6b42c10d4ce5b05b3f5bba9cdb1a6005244717f48a3bb0b205134c910894") << OP_CHECKSIG;

        txNew[135].vin.resize(1);
        txNew[135].vout.resize(1);
        txNew[135].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[135].vout[0].nValue = 1438.03984331 * COIN;
        txNew[135].vout[0].scriptPubKey = CScript() << ParseHex("04e8ca8906663f47b1706ea5fd880ffc4f01a0e63ef676eb893bde5efb676cd44795b75812e146245c54c9e47d90ce1ae4762a57cab691ab1cd463f6dd67e2203f") << OP_CHECKSIG;

        txNew[136].vin.resize(1);
        txNew[136].vout.resize(1);
        txNew[136].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[136].vout[0].nValue = 5752.15937325 * COIN;
        txNew[136].vout[0].scriptPubKey = CScript() << ParseHex("04e542e7856f1427942f550acb028ef68a13e42d7380c1bb1554279cf68410aac6770bc6b2fe7db863c3718aea989ce5d53d586f7be5f086a58b897adc1198ef7f") << OP_CHECKSIG;

        txNew[137].vin.resize(1);
        txNew[137].vout.resize(1);
        txNew[137].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[137].vout[0].nValue = 5752.15937325 * COIN;
        txNew[137].vout[0].scriptPubKey = CScript() << ParseHex("0411e1993a1656742e28272a8e67693fd03f7e12843f2e22f49ee5d1b6f77700f4acf9459994d9f3ae919b136f6b0bc83a482f341067c2e1056f0baebdea718570") << OP_CHECKSIG;

        txNew[138].vin.resize(1);
        txNew[138].vout.resize(1);
        txNew[138].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[138].vout[0].nValue = 5737.77897482 * COIN;
        txNew[138].vout[0].scriptPubKey = CScript() << ParseHex("04b9e3002aaab7b712d37d4a94d1ac2c20fc13e31728f28b790b5aacefdca2b3dba54a6a5c7cdc2c7c26abf90fa89ce841ef627468548e2e8563cc1b75cd54abe1") << OP_CHECKSIG;

        txNew[139].vin.resize(1);
        txNew[139].vout.resize(1);
        txNew[139].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[139].vout[0].nValue = 43141.19529941 * COIN;
        txNew[139].vout[0].scriptPubKey = CScript() << ParseHex("04f08bf2890cfb78eeb6c7cc503241da9560609074214a85f6a30101e07c61228b9dd20b0c07c9b91bec7575e8af1e72bfc7db0dd14edb802ab8eeefa5c24ba725") << OP_CHECKSIG;

        txNew[140].vin.resize(1);
        txNew[140].vout.resize(1);
        txNew[140].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[140].vout[0].nValue = 5752.15937325 * COIN;
        txNew[140].vout[0].scriptPubKey = CScript() << ParseHex("04b7d8bea1c1c197e6b9e6af7309562494ac360b9f792503fb1fae1fb70176fbebcec7320646c676841d28403c24ae9e5fab25eee44d4b04e17155b248571e211c") << OP_CHECKSIG;

        txNew[141].vin.resize(1);
        txNew[141].vout.resize(1);
        txNew[141].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[141].vout[0].nValue = 287.60796866 * COIN;
        txNew[141].vout[0].scriptPubKey = CScript() << ParseHex("047b126b838418348e4393f32ce2246c4048f7be27ca413a1a22156ae9fb6085d916913534148c1b535c5746245703441f40fa5df4c042eb3ed3c61476a896a3b4") << OP_CHECKSIG;

        txNew[142].vin.resize(1);
        txNew[142].vout.resize(1);
        txNew[142].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[142].vout[0].nValue = 7190.19921657 * COIN;
        txNew[142].vout[0].scriptPubKey = CScript() << ParseHex("04bb29821c0249da97df15f291860fc36947c914847c628460e362a6b705a5b61fc751cbb5f40bdb8ce8c340558141a198898c28c00aa5a4c5f6a15692709cf445") << OP_CHECKSIG;

        txNew[143].vin.resize(1);
        txNew[143].vout.resize(1);
        txNew[143].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[143].vout[0].nValue = 2323.87238679 * COIN;
        txNew[143].vout[0].scriptPubKey = CScript() << ParseHex("046e965a2e40d0861ecf3d3dad1a5d858224ddd91631477d4d9bb274abc54d2f257d93f5db69092d2edb2d1487c59b0dbf0a68e02044049d0f332a79d7d1a6e472") << OP_CHECKSIG;

        txNew[144].vin.resize(1);
        txNew[144].vout.resize(1);
        txNew[144].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[144].vout[0].nValue = 719.01992166 * COIN;
        txNew[144].vout[0].scriptPubKey = CScript() << ParseHex("04346f80651a3e3eb9afd55b608e77242e8826af1f0d9b96174314d0f288a50f27777eaeca67b5b3349207a798c847bcbecf0d9dc869fbb4102ad333b34bffa17a") << OP_CHECKSIG;

        txNew[145].vin.resize(1);
        txNew[145].vout.resize(1);
        txNew[145].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[145].vout[0].nValue = 575.21593733 * COIN;
        txNew[145].vout[0].scriptPubKey = CScript() << ParseHex("0415a65e0c4bea9f00f98729fd03cf9e68bd8b15a9c10ec0b52f8c9c3a88221e7a213d7259ba76c3a8c6505c5af6956cc9aa882ff4dee3c27dd758933bab8ec716") << OP_CHECKSIG;

        txNew[146].vin.resize(1);
        txNew[146].vout.resize(1);
        txNew[146].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[146].vout[0].nValue = 6341.15173228 * COIN;
        txNew[146].vout[0].scriptPubKey = CScript() << ParseHex("040a54ac2761d7fcdbae5e1e75bfdb01022b49b628046b10058ab6658f60ea7ef7daa0b60d2a0a1a9792bb1b3c12139152590b1b9e7f2cb8746554bc2781118763") << OP_CHECKSIG;

        txNew[147].vin.resize(1);
        txNew[147].vout.resize(1);
        txNew[147].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[147].vout[0].nValue = 2387.1461399 * COIN;
        txNew[147].vout[0].scriptPubKey = CScript() << ParseHex("041ca665c8ac5e2e1bc08a75fba60e133b19ef71d82a5af7194fd5a7ebea939d55ef11918ac054a0301a7679b49b27095d7840890b5c3b7ae8fd323a6e4967b494") << OP_CHECKSIG;

        txNew[148].vin.resize(1);
        txNew[148].vout.resize(1);
        txNew[148].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[148].vout[0].nValue = 1207.55426852 * COIN;
        txNew[148].vout[0].scriptPubKey = CScript() << ParseHex("047e1ef77a78977f6a720e9fd223ec98e15ed90bef91629b50d1ddb54a673c1a5614017c99be29906d25d7a5eb46aaca338cc6da72e350a2f60ba94b6dadc4f7e6") << OP_CHECKSIG;

        txNew[149].vin.resize(1);
        txNew[149].vout.resize(1);
        txNew[149].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[149].vout[0].nValue = 23401.80218791 * COIN;
        txNew[149].vout[0].scriptPubKey = CScript() << ParseHex("0489a8c6303ecd9d57bea0ae43c1569f0af6b35fd3c46bcff5c07951f977a63c47f65e04648cba855862424f9998bffa75d16039895bfe65ea9024b593bcb29633") << OP_CHECKSIG;

        txNew[150].vin.resize(1);
        txNew[150].vout.resize(1);
        txNew[150].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[150].vout[0].nValue = 5749.28329357 * COIN;
        txNew[150].vout[0].scriptPubKey = CScript() << ParseHex("0417a02a907d733f979cdf9faab2a2fabbe6268ef71b41c90c144402de2df1266237a285d8dad5ed0c5b64379efe43d41159b9170db97c64f8308cb07e0ed9b3b6") << OP_CHECKSIG;

        txNew[151].vin.resize(1);
        txNew[151].vout.resize(1);
        txNew[151].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[151].vout[0].nValue = 712.69254635 * COIN;
        txNew[151].vout[0].scriptPubKey = CScript() << ParseHex("040d28239553f559908f2b5c9797123e0e274df944ec2ae79bafd72e9e4c28a2d33d69ddc5b3fd92b8d2e402255026ebcd4eb85016704dc72fa42767d97c3f85ac") << OP_CHECKSIG;

        txNew[152].vin.resize(1);
        txNew[152].vout.resize(1);
        txNew[152].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[152].vout[0].nValue = 1348.88137303 * COIN;
        txNew[152].vout[0].scriptPubKey = CScript() << ParseHex("047e1ef77a78977f6a720e9fd223ec98e15ed90bef91629b50d1ddb54a673c1a5614017c99be29906d25d7a5eb46aaca338cc6da72e350a2f60ba94b6dadc4f7e6") << OP_CHECKSIG;

        txNew[153].vin.resize(1);
        txNew[153].vout.resize(1);
        txNew[153].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[153].vout[0].nValue = 11504.31874651 * COIN;
        txNew[153].vout[0].scriptPubKey = CScript() << ParseHex("0449a635966ae8b1bb4268384554d1ca65ff7b4bb4e08b1ecbbbf8f5ba05fac04297d0e627ab30468cccc112e7511fd318cde54c1d01edff9f95bb06ef160568a8") << OP_CHECKSIG;

        txNew[154].vin.resize(1);
        txNew[154].vout.resize(1);
        txNew[154].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[154].vout[0].nValue = 7190.19921657 * COIN;
        txNew[154].vout[0].scriptPubKey = CScript() << ParseHex("0442783dee2c92694129dafd9f8e18da3b237f0b880ab475ec14118f1fa116265a852fe0096a29e43142cda0b4887ab4f68353139e3ebf3ed5ae5ad630efe17e9b") << OP_CHECKSIG;

        txNew[155].vin.resize(1);
        txNew[155].vout.resize(1);
        txNew[155].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[155].vout[0].nValue = 295.5387584 * COIN;
        txNew[155].vout[0].scriptPubKey = CScript() << ParseHex("0422c93d26ac789c86b986e1b56c3df9fe9a774a3dc3b40e185a6b0fc9eb5989f00401fdee0d3182ade6b32d97eec07c59318236c3be13f787eef72af9a8906787") << OP_CHECKSIG;

        txNew[156].vin.resize(1);
        txNew[156].vout.resize(1);
        txNew[156].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[156].vout[0].nValue = 862.82390599 * COIN;
        txNew[156].vout[0].scriptPubKey = CScript() << ParseHex("04fe02e611c7576cea9477e8dc095388c927907b5d7da5f8c66c7e693036b687cf5d916296499a6d5620c563639ac665b721065e3c84276b9ed62d10598fa3a90c") << OP_CHECKSIG;

        txNew[157].vin.resize(1);
        txNew[157].vout.resize(1);
        txNew[157].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[157].vout[0].nValue = 2876.07968663 * COIN;
        txNew[157].vout[0].scriptPubKey = CScript() << ParseHex("04c2dfef238182894485bc9ed7573b9929a6b50e3103117b5385c018ece6dbc9c7203a8684e63a6a0769df77934e111b45a486a6aa14bbe89128db4e1486c629c6") << OP_CHECKSIG;

        txNew[158].vin.resize(1);
        txNew[158].vout.resize(1);
        txNew[158].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[158].vout[0].nValue = 1998.87538221 * COIN;
        txNew[158].vout[0].scriptPubKey = CScript() << ParseHex("04c0c527d90d8a6f9966245d133ceea071ad38f833b9da9d72b37bfa9d954429a620c020ef92f18c7796ad6b19318126c50fff1ea86c1793a0ff2e986bd8dcae88") << OP_CHECKSIG;

        txNew[159].vin.resize(1);
        txNew[159].vout.resize(1);
        txNew[159].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[159].vout[0].nValue = 287.60796866 * COIN;
        txNew[159].vout[0].scriptPubKey = CScript() << ParseHex("04bc799b964af579ed31386b8db94af932818bc2c74750dede794a2a9b874d3796156b90c4654d0711c0c495c634358f110eafc44e3c5303850cab624072522598") << OP_CHECKSIG;

        txNew[160].vin.resize(1);
        txNew[160].vout.resize(1);
        txNew[160].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[160].vout[0].nValue = 575.21593733 * COIN;
        txNew[160].vout[0].scriptPubKey = CScript() << ParseHex("04a35ab81c5aa75e4fcd5e4afac20eb5821cad14f78085eb92ef9c0ff416ca838d31f727750ce82daf5412e4b08b9c4f1916cdac7aac0cffe20cb84639ee7da633") << OP_CHECKSIG;

        txNew[161].vin.resize(1);
        txNew[161].vout.resize(1);
        txNew[161].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[161].vout[0].nValue = 14380.39843314 * COIN;
        txNew[161].vout[0].scriptPubKey = CScript() << ParseHex("04840fa1ee36bacfb8f5cdfbf6f02eb3232f7c42e71052a420583c41582b807fff51550b94808c351f3ee37216a81753772da58fb8e03be6c505d0f96ca536281b") << OP_CHECKSIG;

        txNew[162].vin.resize(1);
        txNew[162].vout.resize(1);
        txNew[162].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[162].vout[0].nValue = 2861.65902308 * COIN;
        txNew[162].vout[0].scriptPubKey = CScript() << ParseHex("04842161c2818fcd5d69a16d1e02734eb340f2603f46abe0f4126cda910824cbde90f5b2c1fdcd5530fb8e59db91daa8b648d55452f9085d0f3281b75b9687778e") << OP_CHECKSIG;

        txNew[163].vin.resize(1);
        txNew[163].vout.resize(1);
        txNew[163].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[163].vout[0].nValue = 1438.03984331 * COIN;
        txNew[163].vout[0].scriptPubKey = CScript() << ParseHex("04e0b1f64296a3180a26bcc6fcdc4d9d2edf91668fdeb9e63c5eb10f921f65e994f3019046b42faccc5c0a87cb98361d01c755a83e88fb1088da69a3e37fc67e32") << OP_CHECKSIG;

        txNew[164].vin.resize(1);
        txNew[164].vout.resize(1);
        txNew[164].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[164].vout[0].nValue = 6672.50487298 * COIN;
        txNew[164].vout[0].scriptPubKey = CScript() << ParseHex("04c0c527d90d8a6f9966245d133ceea071ad38f833b9da9d72b37bfa9d954429a620c020ef92f18c7796ad6b19318126c50fff1ea86c1793a0ff2e986bd8dcae88") << OP_CHECKSIG;

        txNew[165].vin.resize(1);
        txNew[165].vout.resize(1);
        txNew[165].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[165].vout[0].nValue = 7190.19921657 * COIN;
        txNew[165].vout[0].scriptPubKey = CScript() << ParseHex("04c4ffb3b773dc2578ec917d85914b9318cdef0ec90e77d527629d0f938f3c00e1ec3c729208dc325d0c851ea7428879ca01e7f22e227fc3ee435bf5a8985ecc14") << OP_CHECKSIG;

        txNew[166].vin.resize(1);
        txNew[166].vout.resize(1);
        txNew[166].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[166].vout[0].nValue = 287.60796866 * COIN;
        txNew[166].vout[0].scriptPubKey = CScript() << ParseHex("0436ce6c13a201a59bb5a43d76fd7a7aa8c19ac63fc195b67697a5c8435870e79e67620c6f70a2eb43ba55e419e24ff443e5c0bd89c808edc9d86803cbf41d0771") << OP_CHECKSIG;

        txNew[167].vin.resize(1);
        txNew[167].vout.resize(1);
        txNew[167].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[167].vout[0].nValue = 14386.15059251 * COIN;
        txNew[167].vout[0].scriptPubKey = CScript() << ParseHex("0407108ffbdf64d3620424b05ea9434942def144d5359b5bee4ca1f1a27df7fa1fab48477399a71588db0f57c7d37a11b117a95d42db67a936ed4c7eb569f70d7b") << OP_CHECKSIG;

        txNew[168].vin.resize(1);
        txNew[168].vout.resize(1);
        txNew[168].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[168].vout[0].nValue = 5752.15937325 * COIN;
        txNew[168].vout[0].scriptPubKey = CScript() << ParseHex("041b5f6fc0a4f58010692aea3e5c67beaf930a9e4a173d81889320b02fdde2b086b315ad9aa1a45ce2786484bfab1e99665874a71db4929c7462700b642e53d342") << OP_CHECKSIG;

        txNew[169].vin.resize(1);
        txNew[169].vout.resize(1);
        txNew[169].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[169].vout[0].nValue = 5752.15937325 * COIN;
        txNew[169].vout[0].scriptPubKey = CScript() << ParseHex("0496d0c782bac98a6362919c7e4c4536b49b14baa83908c37441952f9ce9c2733c7d586665928297d34d5e12e8a0883615e7b5dacd7d6eb4a47d60092affba1ea9") << OP_CHECKSIG;

        txNew[170].vin.resize(1);
        txNew[170].vout.resize(1);
        txNew[170].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[170].vout[0].nValue = 575215.93732547 * COIN;
        txNew[170].vout[0].scriptPubKey = CScript() << ParseHex("0452955f4a625684fd2899f307fa87fad2f6acb369cb75c5583de88b37b81e7a830337fe358d845695ccb96359f2715b934d3f697c67dd6d596a0eace00aa1ae4b") << OP_CHECKSIG;

        txNew[171].vin.resize(1);
        txNew[171].vout.resize(1);
        txNew[171].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[171].vout[0].nValue = 28760.79686627 * COIN;
        txNew[171].vout[0].scriptPubKey = CScript() << ParseHex("0481528349984d04bab49119be7f870ac8253c79545c9e7593ce8d564e137e5ef2adf2d0b556715f6dba65f19349d3a5d0c0b11addf83c692fc2c3a0fd38dc2891") << OP_CHECKSIG;

        txNew[172].vin.resize(1);
        txNew[172].vout.resize(1);
        txNew[172].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[172].vout[0].nValue = 300000 * COIN;
        txNew[172].vout[0].scriptPubKey = CScript() << ParseHex("048733c0bd937b9751a899adb843c495fbb264d617d0b2eb23307540ff9a68be76ce5260af2284d7afbcf585bd365324711fb62e2b5ab0c543bdf2f93f400bdd6f") << OP_CHECKSIG;

        txNew[173].vin.resize(1);
        txNew[173].vout.resize(1);
        txNew[173].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[173].vout[0].nValue = 400000 * COIN;
        txNew[173].vout[0].scriptPubKey = CScript() << ParseHex("049918fa3d8e0c24ea09b45aab531ec863c140af86041bedf45a86f8b764d0d8a621fcd7f368cb28c49c962d144f8a82119ee7357106bf70c1609c7ac0b07ed355") << OP_CHECKSIG;

        txNew[174].vin.resize(1);
        txNew[174].vout.resize(1);
        txNew[174].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[174].vout[0].nValue = 200000 * COIN;
        txNew[174].vout[0].scriptPubKey = CScript() << ParseHex("04af75f183c45a3aa35289aa83ec5a3b3d863b4bfab96b8c530243bdc34b3ac5a20e2fa90cc621b66f9f49d2b4167599f030e5c90ffc15477ca44ad1b49ca76fb4") << OP_CHECKSIG;

        txNew[175].vin.resize(1);
        txNew[175].vout.resize(1);
        txNew[175].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[175].vout[0].nValue = 100000 * COIN;
        txNew[175].vout[0].scriptPubKey = CScript() << ParseHex("04b2c904ae2200ebe763b447545324f5e1ff548fd55c1160555aa6c2f9926527fab2f49c2649190ae3031a8e7a058b7fd610fae2518b3a0e15621cb0d7dc1783bb") << OP_CHECKSIG;

        txNew[176].vin.resize(1);
        txNew[176].vout.resize(1);
        txNew[176].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[176].vout[0].nValue = 400000 * COIN;
        txNew[176].vout[0].scriptPubKey = CScript() << ParseHex("042d29cf124cc46489dc919d5388911da116a18a1dda5796af25cadcff8c39defb9b206adf970320687d30b7bdfdcab6f3f9f3a74521c9246c7a56508f6154077c") << OP_CHECKSIG;

        txNew[177].vin.resize(1);
        txNew[177].vout.resize(1);
        txNew[177].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[177].vout[0].nValue = 100000 * COIN;
        txNew[177].vout[0].scriptPubKey = CScript() << ParseHex("045a45b7df792261ed0f53eb0eda2e611ef82e7faad7376864f03be048f241f896240e927318afd41d62d9154d1c73a519f3f338080697af81786037c49fe5218f") << OP_CHECKSIG;

        txNew[178].vin.resize(1);
        txNew[178].vout.resize(1);
        txNew[178].vin[0].scriptSig = CScript() << 486604799 << CBigNum(4) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        txNew[178].vout[0].nValue = 1500000 * COIN + 18; // Padding for microscopic rounding errors to get an even 8M
        txNew[178].vout[0].scriptPubKey = CScript() << ParseHex("041e6837fde1a4fc30136d0835657e72a4d8dcc12a899817cc959e1956d5b361d0d4dd834a93e1ffa68b300375fa8055ba0dcbc0932f29e4fbad68192e34bcc2a7") << OP_CHECKSIG;

        int64 sum = 0;
        CBlock block;
        for (int i = 0; i < 179; i++) {
            sum += txNew[i].vout[0].nValue;
            block.vtx.push_back(txNew[i]);
        }

        printf("Genesis block sum = %"PRI64d"\n", sum);
        assert(sum/COIN == 8000000);

        block.hashPrevBlock = 0;
        block.hashMerkleRoot = block.BuildMerkleTree();
        block.setVersion(1);
        block.setSupply(sum/COIN);
        block.nTime    = 1394274360;
        block.nBits    = 0x1e1fffe0; // HEFTY1 is very expensive, so starts with lower difficulty
        block.nNonce   = 2102389708;
        block.nReward  = 0; /* Starting block reward */

        if (fTestNet)
        {
            block.nTime  = 1394274360;
            block.nNonce = 2657063146;
        }

        //// debug print
        printf("merkle prehash  %s\n", block.hashMerkleRoot.ToString().c_str());
        uint256 hash = block.GetHash();
        printf("hash    0x%s\n", hash.ToString().c_str());
        printf("genesis 0x%s\n", hashGenesisBlock.ToString().c_str());
        printf("merkle  0x%s\n", block.hashMerkleRoot.ToString().c_str());

        assert(block.getSupply() == 8000000);
        assert(block.hashMerkleRoot
               == uint256("0x708bd24bf8a6e599ec6d74d893dfb4f2c32beeabce41f16c401adb691921d557"));

        // If genesis block hash does not match, then generate new genesis hash.
        if (false && block.GetHash() != hashGenesisBlock)
        {
            uint256 hashTarget = CBigNum().SetCompact(block.nBits).getuint256();
            printf("* Mining genesis block...\n");
            printf("    Target %s\n", hashTarget.ToString().c_str());

            // This will figure out a valid hash and Nonce if you're
            // creating a different genesis block:
            uint64 nStart = GetTimeMillis();
            uint256 thash;
            loop
            {
                thash = block.GetHash();
                if (thash <= hashTarget)
                    break;
                if ((block.nNonce & 0xFFFFF) == 0)
                {
                    printf("    Search: nonce %08x hash %s\n",
                           block.nNonce, thash.ToString().c_str());
                }
                ++block.nNonce;
                if (block.nNonce == 0)
                {
                    printf("    Nonce wrapped: incrementing time\n");
                    ++block.nTime;
                }
            }

            if (CheckProofOfWork(thash, block.nBits)) {
                printf("* Solved genesis block! nonce %u hash 0x%s time %u\n",
                       block.nNonce, thash.ToString().c_str(), block.nTime);
                printf("* Mining took %"PRI64d" minutes\n", (GetTimeMillis() - nStart)/60000);
            }
        }

        block.print();
        assert(hash == hashGenesisBlock);

        // Start new block file
        try {
            unsigned int nBlockSize = ::GetSerializeSize(block, SER_DISK, CLIENT_VERSION);
            CDiskBlockPos blockPos;
            CValidationState state;
            if (!FindBlockPos(state, blockPos, nBlockSize+8, 0, block.nTime))
                return error("LoadBlockIndex() : FindBlockPos failed");
            if (!block.WriteToDisk(blockPos))
                return error("LoadBlockIndex() : writing genesis block to disk failed");
            if (!block.AddToBlockIndex(state, blockPos))
                return error("LoadBlockIndex() : genesis block not accepted");
        } catch(std::runtime_error &e) {
            return error("LoadBlockIndex() : failed to initialize block database: %s", e.what());
        }
    }

    return true;
}



void PrintBlockTree()
{
    // pre-compute tree structure
    map<CBlockIndex*, vector<CBlockIndex*> > mapNext;
    for (map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.begin(); mi != mapBlockIndex.end(); ++mi)
    {
        CBlockIndex* pindex = (*mi).second;
        mapNext[pindex->pprev].push_back(pindex);
        // test
        //while (rand() % 3 == 0)
        //    mapNext[pindex->pprev].push_back(pindex);
    }

    vector<pair<int, CBlockIndex*> > vStack;
    vStack.push_back(make_pair(0, pindexGenesisBlock));

    int nPrevCol = 0;
    while (!vStack.empty())
    {
        int nCol = vStack.back().first;
        CBlockIndex* pindex = vStack.back().second;
        vStack.pop_back();

        // print split or gap
        if (nCol > nPrevCol)
        {
            for (int i = 0; i < nCol-1; i++)
                printf("| ");
            printf("|\\\n");
        }
        else if (nCol < nPrevCol)
        {
            for (int i = 0; i < nCol; i++)
                printf("| ");
            printf("|\n");
       }
        nPrevCol = nCol;

        // print columns
        for (int i = 0; i < nCol; i++)
            printf("| ");

        // print item
        CBlock block;
        block.ReadFromDisk(pindex);
        printf("%d (blk%05u.dat:0x%x)  %s  tx %"PRIszu"",
            pindex->nHeight,
            pindex->GetBlockPos().nFile, pindex->GetBlockPos().nPos,
            DateTimeStrFormat("%Y-%m-%d %H:%M:%S", block.GetBlockTime()).c_str(),
            block.vtx.size());

        PrintWallets(block);

        // put the main time-chain first
        vector<CBlockIndex*>& vNext = mapNext[pindex];
        for (unsigned int i = 0; i < vNext.size(); i++)
        {
            if (vNext[i]->pnext)
            {
                swap(vNext[0], vNext[i]);
                break;
            }
        }

        // iterate children
        for (unsigned int i = 0; i < vNext.size(); i++)
            vStack.push_back(make_pair(nCol+i, vNext[i]));
    }
}

bool LoadExternalBlockFile(FILE* fileIn, CDiskBlockPos *dbp)
{
    int64 nStart = GetTimeMillis();

    int nLoaded = 0;
    try {
        CBufferedFile blkdat(fileIn, 2*MAX_BLOCK_SIZE, MAX_BLOCK_SIZE+8, SER_DISK, CLIENT_VERSION);
        uint64 nStartByte = 0;
        if (dbp) {
            // (try to) skip already indexed part
            CBlockFileInfo info;
            if (pblocktree->ReadBlockFileInfo(dbp->nFile, info)) {
                nStartByte = info.nSize;
                blkdat.Seek(info.nSize);
            }
        }
        uint64 nRewind = blkdat.GetPos();
        while (blkdat.good() && !blkdat.eof()) {
            boost::this_thread::interruption_point();

            blkdat.SetPos(nRewind);
            nRewind++; // start one byte further next time, in case of failure
            blkdat.SetLimit(); // remove former limit
            unsigned int nSize = 0;
            try {
                // locate a header
                unsigned char buf[4];
                blkdat.FindByte(pchMessageStart[0]);
                nRewind = blkdat.GetPos()+1;
                blkdat >> FLATDATA(buf);
                if (memcmp(buf, pchMessageStart, 4))
                    continue;
                // read size
                blkdat >> nSize;
                if (nSize < 80 || nSize > MAX_BLOCK_SIZE)
                    continue;
            } catch (std::exception &e) {
                // no valid block header found; don't complain
                break;
            }
            try {
                // read block
                uint64 nBlockPos = blkdat.GetPos();
                blkdat.SetLimit(nBlockPos + nSize);
                CBlock block;
                blkdat >> block;
                nRewind = blkdat.GetPos();

                // process block
                if (nBlockPos >= nStartByte) {
                    LOCK(cs_main);
                    if (dbp)
                        dbp->nPos = nBlockPos;
                    CValidationState state;
                    if (ProcessBlock(state, NULL, &block, dbp))
                        nLoaded++;
                    if (state.IsError())
                        break;
                }
            } catch (std::exception &e) {
                printf("%s() : Deserialize or I/O error caught during load\n", __PRETTY_FUNCTION__);
            }
        }
        fclose(fileIn);
    } catch(std::runtime_error &e) {
        AbortNode(_("Error: system error: ") + e.what());
    }
    if (nLoaded > 0)
        printf("Loaded %i blocks from external file in %"PRI64d"ms\n", nLoaded, GetTimeMillis() - nStart);
    return nLoaded > 0;
}










//////////////////////////////////////////////////////////////////////////////
//
// CAlert
//

extern map<uint256, CAlert> mapAlerts;
extern CCriticalSection cs_mapAlerts;

string GetWarnings(string strFor)
{
    int nPriority = 0;
    string strStatusBar;
    string strRPC;

    if (GetBoolArg("-testsafemode"))
        strRPC = "test";

    if (!CLIENT_VERSION_IS_RELEASE)
        strStatusBar = _("This is a pre-release test build - use at your own risk - do not use for mining or merchant applications");

    // Misc warnings like out of disk space and clock is wrong
    if (strMiscWarning != "")
    {
        nPriority = 1000;
        strStatusBar = strMiscWarning;
    }

    // Longer invalid proof-of-work chain
    if (pindexBest && nBestInvalidWork > nBestChainWork + (pindexBest->GetBlockWork() * 6).getuint256())
    {
        nPriority = 2000;
        strStatusBar = strRPC = _("Warning: Displayed transactions may not be correct! You may need to upgrade, or other nodes may need to upgrade.");
    }

    // Alerts
    {
        LOCK(cs_mapAlerts);
        BOOST_FOREACH(PAIRTYPE(const uint256, CAlert)& item, mapAlerts)
        {
            const CAlert& alert = item.second;
            if (alert.AppliesToMe() && alert.nPriority > nPriority)
            {
                nPriority = alert.nPriority;
                strStatusBar = alert.strStatusBar;
            }
        }
    }

    if (strFor == "statusbar")
        return strStatusBar;
    else if (strFor == "rpc")
        return strRPC;
    assert(!"GetWarnings() : invalid parameter");
    return "error";
}








//////////////////////////////////////////////////////////////////////////////
//
// Messages
//


bool static AlreadyHave(const CInv& inv)
{
    switch (inv.type)
    {
    case MSG_TX:
        {
            bool txInMap = false;
            {
                LOCK(mempool.cs);
                txInMap = mempool.exists(inv.hash);
            }
            return txInMap || mapOrphanTransactions.count(inv.hash) ||
                pcoinsTip->HaveCoins(inv.hash);
        }
    case MSG_BLOCK:
        return mapBlockIndex.count(inv.hash) ||
               mapOrphanBlocks.count(inv.hash);
    }
    // Don't know what it is, just say we already got one
    return true;
}




// The message start string is designed to be unlikely to occur in normal data.
// The characters are rarely used upper ASCII, not valid as UTF-8, and produce
// a large 4-byte int at any alignment.
unsigned char pchMessageStart[4] = { 0xf9, 0xbe, 0xb4, 0xd9 };


void static ProcessGetData(CNode* pfrom)
{
    std::deque<CInv>::iterator it = pfrom->vRecvGetData.begin();

    vector<CInv> vNotFound;

    while (it != pfrom->vRecvGetData.end()) {
        // Don't bother if send buffer is too full to respond anyway
        if (pfrom->nSendSize >= SendBufferSize())
            break;

        const CInv &inv = *it;
        {
            boost::this_thread::interruption_point();
            it++;

            if (inv.type == MSG_BLOCK || inv.type == MSG_FILTERED_BLOCK)
            {
                // Send block from disk
                map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(inv.hash);
                if (mi != mapBlockIndex.end())
                {
                    CBlock block;
                    block.ReadFromDisk((*mi).second);
                    if (inv.type == MSG_BLOCK)
                        pfrom->PushMessage("block", block);
                    else // MSG_FILTERED_BLOCK)
                    {
                        LOCK(pfrom->cs_filter);
                        if (pfrom->pfilter)
                        {
                            CMerkleBlock merkleBlock(block, *pfrom->pfilter);
                            pfrom->PushMessage("merkleblock", merkleBlock);
                            // CMerkleBlock just contains hashes, so also push any transactions in the block the client did not see
                            // This avoids hurting performance by pointlessly requiring a round-trip
                            // Note that there is currently no way for a node to request any single transactions we didnt send here -
                            // they must either disconnect and retry or request the full block.
                            // Thus, the protocol spec specified allows for us to provide duplicate txn here,
                            // however we MUST always provide at least what the remote peer needs
                            typedef std::pair<unsigned int, uint256> PairType;
                            BOOST_FOREACH(PairType& pair, merkleBlock.vMatchedTxn)
                                if (!pfrom->setInventoryKnown.count(CInv(MSG_TX, pair.second)))
                                    pfrom->PushMessage("tx", block.vtx[pair.first]);
                        }
                        // else
                            // no response
                    }

                    // Trigger them to send a getblocks request for the next batch of inventory
                    if (inv.hash == pfrom->hashContinue)
                    {
                        // Bypass PushInventory, this must send even if redundant,
                        // and we want it right after the last block so they don't
                        // wait for other stuff first.
                        vector<CInv> vInv;
                        vInv.push_back(CInv(MSG_BLOCK, hashBestChain));
                        pfrom->PushMessage("inv", vInv);
                        pfrom->hashContinue = 0;
                    }
                }
            }
            else if (inv.IsKnownType())
            {
                // Send stream from relay memory
                bool pushed = false;
                {
                    LOCK(cs_mapRelay);
                    map<CInv, CDataStream>::iterator mi = mapRelay.find(inv);
                    if (mi != mapRelay.end()) {
                        pfrom->PushMessage(inv.GetCommand(), (*mi).second);
                        pushed = true;
                    }
                }
                if (!pushed && inv.type == MSG_TX) {
                    LOCK(mempool.cs);
                    if (mempool.exists(inv.hash)) {
                        CTransaction tx = mempool.lookup(inv.hash);
                        CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
                        ss.reserve(1000);
                        ss << tx;
                        pfrom->PushMessage("tx", ss);
                        pushed = true;
                    }
                }
                if (!pushed) {
                    vNotFound.push_back(inv);
                }
            }

            // Track requests for our stuff.
            Inventory(inv.hash);
        }
    }

    pfrom->vRecvGetData.erase(pfrom->vRecvGetData.begin(), it);

    if (!vNotFound.empty()) {
        // Let the peer know that we didn't find what it asked for, so it doesn't
        // have to wait around forever. Currently only SPV clients actually care
        // about this message: it's needed when they are recursively walking the
        // dependencies of relevant unconfirmed transactions. SPV clients want to
        // do that because they want to know about (and store and rebroadcast and
        // risk analyze) the dependencies of transactions relevant to them, without
        // having to download the entire memory pool.
        pfrom->PushMessage("notfound", vNotFound);
    }
}

bool static ProcessMessage(CNode* pfrom, string strCommand, CDataStream& vRecv)
{
    RandAddSeedPerfmon();
    if (fDebug)
        printf("received: %s (%"PRIszu" bytes)\n", strCommand.c_str(), vRecv.size());
    if (mapArgs.count("-dropmessagestest") && GetRand(atoi(mapArgs["-dropmessagestest"])) == 0)
    {
        printf("dropmessagestest DROPPING RECV MESSAGE\n");
        return true;
    }





    if (strCommand == "version")
    {
        // Each connection can only send one version message
        if (pfrom->nVersion != 0)
        {
            pfrom->Misbehaving(1);
            return false;
        }

        int64 nTime;
        CAddress addrMe;
        CAddress addrFrom;
        uint64 nNonce = 1;
        vRecv >> pfrom->nVersion >> pfrom->nServices >> nTime >> addrMe;
        if (pfrom->nVersion < MIN_PROTO_VERSION)
        {
            // Since February 20, 2012, the protocol is initiated at version 209,
            // and earlier versions are no longer supported
            printf("partner %s using obsolete version %i; disconnecting\n", pfrom->addr.ToString().c_str(), pfrom->nVersion);
            pfrom->fDisconnect = true;
            return false;
        }

        if (pfrom->nVersion == 10300)
            pfrom->nVersion = 300;
        if (!vRecv.empty())
            vRecv >> addrFrom >> nNonce;
        if (!vRecv.empty())
            vRecv >> pfrom->strSubVer;
        if (!vRecv.empty())
            vRecv >> pfrom->nStartingHeight;
        if (!vRecv.empty())
            vRecv >> pfrom->fRelayTxes; // set to true after we get the first filter* message
        else
            pfrom->fRelayTxes = true;

        if (pfrom->fInbound && addrMe.IsRoutable())
        {
            pfrom->addrLocal = addrMe;
            SeenLocal(addrMe);
        }

        // Disconnect if we connected to ourself
        if (nNonce == nLocalHostNonce && nNonce > 1)
        {
            printf("connected to self at %s, disconnecting\n", pfrom->addr.ToString().c_str());
            pfrom->fDisconnect = true;
            return true;
        }

        // Be shy and don't send version until we hear
        if (pfrom->fInbound)
            pfrom->PushVersion();

        pfrom->fClient = !(pfrom->nServices & NODE_NETWORK);

        AddTimeData(pfrom->addr, nTime);

        // Change version
        pfrom->PushMessage("verack");
        pfrom->ssSend.SetVersion(min(pfrom->nVersion, PROTOCOL_VERSION));

        if (!pfrom->fInbound)
        {
            // Advertise our address
            if (!fNoListen && !IsInitialBlockDownload())
            {
                CAddress addr = GetLocalAddress(&pfrom->addr);
                if (addr.IsRoutable())
                    pfrom->PushAddress(addr);
            }

            // Get recent addresses
            if (pfrom->fOneShot || pfrom->nVersion >= CADDR_TIME_VERSION || addrman.size() < 1000)
            {
                pfrom->PushMessage("getaddr");
                pfrom->fGetAddr = true;
            }
            addrman.Good(pfrom->addr);
        } else {
            if (((CNetAddr)pfrom->addr) == (CNetAddr)addrFrom)
            {
                addrman.Add(addrFrom, addrFrom);
                addrman.Good(addrFrom);
            }
        }

        // Relay alerts
        {
            LOCK(cs_mapAlerts);
            BOOST_FOREACH(PAIRTYPE(const uint256, CAlert)& item, mapAlerts)
                item.second.RelayTo(pfrom);
        }

        pfrom->fSuccessfullyConnected = true;

        printf("receive version message: version %d, blocks=%d, us=%s, them=%s, peer=%s\n", pfrom->nVersion, pfrom->nStartingHeight, addrMe.ToString().c_str(), addrFrom.ToString().c_str(), pfrom->addr.ToString().c_str());

        cPeerBlockCounts.input(pfrom->nStartingHeight);
    }


    else if (pfrom->nVersion == 0)
    {
        // Must have a version message before anything else
        pfrom->Misbehaving(1);
        return false;
    }


    else if (strCommand == "verack")
    {
        pfrom->SetRecvVersion(min(pfrom->nVersion, PROTOCOL_VERSION));
    }


    else if (strCommand == "addr")
    {
        vector<CAddress> vAddr;
        vRecv >> vAddr;

        // Don't want addr from older versions unless seeding
        if (pfrom->nVersion < CADDR_TIME_VERSION && addrman.size() > 1000)
            return true;
        if (vAddr.size() > 1000)
        {
            pfrom->Misbehaving(20);
            return error("message addr size() = %"PRIszu"", vAddr.size());
        }

        // Store the new addresses
        vector<CAddress> vAddrOk;
        int64 nNow = GetAdjustedTime();
        int64 nSince = nNow - 10 * 60;
        BOOST_FOREACH(CAddress& addr, vAddr)
        {
            boost::this_thread::interruption_point();

            if (addr.nTime <= 100000000 || addr.nTime > nNow + 10 * 60)
                addr.nTime = nNow - 5 * 24 * 60 * 60;
            pfrom->AddAddressKnown(addr);
            bool fReachable = IsReachable(addr);
            if (addr.nTime > nSince && !pfrom->fGetAddr && vAddr.size() <= 10 && addr.IsRoutable())
            {
                // Relay to a limited number of other nodes
                {
                    LOCK(cs_vNodes);
                    // Use deterministic randomness to send to the same nodes for 24 hours
                    // at a time so the setAddrKnowns of the chosen nodes prevent repeats
                    static uint256 hashSalt;
                    if (hashSalt == 0)
                        hashSalt = GetRandHash();
                    uint64 hashAddr = addr.GetHash();
                    uint256 hashRand = hashSalt ^ (hashAddr<<32) ^ ((GetTime()+hashAddr)/(24*60*60));
                    hashRand = Hash(BEGIN(hashRand), END(hashRand));
                    multimap<uint256, CNode*> mapMix;
                    BOOST_FOREACH(CNode* pnode, vNodes)
                    {
                        if (pnode->nVersion < CADDR_TIME_VERSION)
                            continue;
                        unsigned int nPointer;
                        memcpy(&nPointer, &pnode, sizeof(nPointer));
                        uint256 hashKey = hashRand ^ nPointer;
                        hashKey = Hash(BEGIN(hashKey), END(hashKey));
                        mapMix.insert(make_pair(hashKey, pnode));
                    }
                    int nRelayNodes = fReachable ? 2 : 1; // limited relaying of addresses outside our network(s)
                    for (multimap<uint256, CNode*>::iterator mi = mapMix.begin(); mi != mapMix.end() && nRelayNodes-- > 0; ++mi)
                        ((*mi).second)->PushAddress(addr);
                }
            }
            // Do not store addresses outside our network
            if (fReachable)
                vAddrOk.push_back(addr);
        }
        addrman.Add(vAddrOk, pfrom->addr, 2 * 60 * 60);
        if (vAddr.size() < 1000)
            pfrom->fGetAddr = false;
        if (pfrom->fOneShot)
            pfrom->fDisconnect = true;
    }


    else if (strCommand == "inv")
    {
        vector<CInv> vInv;
        vRecv >> vInv;
        if (vInv.size() > MAX_INV_SZ)
        {
            pfrom->Misbehaving(20);
            return error("message inv size() = %"PRIszu"", vInv.size());
        }

        // find last block in inv vector
        unsigned int nLastBlock = (unsigned int)(-1);
        for (unsigned int nInv = 0; nInv < vInv.size(); nInv++) {
            if (vInv[vInv.size() - 1 - nInv].type == MSG_BLOCK) {
                nLastBlock = vInv.size() - 1 - nInv;
                break;
            }
        }
        for (unsigned int nInv = 0; nInv < vInv.size(); nInv++)
        {
            const CInv &inv = vInv[nInv];

            boost::this_thread::interruption_point();
            pfrom->AddInventoryKnown(inv);

            bool fAlreadyHave = AlreadyHave(inv);
            if (fDebug)
                printf("  got inventory: %s  %s\n", inv.ToString().c_str(), fAlreadyHave ? "have" : "new");

            if (!fAlreadyHave) {
                if (!fImporting && !fReindex)
                    pfrom->AskFor(inv);
            } else if (inv.type == MSG_BLOCK && mapOrphanBlocks.count(inv.hash)) {
                pfrom->PushGetBlocks(pindexBest, GetOrphanRoot(mapOrphanBlocks[inv.hash]));
            } else if (nInv == nLastBlock) {
                // In case we are on a very long side-chain, it is possible that we already have
                // the last block in an inv bundle sent in response to getblocks. Try to detect
                // this situation and push another getblocks to continue.
                pfrom->PushGetBlocks(mapBlockIndex[inv.hash], uint256(0));
                if (fDebug)
                    printf("force request: %s\n", inv.ToString().c_str());
            }

            // Track requests for our stuff
            Inventory(inv.hash);
        }
    }


    else if (strCommand == "getdata")
    {
        vector<CInv> vInv;
        vRecv >> vInv;
        if (vInv.size() > MAX_INV_SZ)
        {
            pfrom->Misbehaving(20);
            return error("message getdata size() = %"PRIszu"", vInv.size());
        }

        if (fDebugNet || (vInv.size() != 1))
            printf("received getdata (%"PRIszu" invsz)\n", vInv.size());

        if ((fDebugNet && vInv.size() > 0) || (vInv.size() == 1))
            printf("received getdata for: %s\n", vInv[0].ToString().c_str());

        pfrom->vRecvGetData.insert(pfrom->vRecvGetData.end(), vInv.begin(), vInv.end());
        ProcessGetData(pfrom);
    }


    else if (strCommand == "getblocks")
    {
        CBlockLocator locator;
        uint256 hashStop;
        vRecv >> locator >> hashStop;

        // Find the last block the caller has in the main chain
        CBlockIndex* pindex = locator.GetBlockIndex();

        // Send the rest of the chain
        if (pindex)
            pindex = pindex->pnext;
        int nLimit = 500;
        printf("getblocks %d to %s limit %d\n", (pindex ? pindex->nHeight : -1), hashStop.ToString().c_str(), nLimit);
        for (; pindex; pindex = pindex->pnext)
        {
            if (pindex->GetBlockHash() == hashStop)
            {
                printf("  getblocks stopping at %d %s\n", pindex->nHeight, pindex->GetBlockHash().ToString().c_str());
                break;
            }
            pfrom->PushInventory(CInv(MSG_BLOCK, pindex->GetBlockHash()));
            if (--nLimit <= 0)
            {
                // When this block is requested, we'll send an inv that'll make them
                // getblocks the next batch of inventory.
                printf("  getblocks stopping at limit %d %s\n", pindex->nHeight, pindex->GetBlockHash().ToString().c_str());
                pfrom->hashContinue = pindex->GetBlockHash();
                break;
            }
        }
    }


    else if (strCommand == "getheaders")
    {
        CBlockLocator locator;
        uint256 hashStop;
        vRecv >> locator >> hashStop;

        CBlockIndex* pindex = NULL;
        if (locator.IsNull())
        {
            // If locator is null, return the hashStop block
            map<uint256, CBlockIndex*>::iterator mi = mapBlockIndex.find(hashStop);
            if (mi == mapBlockIndex.end())
                return true;
            pindex = (*mi).second;
        }
        else
        {
            // Find the last block the caller has in the main chain
            pindex = locator.GetBlockIndex();
            if (pindex)
                pindex = pindex->pnext;
        }

        // we must use CBlocks, as CBlockHeaders won't include the 0x00 nTx count at the end
        vector<CBlock> vHeaders;
        int nLimit = 2000;
        printf("getheaders %d to %s\n", (pindex ? pindex->nHeight : -1), hashStop.ToString().c_str());
        for (; pindex; pindex = pindex->pnext)
        {
            vHeaders.push_back(pindex->GetBlockHeader());
            if (--nLimit <= 0 || pindex->GetBlockHash() == hashStop)
                break;
        }
        pfrom->PushMessage("headers", vHeaders);
    }


    else if (strCommand == "tx")
    {
        vector<uint256> vWorkQueue;
        vector<uint256> vEraseQueue;
        CDataStream vMsg(vRecv);
        CTransaction tx;
        vRecv >> tx;

        CInv inv(MSG_TX, tx.GetHash());
        pfrom->AddInventoryKnown(inv);

        // Truncate messages to the size of the tx in them
        unsigned int nSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
        unsigned int oldSize = vMsg.size();
        if (nSize < oldSize) {
            vMsg.resize(nSize);
            printf("truncating oversized TX %s (%u -> %u)\n",
                   tx.GetHash().ToString().c_str(),
                   oldSize, nSize);
        }

        bool fMissingInputs = false;
        CValidationState state;
        if (tx.AcceptToMemoryPool(state, true, true, &fMissingInputs))
        {
            RelayTransaction(tx, inv.hash, vMsg);
            mapAlreadyAskedFor.erase(inv);
            vWorkQueue.push_back(inv.hash);
            vEraseQueue.push_back(inv.hash);

            // Recursively process any orphan transactions that depended on this one
            for (unsigned int i = 0; i < vWorkQueue.size(); i++)
            {
                uint256 hashPrev = vWorkQueue[i];
                for (map<uint256, CDataStream*>::iterator mi = mapOrphanTransactionsByPrev[hashPrev].begin();
                     mi != mapOrphanTransactionsByPrev[hashPrev].end();
                     ++mi)
                {
                    const CDataStream& vMsg = *((*mi).second);
                    CTransaction tx;
                    CDataStream(vMsg) >> tx;
                    CInv inv(MSG_TX, tx.GetHash());
                    bool fMissingInputs2 = false;
                    // Use a dummy CValidationState so someone can't setup nodes to counter-DoS based on orphan resolution (that is, feeding people an invalid transaction based on LegitTxX in order to get anyone relaying LegitTxX banned)
                    CValidationState stateDummy;

                    if (tx.AcceptToMemoryPool(stateDummy, true, true, &fMissingInputs2))
                    {
                        printf("   accepted orphan tx %s\n", inv.hash.ToString().c_str());
                        RelayTransaction(tx, inv.hash, vMsg);
                        mapAlreadyAskedFor.erase(inv);
                        vWorkQueue.push_back(inv.hash);
                        vEraseQueue.push_back(inv.hash);
                    }
                    else if (!fMissingInputs2)
                    {
                        // invalid or too-little-fee orphan
                        vEraseQueue.push_back(inv.hash);
                        printf("   removed orphan tx %s\n", inv.hash.ToString().c_str());
                    }
                }
            }

            BOOST_FOREACH(uint256 hash, vEraseQueue)
                EraseOrphanTx(hash);
        }
        else if (fMissingInputs)
        {
            AddOrphanTx(vMsg);

            // DoS prevention: do not allow mapOrphanTransactions to grow unbounded
            unsigned int nEvicted = LimitOrphanTxSize(MAX_ORPHAN_TRANSACTIONS);
            if (nEvicted > 0)
                printf("mapOrphan overflow, removed %u tx\n", nEvicted);
        }
        int nDoS;
        if (state.IsInvalid(nDoS))
            pfrom->Misbehaving(nDoS);
    }


    else if (strCommand == "block" && !fImporting && !fReindex) // Ignore blocks received while importing
    {
        CBlock block;
        vRecv >> block;

        printf("received block %s\n", block.GetHash().ToString().c_str());
        // block.print();

        CInv inv(MSG_BLOCK, block.GetHash());
        pfrom->AddInventoryKnown(inv);

        CValidationState state;
        if (ProcessBlock(state, pfrom, &block))
            mapAlreadyAskedFor.erase(inv);
        int nDoS;
        if (state.IsInvalid(nDoS))
            pfrom->Misbehaving(nDoS);
        else {
            LogBlock(block);

            // Adjust block reward vote limit
            AdjustBlockRewardVoteLimit(pindexBest);

            // Calculate the average block time
            CBigNum bnUnused; float nUnused, nAvgTimespan;
            CalcWindowedAvgs(pindexBest, nDiffWindow, 0,
                             AbsTime((int64)block.nTime, pindexBest->GetBlockTime()),
                             bnUnused, nAvgTimespan, nUnused);

            pvoteMain->UpdateParams((unsigned int)pindexBest->nHeight, nAvgTimespan,
                                    nBlockRewardVoteSpan, GetCurrentBlockReward(pindexBest),
                                    GetNextBlockReward(pindexBest), nBlockRewardVoteLimit,
                                    nPhase, pindexBest->getSupply(), nTarget, nMaxSupply);
        }
    }


    else if (strCommand == "getaddr")
    {
        pfrom->vAddrToSend.clear();
        vector<CAddress> vAddr = addrman.GetAddr();
        BOOST_FOREACH(const CAddress &addr, vAddr)
            pfrom->PushAddress(addr);
    }


    else if (strCommand == "mempool")
    {
        std::vector<uint256> vtxid;
        LOCK2(mempool.cs, pfrom->cs_filter);
        mempool.queryHashes(vtxid);
        vector<CInv> vInv;
        BOOST_FOREACH(uint256& hash, vtxid) {
            CInv inv(MSG_TX, hash);
            if ((pfrom->pfilter && pfrom->pfilter->IsRelevantAndUpdate(mempool.lookup(hash), hash)) ||
               (!pfrom->pfilter))
                vInv.push_back(inv);
            if (vInv.size() == MAX_INV_SZ)
                break;
        }
        if (vInv.size() > 0)
            pfrom->PushMessage("inv", vInv);
    }


    else if (strCommand == "ping")
    {
        if (pfrom->nVersion > BIP0031_VERSION)
        {
            uint64 nonce = 0;
            vRecv >> nonce;
            // Echo the message back with the nonce. This allows for two useful features:
            //
            // 1) A remote node can quickly check if the connection is operational
            // 2) Remote nodes can measure the latency of the network thread. If this node
            //    is overloaded it won't respond to pings quickly and the remote node can
            //    avoid sending us more work, like chain download requests.
            //
            // The nonce stops the remote getting confused between different pings: without
            // it, if the remote node sends a ping once per second and this node takes 5
            // seconds to respond to each, the 5th ping the remote sends would appear to
            // return very quickly.
            pfrom->PushMessage("pong", nonce);
        }
    }


    else if (strCommand == "alert")
    {
        CAlert alert;
        vRecv >> alert;

        uint256 alertHash = alert.GetHash();
        if (pfrom->setKnown.count(alertHash) == 0)
        {
            if (alert.ProcessAlert())
            {
                // Relay
                pfrom->setKnown.insert(alertHash);
                {
                    LOCK(cs_vNodes);
                    BOOST_FOREACH(CNode* pnode, vNodes)
                        alert.RelayTo(pnode);
                }
            }
            else {
                // Small DoS penalty so peers that send us lots of
                // duplicate/expired/invalid-signature/whatever alerts
                // eventually get banned.
                // This isn't a Misbehaving(100) (immediate ban) because the
                // peer might be an older or different implementation with
                // a different signature key, etc.
                pfrom->Misbehaving(10);
            }
        }
    }


    else if (strCommand == "filterload")
    {
        CBloomFilter filter;
        vRecv >> filter;

        if (!filter.IsWithinSizeConstraints())
            // There is no excuse for sending a too-large filter
            pfrom->Misbehaving(100);
        else
        {
            LOCK(pfrom->cs_filter);
            delete pfrom->pfilter;
            pfrom->pfilter = new CBloomFilter(filter);
        }
        pfrom->fRelayTxes = true;
    }


    else if (strCommand == "filteradd")
    {
        vector<unsigned char> vData;
        vRecv >> vData;

        // Nodes must NEVER send a data item > 520 bytes (the max size for a script data object,
        // and thus, the maximum size any matched object can have) in a filteradd message
        if (vData.size() > MAX_SCRIPT_ELEMENT_SIZE)
        {
            pfrom->Misbehaving(100);
        } else {
            LOCK(pfrom->cs_filter);
            if (pfrom->pfilter)
                pfrom->pfilter->insert(vData);
            else
                pfrom->Misbehaving(100);
        }
    }


    else if (strCommand == "filterclear")
    {
        LOCK(pfrom->cs_filter);
        delete pfrom->pfilter;
        pfrom->pfilter = NULL;
        pfrom->fRelayTxes = true;
    }


    else
    {
        // Ignore unknown commands for extensibility
    }


    // Update the last seen time for this node's address
    if (pfrom->fNetworkNode)
        if (strCommand == "version" || strCommand == "addr" || strCommand == "inv" || strCommand == "getdata" || strCommand == "ping")
            AddressCurrentlyConnected(pfrom->addr);


    return true;
}

// requires LOCK(cs_vRecvMsg)
bool ProcessMessages(CNode* pfrom)
{
    //if (fDebug)
    //    printf("ProcessMessages(%zu messages)\n", pfrom->vRecvMsg.size());

    //
    // Message format
    //  (4) message start
    //  (12) command
    //  (4) size
    //  (4) checksum
    //  (x) data
    //
    bool fOk = true;

    if (!pfrom->vRecvGetData.empty())
        ProcessGetData(pfrom);

    std::deque<CNetMessage>::iterator it = pfrom->vRecvMsg.begin();
    while (!pfrom->fDisconnect && it != pfrom->vRecvMsg.end()) {
        // Don't bother if send buffer is too full to respond anyway
        if (pfrom->nSendSize >= SendBufferSize())
            break;

        // get next message
        CNetMessage& msg = *it;

        //if (fDebug)
        //    printf("ProcessMessages(message %u msgsz, %zu bytes, complete:%s)\n",
        //            msg.hdr.nMessageSize, msg.vRecv.size(),
        //            msg.complete() ? "Y" : "N");

        // end, if an incomplete message is found
        if (!msg.complete())
            break;

        // at this point, any failure means we can delete the current message
        it++;

        // Scan for message start
        if (memcmp(msg.hdr.pchMessageStart, pchMessageStart, sizeof(pchMessageStart)) != 0) {
            printf("\n\nPROCESSMESSAGE: INVALID MESSAGESTART\n\n");
            fOk = false;
            break;
        }

        // Read header
        CMessageHeader& hdr = msg.hdr;
        if (!hdr.IsValid())
        {
            printf("\n\nPROCESSMESSAGE: ERRORS IN HEADER %s\n\n\n", hdr.GetCommand().c_str());
            continue;
        }
        string strCommand = hdr.GetCommand();

        // Message size
        unsigned int nMessageSize = hdr.nMessageSize;

        // Checksum
        CDataStream& vRecv = msg.vRecv;
        uint256 hash = Hash(vRecv.begin(), vRecv.begin() + nMessageSize);
        unsigned int nChecksum = 0;
        memcpy(&nChecksum, &hash, sizeof(nChecksum));
        if (nChecksum != hdr.nChecksum)
        {
            printf("ProcessMessages(%s, %u bytes) : CHECKSUM ERROR nChecksum=%08x hdr.nChecksum=%08x\n",
               strCommand.c_str(), nMessageSize, nChecksum, hdr.nChecksum);
            continue;
        }

        // Process message
        bool fRet = false;
        try
        {
            {
                LOCK(cs_main);
                fRet = ProcessMessage(pfrom, strCommand, vRecv);
            }
            boost::this_thread::interruption_point();
        }
        catch (std::ios_base::failure& e)
        {
            if (strstr(e.what(), "end of data"))
            {
                // Allow exceptions from under-length message on vRecv
                printf("ProcessMessages(%s, %u bytes) : Exception '%s' caught, normally caused by a message being shorter than its stated length\n", strCommand.c_str(), nMessageSize, e.what());
            }
            else if (strstr(e.what(), "size too large"))
            {
                // Allow exceptions from over-long size
                printf("ProcessMessages(%s, %u bytes) : Exception '%s' caught\n", strCommand.c_str(), nMessageSize, e.what());
            }
            else
            {
                PrintExceptionContinue(&e, "ProcessMessages()");
            }
        }
        catch (boost::thread_interrupted) {
            throw;
        }
        catch (std::exception& e) {
            PrintExceptionContinue(&e, "ProcessMessages()");
        } catch (...) {
            PrintExceptionContinue(NULL, "ProcessMessages()");
        }

        if (!fRet)
            printf("ProcessMessage(%s, %u bytes) FAILED\n", strCommand.c_str(), nMessageSize);
    }

    // In case the connection got shut down, its receive buffer was wiped
    if (!pfrom->fDisconnect)
        pfrom->vRecvMsg.erase(pfrom->vRecvMsg.begin(), it);

    return fOk;
}


bool SendMessages(CNode* pto, bool fSendTrickle)
{
    TRY_LOCK(cs_main, lockMain);
    if (lockMain) {
        // Don't send anything until we get their version message
        if (pto->nVersion == 0)
            return true;

        // Keep-alive ping. We send a nonce of zero because we don't use it anywhere
        // right now.
        if (pto->nLastSend && GetTime() - pto->nLastSend > 30 * 60 && pto->vSendMsg.empty()) {
            uint64 nonce = 0;
            if (pto->nVersion > BIP0031_VERSION)
                pto->PushMessage("ping", nonce);
            else
                pto->PushMessage("ping");
        }

        // Start block sync
        if (pto->fStartSync && !fImporting && !fReindex) {
            pto->fStartSync = false;
            pto->PushGetBlocks(pindexBest, uint256(0));
        }

        // Resend wallet transactions that haven't gotten in a block yet
        // Except during reindex, importing and IBD, when old wallet
        // transactions become unconfirmed and spams other nodes.
        if (!fReindex && !fImporting && !IsInitialBlockDownload())
        {
            ResendWalletTransactions();
        }

        // Address refresh broadcast
        static int64 nLastRebroadcast;
        if (!IsInitialBlockDownload() && (GetTime() - nLastRebroadcast > 24 * 60 * 60))
        {
            {
                LOCK(cs_vNodes);
                BOOST_FOREACH(CNode* pnode, vNodes)
                {
                    // Periodically clear setAddrKnown to allow refresh broadcasts
                    if (nLastRebroadcast)
                        pnode->setAddrKnown.clear();

                    // Rebroadcast our address
                    if (!fNoListen)
                    {
                        CAddress addr = GetLocalAddress(&pnode->addr);
                        if (addr.IsRoutable())
                            pnode->PushAddress(addr);
                    }
                }
            }
            nLastRebroadcast = GetTime();
        }

        //
        // Message: addr
        //
        if (fSendTrickle)
        {
            vector<CAddress> vAddr;
            vAddr.reserve(pto->vAddrToSend.size());
            BOOST_FOREACH(const CAddress& addr, pto->vAddrToSend)
            {
                // returns true if wasn't already contained in the set
                if (pto->setAddrKnown.insert(addr).second)
                {
                    vAddr.push_back(addr);
                    // receiver rejects addr messages larger than 1000
                    if (vAddr.size() >= 1000)
                    {
                        pto->PushMessage("addr", vAddr);
                        vAddr.clear();
                    }
                }
            }
            pto->vAddrToSend.clear();
            if (!vAddr.empty())
                pto->PushMessage("addr", vAddr);
        }


        //
        // Message: inventory
        //
        vector<CInv> vInv;
        vector<CInv> vInvWait;
        {
            LOCK(pto->cs_inventory);
            vInv.reserve(pto->vInventoryToSend.size());
            vInvWait.reserve(pto->vInventoryToSend.size());
            BOOST_FOREACH(const CInv& inv, pto->vInventoryToSend)
            {
                if (pto->setInventoryKnown.count(inv))
                    continue;

                // trickle out tx inv to protect privacy
                if (inv.type == MSG_TX && !fSendTrickle)
                {
                    // 1/4 of tx invs blast to all immediately
                    static uint256 hashSalt;
                    if (hashSalt == 0)
                        hashSalt = GetRandHash();
                    uint256 hashRand = inv.hash ^ hashSalt;
                    hashRand = Hash(BEGIN(hashRand), END(hashRand));
                    bool fTrickleWait = ((hashRand & 3) != 0);

                    // always trickle our own transactions
                    if (!fTrickleWait)
                    {
                        CWalletTx wtx;
                        if (GetTransaction(inv.hash, wtx))
                            if (wtx.fFromMe)
                                fTrickleWait = true;
                    }

                    if (fTrickleWait)
                    {
                        vInvWait.push_back(inv);
                        continue;
                    }
                }

                // returns true if wasn't already contained in the set
                if (pto->setInventoryKnown.insert(inv).second)
                {
                    vInv.push_back(inv);
                    if (vInv.size() >= 1000)
                    {
                        pto->PushMessage("inv", vInv);
                        vInv.clear();
                    }
                }
            }
            pto->vInventoryToSend = vInvWait;
        }
        if (!vInv.empty())
            pto->PushMessage("inv", vInv);


        //
        // Message: getdata
        //
        vector<CInv> vGetData;
        int64 nNow = GetTime() * 1000000;
        while (!pto->mapAskFor.empty() && (*pto->mapAskFor.begin()).first <= nNow)
        {
            const CInv& inv = (*pto->mapAskFor.begin()).second;
            if (!AlreadyHave(inv))
            {
                if (fDebugNet)
                    printf("sending getdata: %s\n", inv.ToString().c_str());
                vGetData.push_back(inv);
                if (vGetData.size() >= 1000)
                {
                    pto->PushMessage("getdata", vGetData);
                    vGetData.clear();
                }
            }
            pto->mapAskFor.erase(pto->mapAskFor.begin());
        }
        if (!vGetData.empty())
            pto->PushMessage("getdata", vGetData);

    }
    return true;
}

//////////////////////////////////////////////////////////////////////////////
//
// HeavycoinMiner
//

int static FormatHashBlocks(void* pbuffer, unsigned int len)
{
    unsigned char* pdata = (unsigned char*)pbuffer;
    unsigned int blocks = 1 + ((len + 8) / 64);
    unsigned char* pend = pdata + 64 * blocks;
    memset(pdata + len, 0, 64 * blocks - len);
    pdata[len] = 0x80;
    unsigned int bits = len * 8;
    pend[-1] = (bits >> 0) & 0xff;
    pend[-2] = (bits >> 8) & 0xff;
    pend[-3] = (bits >> 16) & 0xff;
    pend[-4] = (bits >> 24) & 0xff;
    return blocks;
}

void SHA256Transform(void* pstate, void* pdata, const void* pinit)
{
    SHA256_CTX ctx;
    unsigned char data[64];

    SHA256_Init(&ctx);

    if (pinit)
    {
        for (int i = 0; i < 8; i++)
            ctx.h[i] = ((uint32_t*)pinit)[i];
    }

    for (size_t i = 0; i < 16; i++)
        ((uint32_t*)data)[i] = ByteReverse(((uint32_t*)pdata)[i]);

    SHA256_Update(&ctx, data, sizeof(data));

    for (int i = 0; i < 8; i++)
        ((uint32_t*)pstate)[i] = ctx.h[i];
}

void HEFTY1Transform(void* pstate, uint32_t *spongeOut, void* pinput,
                     const void* pinit, uint32_t* spongeIn)
{
    HEFTY1_CTX ctx;
    unsigned char data[64];

    HEFTY1_Init(&ctx);

    for (int i = 0; i < 16; i++)
        ((uint32_t*)data)[i] = ByteReverse(((uint32_t*)pinput)[i]);

    if (pinit)
    {
        for (int i = 0; i < 8; i++)
            ctx.h[i] = ((uint32_t*)pinit)[i];
    }

    if (spongeIn)
    {
        for (int i = 0; i < HEFTY1_SPONGE_WORDS; i++)
            ctx.sponge[i] = spongeIn[i];
    }

    HEFTY1_Update(&ctx, data, sizeof(data));
    for (int i = 0; i < 8; i++)
        ((uint32_t*)pstate)[i] = ctx.h[i];

    if (spongeOut)
    {
        for (int i = 0; i < HEFTY1_SPONGE_WORDS; i++)
            spongeOut[i] = ctx.sponge[i];
    }
}

// Some explaining would be appreciated
class COrphan
{
public:
    CTransaction* ptx;
    set<uint256> setDependsOn;
    double dPriority;
    double dFeePerKb;

    COrphan(CTransaction* ptxIn)
    {
        ptx = ptxIn;
        dPriority = dFeePerKb = 0;
    }

    void print() const
    {
        printf("COrphan(hash=%s, dPriority=%.1f, dFeePerKb=%.1f)\n",
               ptx->GetHash().ToString().c_str(), dPriority, dFeePerKb);
        BOOST_FOREACH(uint256 hash, setDependsOn)
            printf("   setDependsOn %s\n", hash.ToString().c_str());
    }
};


uint64 nLastBlockTx = 0;
uint64 nLastBlockSize = 0;

// We want to sort transactions by priority and fee, so:
typedef boost::tuple<double, double, CTransaction*> TxPriority;
class TxPriorityCompare
{
    bool byFee;
public:
    TxPriorityCompare(bool _byFee) : byFee(_byFee) { }
    bool operator()(const TxPriority& a, const TxPriority& b)
    {
        if (byFee)
        {
            if (a.get<1>() == b.get<1>())
                return a.get<0>() < b.get<0>();
            return a.get<1>() < b.get<1>();
        }
        else
        {
            if (a.get<0>() == b.get<0>())
                return a.get<1>() < b.get<1>();
            return a.get<0>() < b.get<0>();
        }
    }
};

CBlockTemplate* CreateNewBlock(CReserveKey& reservekey)
{
    // Create new block
    auto_ptr<CBlockTemplate> pblocktemplate(new CBlockTemplate());
    if(!pblocktemplate.get())
        return NULL;
    CBlock *pblock = &pblocktemplate->block; // pointer for convenience

    // Create coinbase tx
    CTransaction txNew;
    txNew.vin.resize(1);
    txNew.vin[0].prevout.SetNull();
    txNew.vout.resize(1);
    CPubKey pubkey;
    if (!reservekey.GetReservedKey(pubkey))
        return NULL;
    txNew.vout[0].scriptPubKey << pubkey << OP_CHECKSIG;

    // Add our coinbase tx as first transaction
    pblock->vtx.push_back(txNew);
    pblocktemplate->vTxFees.push_back(-1); // updated at end
    pblocktemplate->vTxSigOps.push_back(-1); // updated at end

    // Largest block you're willing to create:
    unsigned int nBlockMaxSize = GetArg("-blockmaxsize", MAX_BLOCK_SIZE_GEN/2);
    // Limit to betweeen 1K and MAX_BLOCK_SIZE-1K for sanity:
    nBlockMaxSize = std::max((unsigned int)1000, std::min((unsigned int)(MAX_BLOCK_SIZE-1000), nBlockMaxSize));

    // Special compatibility rule before 15 May: limit size to 500,000 bytes:
    if (GetAdjustedTime() < 1368576000)
        nBlockMaxSize = std::min(nBlockMaxSize, (unsigned int)(MAX_BLOCK_SIZE_GEN));

    // How much of the block should be dedicated to high-priority transactions,
    // included regardless of the fees they pay
    unsigned int nBlockPrioritySize = GetArg("-blockprioritysize", 27000);
    nBlockPrioritySize = std::min(nBlockMaxSize, nBlockPrioritySize);

    // Minimum block size you want to create; block will be filled with free transactions
    // until there are no more or the block reaches this size:
    unsigned int nBlockMinSize = GetArg("-blockminsize", 0);
    nBlockMinSize = std::min(nBlockMaxSize, nBlockMinSize);

    // Collect memory pool transactions into the block
    int64 nFees = 0;
    {
        LOCK2(cs_main, mempool.cs);
        CBlockIndex* pindexPrev = pindexBest;
        CCoinsViewCache view(*pcoinsTip, true);

        // Priority order to process transactions
        list<COrphan> vOrphan; // list memory doesn't move
        map<uint256, vector<COrphan*> > mapDependers;
        bool fPrintPriority = GetBoolArg("-printpriority");

        // This vector will be sorted into a priority queue:
        vector<TxPriority> vecPriority;
        vecPriority.reserve(mempool.mapTx.size());
        for (map<uint256, CTransaction>::iterator mi = mempool.mapTx.begin(); mi != mempool.mapTx.end(); ++mi)
        {
            CTransaction& tx = (*mi).second;
            if (tx.IsCoinBase() || !tx.IsFinal())
                continue;

            COrphan* porphan = NULL;
            double dPriority = 0;
            int64 nTotalIn = 0;
            bool fMissingInputs = false;
            BOOST_FOREACH(const CTxIn& txin, tx.vin)
            {
                // Read prev transaction
                if (!view.HaveCoins(txin.prevout.hash))
                {
                    // This should never happen; all transactions in the memory
                    // pool should connect to either transactions in the chain
                    // or other transactions in the memory pool.
                    if (!mempool.mapTx.count(txin.prevout.hash))
                    {
                        printf("ERROR: mempool transaction missing input\n");
                        if (fDebug) assert("mempool transaction missing input" == 0);
                        fMissingInputs = true;
                        if (porphan)
                            vOrphan.pop_back();
                        break;
                    }

                    // Has to wait for dependencies
                    if (!porphan)
                    {
                        // Use list for automatic deletion
                        vOrphan.push_back(COrphan(&tx));
                        porphan = &vOrphan.back();
                    }
                    mapDependers[txin.prevout.hash].push_back(porphan);
                    porphan->setDependsOn.insert(txin.prevout.hash);
                    nTotalIn += mempool.mapTx[txin.prevout.hash].vout[txin.prevout.n].nValue;
                    continue;
                }
                const CCoins &coins = view.GetCoins(txin.prevout.hash);

                int64 nValueIn = coins.vout[txin.prevout.n].nValue;
                nTotalIn += nValueIn;

                int nConf = pindexPrev->nHeight - coins.nHeight + 1;

                dPriority += (double)nValueIn * nConf;
            }
            if (fMissingInputs) continue;

            // Priority is sum(valuein * age) / txsize
            unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
            dPriority /= nTxSize;

            // This is a more accurate fee-per-kilobyte than is used by the client code, because the
            // client code rounds up the size to the nearest 1K. That's good, because it gives an
            // incentive to create smaller transactions.
            double dFeePerKb =  double(nTotalIn-tx.GetValueOut()) / (double(nTxSize)/1000.0);

            if (porphan)
            {
                porphan->dPriority = dPriority;
                porphan->dFeePerKb = dFeePerKb;
            }
            else
                vecPriority.push_back(TxPriority(dPriority, dFeePerKb, &(*mi).second));
        }

        // Collect transactions into block
        uint64 nBlockSize = 1000;
        uint64 nBlockTx = 0;
        int nBlockSigOps = 100;
        bool fSortedByFee = (nBlockPrioritySize <= 0);

        TxPriorityCompare comparer(fSortedByFee);
        std::make_heap(vecPriority.begin(), vecPriority.end(), comparer);

        while (!vecPriority.empty())
        {
            // Take highest priority transaction off the priority queue:
            double dPriority = vecPriority.front().get<0>();
            double dFeePerKb = vecPriority.front().get<1>();
            CTransaction& tx = *(vecPriority.front().get<2>());

            std::pop_heap(vecPriority.begin(), vecPriority.end(), comparer);
            vecPriority.pop_back();

            // Size limits
            unsigned int nTxSize = ::GetSerializeSize(tx, SER_NETWORK, PROTOCOL_VERSION);
            if (nBlockSize + nTxSize >= nBlockMaxSize)
                continue;

            // Legacy limits on sigOps:
            unsigned int nTxSigOps = tx.GetLegacySigOpCount();
            if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS)
                continue;

            // Skip free transactions if we're past the minimum block size:
            if (fSortedByFee && (dFeePerKb < CTransaction::nMinTxFee) && (nBlockSize + nTxSize >= nBlockMinSize))
                continue;

            // Prioritize by fee once past the priority size or we run out of high-priority
            // transactions:
            if (!fSortedByFee &&
                ((nBlockSize + nTxSize >= nBlockPrioritySize) || (dPriority < COIN * 144 / 250)))
            {
                fSortedByFee = true;
                comparer = TxPriorityCompare(fSortedByFee);
                std::make_heap(vecPriority.begin(), vecPriority.end(), comparer);
            }

            if (!tx.HaveInputs(view))
                continue;

            int64 nTxFees = tx.GetValueIn(view)-tx.GetValueOut();

            nTxSigOps += tx.GetP2SHSigOpCount(view);
            if (nBlockSigOps + nTxSigOps >= MAX_BLOCK_SIGOPS)
                continue;

            CValidationState state;
            if (!tx.CheckInputs(state, view, true, SCRIPT_VERIFY_P2SH))
                continue;

            CTxUndo txundo;
            uint256 hash = tx.GetHash();
            tx.UpdateCoins(state, view, txundo, pindexPrev->nHeight+1, hash);

            // Added
            pblock->vtx.push_back(tx);
            pblocktemplate->vTxFees.push_back(nTxFees);
            pblocktemplate->vTxSigOps.push_back(nTxSigOps);
            nBlockSize += nTxSize;
            ++nBlockTx;
            nBlockSigOps += nTxSigOps;
            nFees += nTxFees;

            if (fPrintPriority)
            {
                printf("priority %.1f feeperkb %.1f txid %s\n",
                       dPriority, dFeePerKb, tx.GetHash().ToString().c_str());
            }

            // Add transactions that depend on this one to the priority queue
            if (mapDependers.count(hash))
            {
                BOOST_FOREACH(COrphan* porphan, mapDependers[hash])
                {
                    if (!porphan->setDependsOn.empty())
                    {
                        porphan->setDependsOn.erase(hash);
                        if (porphan->setDependsOn.empty())
                        {
                            vecPriority.push_back(TxPriority(porphan->dPriority, porphan->dFeePerKb, porphan->ptx));
                            std::push_heap(vecPriority.begin(), vecPriority.end(), comparer);
                        }
                    }
                }
            }
        }

        nLastBlockTx = nBlockTx;
        nLastBlockSize = nBlockSize;
        printf("CreateNewBlock(): total size %"PRI64u"\n", nBlockSize);

        pblock->nReward = GetCurrentBlockReward(pindexPrev);
        if (pblock->nReward + pindexPrev->getSupply() > nMaxSupply) {
            pblock->nReward = nMaxSupply - pindexPrev->getSupply();
            printf("Vote: Limiting current block reward to %hu\n", pblock->nReward);
        }
        pblock->vtx[0].vout[0].nValue = GetBlockValue(pblock->nReward,
                                                      pindexPrev->nHeight + 1, nFees);
        pblocktemplate->vTxFees[0] = -nFees;

        // Set next money supply
        pblock->setSupply(pindexPrev->getSupply() + pblock->nReward);

        // Fill in header
        pblock->hashPrevBlock  = pindexPrev->GetBlockHash();
        pblock->UpdateTime(pindexPrev);
        pblock->nBits          = GetNextWorkRequired(pindexPrev, pblock);
        pblock->nNonce         = 0;
        if (nBlockRewardVote > nBlockRewardVoteLimit)
            nBlockRewardVote = nBlockRewardVoteLimit;
        pblock->nVote          = nBlockRewardVote;
        pblock->vtx[0].vin[0].scriptSig = CScript() << OP_0 << OP_0;
        pblocktemplate->vTxSigOps[0] = pblock->vtx[0].GetLegacySigOpCount();

        CBlockIndex indexDummy(*pblock);
        indexDummy.pprev = pindexPrev;
        indexDummy.nHeight = pindexPrev->nHeight + 1;
        CCoinsViewCache viewNew(*pcoinsTip, true);
        CValidationState state;
        if (!pblock->ConnectBlock(state, &indexDummy, viewNew, true))
            throw std::runtime_error("CreateNewBlock() : ConnectBlock failed");
    }

    return pblocktemplate.release();
}


void IncrementExtraNonce(CBlock* pblock, CBlockIndex* pindexPrev, unsigned int& nExtraNonce)
{
    // Update nExtraNonce
    static uint256 hashPrevBlock;
    if (hashPrevBlock != pblock->hashPrevBlock)
    {
        nExtraNonce = 0;
        hashPrevBlock = pblock->hashPrevBlock;
    }
    ++nExtraNonce;
    unsigned int nHeight = pindexPrev->nHeight+1; // Height first in coinbase required for block.version=2
    pblock->vtx[0].vin[0].scriptSig = (CScript() << nHeight << CBigNum(nExtraNonce)) + COINBASE_FLAGS;
    assert(pblock->vtx[0].vin[0].scriptSig.size() <= 100);

    pblock->hashMerkleRoot = pblock->BuildMerkleTree();
}

// Time precludes scanhash implemention, so provide a simple
// implementation for RPC mining
void FormatHashBuffers(CBlock* pblock, char* pdata)
{
    //
    // Pre-build hash buffers
    //
    struct
    {
        struct unnamed2
        {
            int nVersion;
            uint256 hashPrevBlock;
            uint256 hashMerkleRoot;
            unsigned int nTime;
            unsigned int nBits;
            unsigned int nNonce;
            uint16_t nVote;
            uint16_t nReward;
        }
        block;
        unsigned char pchPadding0[64];
        uint256 hash1;
        unsigned char pchPadding1[64];
    }
    tmp;
    memset(&tmp, 0, sizeof(tmp));

    tmp.block.nVersion       = pblock->nVersion;
    tmp.block.hashPrevBlock  = pblock->hashPrevBlock;
    tmp.block.hashMerkleRoot = pblock->hashMerkleRoot;
    tmp.block.nTime          = pblock->nTime;
    tmp.block.nBits          = pblock->nBits;
    tmp.block.nNonce         = pblock->nNonce;
    tmp.block.nVote         = pblock->nVote;
    tmp.block.nReward       = pblock->nReward;

    FormatHashBlocks(&tmp.block, sizeof(tmp.block));
    FormatHashBlocks(&tmp.hash1, sizeof(tmp.hash1));

    memcpy(pdata, &tmp.block, 128);
}

bool CheckWork(CBlock* pblock, CWallet& wallet, CReserveKey& reservekey)
{
    uint256 hash = pblock->GetHash();
    uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();

    if (hash > hashTarget)
        return false;

    //// debug print
    printf("proof-of-work found: difficulty %g tx %s\n  hash: %s  \ntarget: %s\n",
           GetDifficulty(pindexBest),
           pblock->hashMerkleRoot.ToString().c_str(),
           hash.GetHex().c_str(), hashTarget.GetHex().c_str());
    pblock->print();
    printf("generated %s\n", FormatMoney(pblock->vtx[0].vout[0].nValue).c_str());

    // Found a solution
    {
        LOCK(cs_main);
        if (pblock->hashPrevBlock != hashBestChain)
            return error("generated block is stale");

        // Remove key from key pool
        reservekey.KeepKey();

        // Track how many getdata requests this block gets
        {
            LOCK(wallet.cs_wallet);
            wallet.mapRequestCount[pblock->GetHash()] = 0;
        }

        // Process this block the same as if we had received it from another node
        CValidationState state;
        if (!ProcessBlock(state, NULL, pblock))
            return error("ProcessBlock, block not accepted");

        LogBlock(*pblock);

        AdjustBlockRewardVoteLimit(pindexBest);

        // Calculate the average block time
        CBigNum bnUnused; float nUnused, nAvgTimespan;
        CalcWindowedAvgs(pindexBest, nDiffWindow, 0,
                         AbsTime((int64)pblock->nTime, pindexBest->GetBlockTime()),
                         bnUnused, nAvgTimespan, nUnused);

        pvoteMain->UpdateParams((unsigned int)pindexBest->nHeight, nAvgTimespan,
                                nBlockRewardVoteSpan, GetCurrentBlockReward(pindexBest),
                                GetNextBlockReward(pindexBest), nBlockRewardVoteLimit,
                                nPhase, pindexBest->getSupply(), nTarget, nMaxSupply);
    }

    return true;
}

void static HeavycoinMiner(CWallet *pwallet)
{
    printf("HeavycoinMiner started\n");
    SetThreadPriority(THREAD_PRIORITY_LOWEST);
    RenameThread("heavycoin-miner");

    // Each thread has its own key and counter
    CReserveKey reservekey(pwallet);
    unsigned int nExtraNonce = 0;

    try { loop {
        while (vNodes.empty())
            MilliSleep(1000);

        //
        // Create new block
        //
        unsigned int nTransactionsUpdatedLast = nTransactionsUpdated;
        CBlockIndex* pindexPrev = pindexBest;

        auto_ptr<CBlockTemplate> pblocktemplate(CreateNewBlock(reservekey));
        if (!pblocktemplate.get())
            return;
        CBlock *pblock = &pblocktemplate->block;
        IncrementExtraNonce(pblock, pindexPrev, nExtraNonce);

        printf("Running HeavycoinMiner with %"PRIszu" transactions in block (%u bytes)\n",
               pblock->vtx.size(),
               ::GetSerializeSize(*pblock, SER_NETWORK, PROTOCOL_VERSION));

        //
        // Search
        //
        int64 nStart = GetTime();
        uint256 hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();
        unsigned int nHashesDone = 0;
        loop
        {
            uint256 hash = pblock->GetHash();
            nHashesDone++;
            if (hash < hashTarget)
            {
                    // Found a solution
                    printf("Found block: %d %.8f %u %s %s\n",
                           pindexPrev->nHeight + 1,
                           (float)CalcDifficulty(pblock->nBits),
                           nHashesDone, pblock->hashMerkleRoot.ToString().c_str(),
                           pblock->GetHash().GetHex().c_str());

                    SetThreadPriority(THREAD_PRIORITY_NORMAL);
                    CheckWork(pblock, *pwalletMain, reservekey);
                    SetThreadPriority(THREAD_PRIORITY_LOWEST);

                    break;
            }
            pblock->nNonce++;

            // Meter hashes/sec
            static int64 nHashCounter;
            if (nHPSTimerStart == 0)
            {
                nHPSTimerStart = GetTimeMillis();
                nHashCounter = 0;
            }
            else
                nHashCounter++;
            if (GetTimeMillis() - nHPSTimerStart > 4000)
            {
                static CCriticalSection cs;
                {
                    LOCK(cs);
                    if (GetTimeMillis() - nHPSTimerStart > 4000)
                    {
                        dHashesPerSec = 1000.0 * nHashCounter / (GetTimeMillis() - nHPSTimerStart);
                        nHPSTimerStart = GetTimeMillis();
                        nHashCounter = 0;
                        static int64 nLogTime;
                        if (GetTime() - nLogTime > 10 * 60)
                        {
                            nLogTime = GetTime();
                            printf("Hashmeter: %6.0f khash/s\n", dHashesPerSec/1000.0);
                        }
                    }
                }
            }

            // Check for stop or if block needs to be rebuilt
            boost::this_thread::interruption_point();
            if (vNodes.empty())
                break;
            if (pblock->nNonce > 0xFFFFF)
                break;
            if (nTransactionsUpdated != nTransactionsUpdatedLast && GetTime() - nStart > 60)
                break;
            if (pindexPrev != pindexBest)
                break;
            if (pblock->nVote != nBlockRewardVote) {
                printf("Vote: Block reward vote changed (restart mining)\n");
                break;
            }

            // Update nTime every few seconds
            pblock->UpdateTime(pindexPrev);
            if (fTestNet)
            {
                // Changing pblock->nTime can change work required on testnet:
                hashTarget = CBigNum().SetCompact(pblock->nBits).getuint256();
            }
        }
    } }
    catch (boost::thread_interrupted)
    {
        printf("HeavycoinMiner terminated\n");
        throw;
    }
}

void SetGenerateThreads(int nThreads)
{
    nGenerateThreads = nThreads;
    if (nGenerateThreads < 0)
        nGenerateThreads = boost::thread::hardware_concurrency();

    std::ostringstream ss;
    ss << nGenerateThreads;
    mapArgs["-genproclimit"] = ss.str();
}

void GenerateBitcoins(bool fGenerate, CWallet* pwallet)
{
    static boost::thread_group* minerThreads = NULL;

    bGenerate = fGenerate;
    mapArgs["-gen"] = bGenerate ? "1" : "0";

    nGenerateThreads = GetArg("-genproclimit", -1);
    if (nGenerateThreads < 0)
        nGenerateThreads = boost::thread::hardware_concurrency();

    if (minerThreads != NULL)
    {
        minerThreads->interrupt_all();
        delete minerThreads;
        minerThreads = NULL;
    }

    if (nGenerateThreads == 0 || !fGenerate)
        return;

    minerThreads = new boost::thread_group();
    for (int i = 0; i < nGenerateThreads; i++)
        minerThreads->create_thread(boost::bind(&HeavycoinMiner, pwallet));
}

// Amount compression:
// * If the amount is 0, output 0
// * first, divide the amount (in base units) by the largest power of 10 possible; call the exponent e (e is max 9)
// * if e<9, the last digit of the resulting number cannot be 0; store it as d, and drop it (divide by 10)
//   * call the result n
//   * output 1 + 10*(9*n + d - 1) + e
// * if e==9, we only know the resulting number is not zero, so output 1 + 10*(n - 1) + 9
// (this is decodable, as d is in [1-9] and e is in [0-9])

uint64 CTxOutCompressor::CompressAmount(uint64 n)
{
    if (n == 0)
        return 0;
    int e = 0;
    while (((n % 10) == 0) && e < 9) {
        n /= 10;
        e++;
    }
    if (e < 9) {
        int d = (n % 10);
        assert(d >= 1 && d <= 9);
        n /= 10;
        return 1 + (n*9 + d - 1)*10 + e;
    } else {
        return 1 + (n - 1)*10 + 9;
    }
}

uint64 CTxOutCompressor::DecompressAmount(uint64 x)
{
    // x = 0  OR  x = 1+10*(9*n + d - 1) + e  OR  x = 1+10*(n - 1) + 9
    if (x == 0)
        return 0;
    x--;
    // x = 10*(9*n + d - 1) + e
    int e = x % 10;
    x /= 10;
    uint64 n = 0;
    if (e < 9) {
        // x = 9*n + d - 1
        int d = (x % 9) + 1;
        x /= 9;
        // x = n
        n = x*10 + d;
    } else {
        n = x+1;
    }
    while (e) {
        n *= 10;
        e--;
    }
    return n;
}


class CMainCleanup
{
public:
    CMainCleanup() {}
    ~CMainCleanup() {
        // block headers
        std::map<uint256, CBlockIndex*>::iterator it1 = mapBlockIndex.begin();
        for (; it1 != mapBlockIndex.end(); it1++)
            delete (*it1).second;
        mapBlockIndex.clear();

        // orphan blocks
        std::map<uint256, CBlock*>::iterator it2 = mapOrphanBlocks.begin();
        for (; it2 != mapOrphanBlocks.end(); it2++)
            delete (*it2).second;
        mapOrphanBlocks.clear();

        // orphan transactions
        std::map<uint256, CDataStream*>::iterator it3 = mapOrphanTransactions.begin();
        for (; it3 != mapOrphanTransactions.end(); it3++)
            delete (*it3).second;
        mapOrphanTransactions.clear();
    }
} instance_of_cmaincleanup;
