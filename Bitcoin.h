#ifndef Bitcoin
#define Bitcoin
#include "SHA.h";
#include <chrono>
using namespace std::chrono;

//Original protocol operates with little-endian values, this partial implementation uses big-endian values.

const unsigned long long G = 0x79BE667EF9DCBBAC;
const unsigned long long n = 0xBFD25E8CD0364141;

struct wallet
{
	unsigned long long secretKey;
	unsigned long* publicKeys;
};

struct tx
{
	unsigned short version = 0x31;				//Version '1'
	unsigned short signatureLength = 0x40;		//long long data type is 64 bits
	unsigned long long signature = 0;			//Public buffer to protect secret key. Real signatures created using elliptical curve
	unsigned long long transactionValue = 0;	//Binary representation of first 8 chars of word from "Computing Machinery and Intelligence" (Transactions.txt)
	tx* input = nullptr;						/*Array of pointers to previous transactions where buyer was the recipient.
												  Wallets don't have balance pools, but have pointers to previous transactions 
												  where wallet holder received bitcoin. All inputs can be verified by tracing their transaction history
												  back to a coinbase transaction.
												  All unspent transactions exist inside of a database that is part of the public ledger to save time.
												  All inputs must be spent completely. The remaining balance may be sent back to the sender 
												  (typically under a different pk address) or optionally used to tip a miner.
												  This demo only supports a single input and a single recipient.*/ 
	unsigned long pkLength = 0x20; 
	unsigned long publicKey = 0;				//Ordered pair generated using elliptical curve and sk 
	bool spent = false;
};

struct txNode
{
	tx* data = nullptr;
	txNode* next = nullptr;
};

struct treeNode
{
	hashDigest* data = nullptr;
	treeNode* lChild = nullptr;
	treeNode* rChild = nullptr;
};

struct blockHeader
{
	unsigned long rawHeader[8]{ '1', 0, 0, 0, 0, 0, 0, 0 };
};

struct block
{
	unsigned short version = 0x31;
	unsigned short numTxs = 0;
	hashDigest* prevHash = nullptr;
	treeNode* merkleRoot = nullptr;
	txNode* transactionListHead = nullptr;
	unsigned long timeStamp = 0;
	unsigned long difficultyBits = 0;
	unsigned long nonce = 0;
	blockHeader header;
};

struct blockNode
{
	block* data = nullptr;
	blockNode* prevBlock = nullptr;
};

static blockNode* blockchain = nullptr;
static unsigned char blockReward = 50;
static unsigned long long numBlocks = 0;

static txNode* unblockedHead = nullptr;
static txNode* unblockedTail = nullptr;

tx* pushTx(tx* node);
txNode* popTx();
bool txQueueIsEmpty();
txNode* listenForTransactions();
hashDigest* getTxDigest(tx* t);
unsigned long long generateSignature(unsigned long long sk, hashDigest* message);
tx* tradeCoin(tx* input, unsigned long numInputs, unsigned long long amount, unsigned long pk, unsigned long long sk, string message);

block* createBlock(block* prevBlock, unsigned long difficulty, unsigned long minerPk);
treeNode* generateMerkleTree(block* b);
treeNode* populateTree(treeNode* curRoot, unsigned long Pow, unsigned long index, hashDigest** txDigests, unsigned long numTxns);
unsigned long* getBlockHeader(block* b);
hashDigest* getBlockDigest(block* b);
block* mineBlock(block* b);
blockNode* addBlockToChain(block* b);
#endif // !Bitcoin.h
