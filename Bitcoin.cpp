#include "Bitcoin.h"

tx* pushTx(tx* node)
{
	txNode* pushNode = new txNode;
	pushNode->data = node;
	if (txQueueIsEmpty())
		unblockedHead = pushNode;
	else
		unblockedTail->next = pushNode;
	unblockedTail = pushNode;
	return pushNode->data;
}

txNode* popTx()
{
	if (txQueueIsEmpty())
		return nullptr;
	txNode* node = unblockedHead;
	unblockedHead = unblockedHead->next;
	return node;
}

bool txQueueIsEmpty()
{
	return unblockedHead == nullptr;
}

unsigned long long generateSignature(unsigned long long sk, hashDigest* message)
{
	system_clock::time_point time = system_clock::now();
	unsigned long long k = duration_cast<seconds>(time.time_since_epoch()).count();
	unsigned long r = (unsigned long)((G * k) % n);
	unsigned long long z = (((unsigned long long)message->rawDigest[0] << 32) + message->rawDigest[1])
						 ^ (((unsigned long long)message->rawDigest[2] << 32) + message->rawDigest[3])
						 ^ (((unsigned long long)message->rawDigest[4] << 32) + message->rawDigest[5])
						 ^ (((unsigned long long)message->rawDigest[6] << 32) + message->rawDigest[7]);
	unsigned long s = (unsigned long)((z + r * sk) / k) % n;
	unsigned long long signature = ((unsigned long long)r << 32) + s;
	return signature;
}

tx* tradeCoin(tx* input, unsigned long numInputs, unsigned long long amount, unsigned long pk, unsigned long long sk, string message)
{
	if (input->transactionValue < amount)
		return nullptr;
	tx* newTx = new tx;
	newTx->signature = generateSignature(sk, SHA256(message));
	newTx->transactionValue = input->transactionValue;
	newTx->input = input;
	newTx->publicKey = pk;
	input->spent = true;
	return pushTx(newTx);
}

hashDigest* getTxDigest(tx* t)
{
	unsigned long hashInput[9];
	hashInput[0] = (t->version << 16) + t->signatureLength;
	hashInput[1] = (unsigned long long)t->signature >> 32;
	hashInput[2] = (unsigned long)t->signature;
	hashInput[3] = (unsigned long long)t->transactionValue >> 32;
	hashInput[4] = (unsigned long)t->transactionValue;
	hashInput[5] = (unsigned long long)t->input >> 32;
	hashInput[6] = (unsigned long)t->input;
	hashInput[7] = t->pkLength;
	hashInput[8] = t->publicKey;

	return doubleHash(hashInput, 36);
}

block* createBlock(block* prevBlock, unsigned long difficulty, unsigned long minerPk)
{
	system_clock::time_point tp = system_clock::now();
	block* newBlock = new block;
	newBlock->prevHash = getBlockDigest(prevBlock);
	txNode* curNode = new txNode;

	tx* coinbaseTx = new tx;
	coinbaseTx->signature = 0;
	coinbaseTx->transactionValue = blockReward;
	coinbaseTx->input = nullptr;
	coinbaseTx->publicKey = minerPk;

	curNode->data = coinbaseTx;
	newBlock->transactionListHead = curNode;
	newBlock->numTxs = 1;

	while (!txQueueIsEmpty())
	{
		curNode->next = popTx();
		curNode = curNode->next;
		newBlock->numTxs++;
	}
	newBlock->timeStamp = (unsigned long)duration_cast<seconds>(tp.time_since_epoch()).count();
	newBlock->difficultyBits = difficulty;
	newBlock->merkleRoot = generateMerkleTree(newBlock);
	return newBlock;
}

treeNode* generateMerkleTree(block* b)
{
	unsigned long Pow = 1;
	while (Pow < b->numTxs)
		Pow = Pow << 1;
	hashDigest** txDigests = new hashDigest * [b->numTxs];
	txNode* curNode = b->transactionListHead;
	unsigned long i = 0;
	for (; i < b->numTxs; i++)
		txDigests[i] = getTxDigest(curNode->data);
	return populateTree(b->merkleRoot, Pow >> 1, 0, txDigests, b->numTxs);
}

treeNode* populateTree(treeNode* curRoot, unsigned long Pow, unsigned long index, hashDigest** txDigests, unsigned long numTxns)
{
	switch (Pow)
	{
	case 0: curRoot->data = (index < numTxns) ? txDigests[index] : nullptr; break;
	default:
	{	curRoot->lChild = populateTree(new treeNode, Pow >> 1, index, txDigests, numTxns);
	curRoot->rChild = populateTree(new treeNode, Pow >> 1, index + Pow, txDigests, numTxns);
	if (curRoot->lChild->data == nullptr)
		curRoot->data = nullptr;
	else
	{
		unsigned long* hashInput = new unsigned long[16];
		int i = 0;
		for (; i < 8; i++)
			hashInput[i] = curRoot->lChild->data->rawDigest[i];
		for (; i < 16; i++)
			hashInput[i] = (curRoot->rChild->data == nullptr) ? hashInput[i - 8] : curRoot->rChild->data->rawDigest[i - 8];
		curRoot->data = doubleHash(hashInput, 64);
		delete[] hashInput;
	}
	}
	}
	return curRoot;
}

hashDigest* getBlockDigest(block* b)
{
	return SHA256(b->header.rawHeader, 32);
}

block* mineBlock(block* b)
{
	hashDigest* digest = getBlockDigest(b);
	while (digest->rawDigest[0] > b->difficultyBits)
	{
		b->nonce++;
		b->header.rawHeader[7]++;
		digest = getBlockDigest(b);
	}
	return addBlockToChain(b)->data;
}

blockNode* addBlockToChain(block* b)
{
	blockNode* newNode = new blockNode;
	newNode->data = b;
	if (blockchain == nullptr)
		blockchain = newNode;
	else
	{
		blockNode* tempNode = blockchain;
		blockchain = newNode;
		blockchain->prevBlock = tempNode;
	}
	numBlocks++;
	switch (numBlocks % 210000)
	{
	case 0: blockReward /= 2;
	}
	return newNode;
}
