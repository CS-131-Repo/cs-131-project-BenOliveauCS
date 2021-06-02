#ifndef SHA
#define SHA
#include <iostream>
#include <iomanip>
#include <fstream>
#include <string.h>
//#include <stdlib.h>
#include <sstream>
using namespace std;

struct hashDigest
{
	unsigned long rawDigest[8];
};

hashDigest* SHA256(string input);
hashDigest* SHA256(unsigned long hashInput[], unsigned long long numBytes);
hashDigest* SHA256(hashDigest* prevDigest);
hashDigest* SHA256Demo(string input);
hashDigest* doubleHash(string input);
hashDigest* doubleHash(unsigned long input[], unsigned long long numBytes);
void printDigest(hashDigest digest);
#endif // !SHA
