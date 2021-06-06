#include "SHA.h"

#define S(x, n) ((x >> n) | (x << (32 - n)))
#define Ch(x, y, z) ((x & y) ^ ((~x) & z))
#define Ma(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define S0(x) (S(x, 2) ^ S(x, 13) ^ S(x, 22))
#define S1(x) (S(x, 6) ^ S(x, 11) ^ S(x, 25))
#define s0(x) (S(x, 7) ^ S(x, 18) ^ (x >> 3))
#define s1(x) (S(x, 17) ^ S(x, 19) ^ (x >> 10))

hashDigest* SHA256(string input)
{
	const unsigned long long inputLength = input.length();
	const unsigned long long numBlocks = (((inputLength * 8) + 65) / 512) + 1;
	auto hashBlocks = new unsigned long[numBlocks][16]{ 0 };
	fstream constants;
	constants.open("CBRTs.txt", ios::in);
	unsigned long* messageSchedule = new unsigned long[64];
	unsigned long* wordRegisters = new unsigned long[8]{ 1779033703, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635, 1541459225 };
	unsigned long* prevHashValues = new unsigned long[8];
	unsigned long curPrime, T0, T1 = 0;
	unsigned long long i, j, k;

	//Message
	for (i = 0; i < inputLength - inputLength % 4; i += 4)
		hashBlocks[i / 64][(i % 64) / 4] = ((long)input[i] << 24) + ((long)input[i + 1] << 16) + ((long)input[i + 2] << 8) + input[i + 3];
	//Transition Word
	hashBlocks[inputLength / 64][(inputLength % 64) / 4] = (1 << (31 - (8 * (inputLength % 4))));
	for (i = inputLength % 4; i > 0; i--)
		hashBlocks[inputLength / 64][(inputLength % 64) / 4] += ((long)input[inputLength - i] << (8 * (3 - (inputLength % 4 - i))));
	//Padding (done via initialization) + input length
	hashBlocks[numBlocks - 1][14] = ((inputLength << 3) >> 32) << 32;
	hashBlocks[numBlocks - 1][15] = ((inputLength << 3) << 32) >> 32;

	for (i = 0; i < numBlocks; i++)
	{
		constants.seekg(0);
		for (j = 0; j < 8; j++)
			prevHashValues[j] = wordRegisters[j];
		for (j = 0; j < 16; j++)
			messageSchedule[j] = hashBlocks[i][j];
		for (; j < 64; j++)
		{
			messageSchedule[j] = s1(messageSchedule[j - 2]) + messageSchedule[j - 7] + s0(messageSchedule[j - 15]) + messageSchedule[j - 16];
		}
		for (j = 0; j < 64; j++)
		{
			constants >> curPrime;
			T0 = S1(wordRegisters[4]) + Ch(wordRegisters[4], wordRegisters[5], wordRegisters[6]) + wordRegisters[7] + curPrime + messageSchedule[j];
			T1 = S0(wordRegisters[0]) + Ma(wordRegisters[0], wordRegisters[1], wordRegisters[2]);

			for (k = 7; k > 0; k--)
				wordRegisters[k] = wordRegisters[k - 1];
			wordRegisters[0] = T0 + T1;
			wordRegisters[4] += T0;
		}
		for (j = 0; j < 8; j++)
			wordRegisters[j] += prevHashValues[j];
	}
	hashDigest* digest = new hashDigest;
	for (i = 0; i < 8; i++)
		digest->rawDigest[i] = wordRegisters[i];

	delete[] hashBlocks;
	delete[] messageSchedule;
	delete[] wordRegisters;
	delete[] prevHashValues;
	constants.close();

	return digest;
}

//Does not function correctly iff input is non-integer # of bytes
hashDigest* SHA256(unsigned long hashInput[], unsigned long long numBytes)
{
	unsigned long long numBlocks = (((numBytes * 8) + 65) / 512) + 1;
	auto hashBlocks = new unsigned long[numBlocks][16]{ 0 };
	fstream constants;
	constants.open("CBRTs.txt", ios::in);
	unsigned long* messageSchedule = new unsigned long[64];
	unsigned long* wordRegisters = new unsigned long[8]{ 1779033703, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635, 1541459225 };
	unsigned long* prevHashValues = new unsigned long[8];
	unsigned long curPrime, T0, T1 = 0;
	unsigned long long i, j, k;
	//Message
	for (i = 0; i < numBytes / 4; i++)
		hashBlocks[i / 16][i % 16] = hashInput[i];
	//Transition Word
	hashBlocks[i / 16][i % 16] = hashInput[i] << (8 * ((4 - (numBytes % 4)) % 4));
	switch (numBytes % 4)
	{
	case 0: i++;
	}
	hashBlocks[numBytes / 64][(numBytes % 64) / 4] += (1 << (31 - (8 * (numBytes % 4))));
	//Padding (done via initialization) + input length
	hashBlocks[numBlocks - 1][14] = ((numBytes << 3) >> 32) << 32;
	hashBlocks[numBlocks - 1][15] = ((numBytes << 3) << 32) >> 32;

	for (i = 0; i < numBlocks; i++)
	{
		constants.seekg(0);
		for (j = 0; j < 8; j++)
			prevHashValues[j] = wordRegisters[j];
		for (j = 0; j < 16; j++)
			messageSchedule[j] = hashBlocks[i][j];
		for (; j < 64; j++)
			messageSchedule[j] = s1(messageSchedule[j - 2]) + messageSchedule[j - 7] + s0(messageSchedule[j - 15]) + messageSchedule[j - 16];
		for (j = 0; j < 64; j++)
		{
			constants >> curPrime;
			T0 = S1(wordRegisters[4]) + Ch(wordRegisters[4], wordRegisters[5], wordRegisters[6]) + wordRegisters[7] + curPrime + messageSchedule[j];
			T1 = S0(wordRegisters[0]) + Ma(wordRegisters[0], wordRegisters[1], wordRegisters[2]);

			for (k = 7; k > 0; k--)
				wordRegisters[k] = wordRegisters[k - 1];
			wordRegisters[0] = T0 + T1;
			wordRegisters[4] += T0;
		}
		for (j = 0; j < 8; j++)
			wordRegisters[j] += prevHashValues[j];
	}
	hashDigest* digest = new hashDigest;
	for (i = 0; i < 8; i++)
		digest->rawDigest[i] = wordRegisters[i];

	delete[] hashBlocks;
	delete[] messageSchedule;
	delete[] wordRegisters;
	delete[] prevHashValues;
	constants.close();

	return digest;
}

hashDigest* SHA256(hashDigest* prevDigest)
{
	auto hashBlocks = new unsigned long[16]{prevDigest->rawDigest[0], prevDigest->rawDigest[1], prevDigest->rawDigest[2], prevDigest->rawDigest[3], prevDigest->rawDigest[4], prevDigest->rawDigest[5], prevDigest->rawDigest[6], prevDigest->rawDigest[7], ((unsigned long)1 << 31), 0, 0, 0, 0, 0, 0, 256 };
	fstream constants;
	constants.open("CBRTs.txt", ios::in);
	unsigned long* messageSchedule = new unsigned long[64];
	unsigned long* wordRegisters = new unsigned long[8]{ 1779033703, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635, 1541459225 };
	unsigned long* prevHashValues = new unsigned long[8];
	unsigned long curPrime, T0, T1 = 0;
	unsigned long long i, j, k;

	constants.seekg(0);
	for (j = 0; j < 8; j++)
		prevHashValues[j] = wordRegisters[j];
	for (j = 0; j < 16; j++)
		messageSchedule[j] = hashBlocks[j];
	for (; j < 64; j++)
		messageSchedule[j] = s1(messageSchedule[j - 2]) + messageSchedule[j - 7] + s0(messageSchedule[j - 15]) + messageSchedule[j - 16];
	for (j = 0; j < 64; j++)
	{
		constants >> curPrime;
		T0 = S1(wordRegisters[4]) + Ch(wordRegisters[4], wordRegisters[5], wordRegisters[6]) + wordRegisters[7] + curPrime + messageSchedule[j];
		T1 = S0(wordRegisters[0]) + Ma(wordRegisters[0], wordRegisters[1], wordRegisters[2]);

		for (k = 7; k > 0; k--)
			wordRegisters[k] = wordRegisters[k - 1];
		wordRegisters[0] = T0 + T1;
		wordRegisters[4] += T0;
	}
	for (j = 0; j < 8; j++)
		wordRegisters[j] += prevHashValues[j];
	hashDigest* digest = new hashDigest;
	for (i = 0; i < 8; i++)
		digest->rawDigest[i] = wordRegisters[i];

	delete[] hashBlocks;
	delete[] messageSchedule;
	delete[] wordRegisters;
	delete[] prevHashValues;
	constants.close();

	return digest;
}
hashDigest* doubleHash(string input)
{
	return SHA256(SHA256(input));
}

hashDigest* doubleHash(unsigned long input[], unsigned long long numBytes)
{
	return SHA256(SHA256(input, numBytes));
}

void printDigest(hashDigest digest)
{
	cout << hex << setw(8) << setfill('0') << digest.rawDigest[0] << setw(8) << digest.rawDigest[1] << setw(8) << digest.rawDigest[2] << setw(8) << digest.rawDigest[3] << setw(8) << digest.rawDigest[4] << setw(8) << digest.rawDigest[5] << setw(8) << digest.rawDigest[6] << setw(8) << digest.rawDigest[7] << '\n';
}

/*Code used to animate the demonstration.*/
hashDigest* SHA256Demo(string input)
{
	char c;
	cout << "Initial message: " << input << '\n';
	c = getchar();
	const unsigned long long inputLength = input.length();
	const unsigned long long numBlocks = (((inputLength * 8) + 65) / 512) + 1;
	auto hashBlocks = new unsigned long[numBlocks][16]{ 0 };
	fstream constants;
	constants.open("CBRTs.txt", ios::in);
	unsigned long* messageSchedule = new unsigned long[64];
	unsigned long* wordRegisters = new unsigned long[8]{ 1779033703, 3144134277, 1013904242, 2773480762, 1359893119, 2600822924, 528734635, 1541459225 };
	unsigned long* prevHashValues = new unsigned long[8];
	unsigned long curPrime, T0, T1 = 0;
	unsigned long long i, j, k, l, m;

	cout << "Convert the message into a bit string:\n";
	for (i = 0; i < inputLength/8 + 1; i++)
	{
		for (j = 0; j < 8 && 8 * i + j < inputLength; j++)
		{
			for (k = 8; k > 0; k--)
				cout << (input[8 * i + j] >> (k - 1)) % 2;
			cout << ' ';
		}
		for (k = j; k < 8; k++)
			cout << "         ";
		cout << '\t';
		for (k = 0; k < j; k++)
		{
			cout << hex << (unsigned long)input[8 * i + k] << ' ';
		}
		cout << '\n';
	}
	c = getchar();

	system("CLS");
	cout << "Initial message: " << input << "\n\n";
	cout << "Add a 1 to the end as a delimiter:\n";
	for (i = 0; i < inputLength / 8 + 1; i++)
	{
		for (j = 0; j < 8 && 8 * i + j < inputLength; j++)
		{
			for (k = 8; k > 0; k--)
				cout << (input[8 * i + j] >> (k - 1)) % 2;
			cout << ' ';
		}
		if (i != inputLength / 8)
		{
			cout << '\t';
			for (k = 0; k < j; k++)
				cout << hex << (unsigned long)input[8 * i + k] << ' ';
		}
		else
		{
			if (j != 0)
			{
				cout << "1(000)   ";
				for (k = j + 1; k < 8; k++)
					cout << "         ";
				cout << '\t';
				for (k = 0; k < j; k++)
					cout << hex << (unsigned long)input[8 * i + k] << ' ';
				cout << '8';
			}
			else
			{
				for (k = 0; k < j; k++)
					cout << hex << (unsigned long)input[8 * i + k] << ' ';
				cout << "1(000)\t\t\t\t\t\t\t\t\t\t8";
			}
		}
		cout << '\n';
	}
	c = getchar();

	system("CLS");
	cout << "Initial message: " << input << "\n\n";
	cout << "Pad the message with 0s until the total length is congruant to 448 (mod 512):\n";
	for (i = 0; i < inputLength / 8 + 1; i++)
	{
		for (j = 0; j < 8 && 8 * i + j < inputLength; j++)
		{
			for (k = 8; k > 0; k--)
				cout << (input[8 * i + j] >> (k - 1)) % 2;
			cout << ' ';
		}
		if (i != inputLength / 8)
		{
			cout << '\t';
			for (k = 0; k < j; k++)
				cout << hex << (unsigned long)input[8 * i + k] << ' ';
		}
		else
		{
			if (j != 0)
			{
				cout << "10000000 ";
				for (k = j + 1; k < 8; k++)
					cout << "00000000 ";
				cout << '\t';
				for (k = 0; k < j; k++)
					cout << hex << (unsigned long)input[8 * i + k] << ' ';
				cout << "80 ";
				for (k = j + 1; k < 8; k++)
					cout << "00 ";
			}
			else
			{
				for (k = 0; k < j; k++)
					cout << hex << (unsigned long)input[8 * i + k] << ' ';
				cout << "10000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 \t80 00 00 00 00 00 00 00";
			}
		}
		cout << '\n';
	}
	for(; i % 8 != 7; i++)
		cout << "00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 \t00 00 00 00 00 00 00 00\n";
	c = getchar();

	system("CLS");
	cout << "Initial message: " << input << "\n\n";
	cout << "Add on the bit length of the original message as a 64 bit word:\n";
	for (i = 0; i < inputLength / 8 + 1; i++)
	{
		for (j = 0; j < 8 && 8 * i + j < inputLength; j++)
		{
			for (k = 8; k > 0; k--)
				cout << (input[8 * i + j] >> (k - 1)) % 2;
			cout << ' ';
		}
		if (i != inputLength / 8)
		{
			cout << '\t';
			for (k = 0; k < j; k++)
				cout << hex << (unsigned long)input[8 * i + k] << ' ';
		}
		else
		{
			if (j != 0)
			{
				cout << "10000000 ";
				for (k = j + 1; k < 8; k++)
					cout << "00000000 ";
				cout << '\t';
				for (k = 0; k < j; k++)
					cout << hex << (unsigned long)input[8 * i + k] << ' ';
				cout << "80 ";
				for (k = j + 1; k < 8; k++)
					cout << "00 ";
			}
			else
			{
				for (k = 0; k < j; k++)
					cout << hex << (unsigned long)input[8 * i + k] << ' ';
				cout << "10000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 \t80 00 00 00 00 00 00 00";
			}
		}
		cout << '\n';
	}
	for (; i % 8 != 7; i++)
		cout << "00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 \t00 00 00 00 00 00 00 00\n";
	for (i = 0; i < 8; i++)
	{
		int mod = ((inputLength * 8) >> (56 - 8 * i)) % 0x100;
		for (j = 8; j > 0; j--)
			cout << (mod >> (j - 1)) % 2;
		cout << ' ';
	}
	cout << '\t';
	for (i = 0; i < 8; i++)
	{
		int mod = ((inputLength * 8) >> (56 - 8 * i)) % 0x100;
		cout << hex << setw(2) << setfill('0') << mod << ' ';
	}
	cout << '\n';
	c = getchar();

	//Message
	for (i = 0; i < inputLength - inputLength % 4; i += 4)
		hashBlocks[i / 64][(i % 64) / 4] = ((long)input[i] << 24) + ((long)input[i + 1] << 16) + ((long)input[i + 2] << 8) + input[i + 3];
	//Transition Word
	hashBlocks[inputLength / 64][(inputLength % 64) / 4] = (1 << (31 - (8 * (inputLength % 4))));
	for (i = inputLength % 4; i > 0; i--)
		hashBlocks[inputLength / 64][(inputLength % 64) / 4] += ((long)input[inputLength - i] << (8 * (3 - (inputLength % 4 - i))));
	//Padding (done via initialization) + input length
	hashBlocks[numBlocks - 1][14] = ((inputLength << 3) >> 32) << 32;
	hashBlocks[numBlocks - 1][15] = ((inputLength << 3) << 32) >> 32;

	system("CLS");
	cout << "Initial message: " << input << "\n\n";
	cout << "Split the padded message into blocks of 512 bits:\n";
	for (i = 0; i < numBlocks; i++)
	{
		cout << "Block " << i << ":\n";
		for (j = 0; j < 16; j++)
		{
			for (k = 32; k > 0; k--)
			{
				cout << (hashBlocks[i][j] >> (k - 1)) % 2 << ((k % 8 == 1) ? " " : "");
			}
			switch (j % 2)
			{
			case 1: cout << '\t';
					for (k = 0; k < 8; k++)
						cout << hex << setw(2) << setfill('0') << (hashBlocks[i][j - (1 - k / 4)] >> (24 - 8 * (k % 4))) % 0x100 << ' ';
					cout << '\n';
					break;
			}
		}
	}
	c = getchar();

	cout << "For each block do the following:\n-Create the message schedule\n-Initialize the 8 word registers\n-Compress the message schedule into the word registers\n-Add the final values of the word registers to the initial values\n";
	c = getchar();

	stringstream str;
	string header = "Initial message: ";
	header += input;
	header += "\n\nSplit the padded message into blocks of 512 bits:\n";
	for (k = 0; k < numBlocks; k++)
	{
		header += "Block ";
		header += to_string(k);
		header += ":\n";
		for (l = 0; l < 16; l++)
		{
			for (m = 32; m > 0; m--)
			{
				header += to_string((hashBlocks[k][l] >> (m - 1)) % 2);
				header += (m % 8 == 1) ? " " : "";
			}
			switch (l % 2)
			{
			case 1: header += '\t';
				for (m = 0; m < 8; m++)
				{
					str.str(string());
					str << hex << setw(2) << setfill('0') << (hashBlocks[k][l - (1 - m / 4)] >> (24 - 8 * (m % 4))) % 0x100 << ' ';
					header += str.str();
				}
				header += '\n';
				break;
			}
		}
	}
	header += "\nFor each block do the following:\n-Create the message schedule\n-Initialize the 8 word registers\n-Compress the message schedule into the word registers\n-Add the final values of the word registers to the initial values\n\n";

	for (i = 0; i < numBlocks; i++)
	{
		system("CLS");
		cout << header;
		cout << "Now hashing block " << i << ": " << '\n';
		c = getchar();
		cout << "Form the message schedule:";
		c = getchar();

		system("CLS");
		cout << header;
		cout << "Now hashing block " << i << ": " << "\n\n";
		cout << "Form the message schedule: 00 -> 0f - Block Data ";
		c = getchar();

		constants.seekg(0);
		for (j = 0; j < 16; j++)
		{
			cout << '\n';
			messageSchedule[j] = hashBlocks[i][j];
			cout << hex << 'w' << setw(2) << setfill('0') << j << ": ";
			for (k = 32; k > 0; k--)
				cout << (messageSchedule[j] >> (k - 1)) % 2 << (((k - 1) % 8 == 0) ? " " : "");
			cout << "\t";
			for (k = 0; k < 4; k++)
				cout << setw(2) << setfill('0') << (messageSchedule[j] >> (24 - 8 * k)) % 256 << ' ';
		}
		c = getchar();

		system("CLS");
		cout << header;
		cout << "Now hashing block " << i << ": " << "\n\n";
		cout << "Form the message schedule: 10 -> ef -  w[x] = s1(w[x-2]) + w[x-7] + s0(w[x-15]) + w[x-16]\n";
		for (j = 0; j < 16; j++)
		{
			cout << '\n';
			messageSchedule[j] = hashBlocks[i][j];
			cout << hex << 'w' << setw(2) << setfill('0') << j << ": ";
			for (k = 32; k > 0; k--)
				cout << (messageSchedule[j] >> (k - 1)) % 2 << (((k - 1) % 8 == 0) ? " " : "");
			cout << "\t";
			for (k = 0; k < 4; k++)
				cout << setw(2) << setfill('0') << (messageSchedule[j] >> (24 - 8 * k)) % 256 << ' ';
		}
		c = getchar();
		for (; j < 64; j++)
		{
			messageSchedule[j] = s1(messageSchedule[j - 2]) + messageSchedule[j - 7] + s0(messageSchedule[j - 15]) + messageSchedule[j - 16];
			cout << hex << 'w' << j << ": ";
			for (k = 32; k > 0; k--)
				cout << (messageSchedule[j] >> (k - 1)) % 2 << (((k - 1) % 8 == 0) ? " " : "");
			cout << "\t";
			for (k = 0; k < 4; k++)
				cout << setw(2) << setfill('0') << (messageSchedule[j] >> (24 - 8 * k)) % 256 << ' ';
			cout << "\tw" << j << " = s1(w" << setw(2) << setfill('0') << j - 2 << ") + w" << setw(2) << j - 7 << " + s0(w" << setw(2) << j - 15 << ") + w" << setw(2) << j - 16 << "\n";
		}
		c = getchar();

		system("CLS");
		cout << header;
		cout << "Now hashing block " << i << ": " << "\n\n";

		cout << "Initialize the 8 word registers:";
		c = getchar();

		cout << hex << setfill('0') << "a: " << setw(8) << "0" << "\n" 
									<< "b: " << setw(8) << "0" << "\n"
									<< "c: " << setw(8) << "0" << "\n"
									<< "d: " << setw(8) << "0" << "\n"
									<< "e: " << setw(8) << "0" << "\n"
									<< "f: " << setw(8) << "0" << "\n"
									<< "g: " << setw(8) << "0" << "\n"
									<< "h: " << setw(8) << "0" << "\n";
		c = getchar();

		system("CLS");
		cout << header;
		cout << "Now hashing block " << i << ": " << "\n\n";
		cout << "Initialize the 8 word registers:\n";

		cout << hex << setfill('0') << "a: " << setw(8) << '0' << " + H0\n"
									<< "b: " << setw(8) << '0' << " + H1\n"
									<< "c: " << setw(8) << '0' << " + H2\n"
									<< "d: " << setw(8) << '0' << " + H3\n"
									<< "e: " << setw(8) << '0' << " + H4\n"
									<< "f: " << setw(8) << '0' << " + H5\n"
									<< "g: " << setw(8) << '0' << " + H6\n"
									<< "h: " << setw(8) << '0' << " + H7\n";
		c = getchar();

		system("CLS");
		cout << header;
		cout << "Now hashing block " << i << ": " << "\n\n";
		cout << "Initialize the 8 word registers:\n";

		for(j = 0; j < 8; j++)
		{
			cout << (char)(97 + j) << ": ";
			for (k = 32; k > 0; k--)
				cout << (wordRegisters[j] >> (k - 1)) % 2 << ((k % 8 == 1) ? " " : "");
			cout << hex << "\t\t" << setfill('0') << setw(8) << wordRegisters[j] << '\n';
		}

		c = getchar();

		for (j = 0; j < 8; j++)
			prevHashValues[j] = wordRegisters[j];

		constants >> curPrime;
		system("CLS");
		cout << header;
		cout << "Now hashing block " << i << ": " << "\n\n";
		cout << "Compress the message schedule into the word registers\n";
		for (j = 0; j < 8; j++)
		{
			cout << (char)(97 + j) << ": ";
			for (k = 32; k > 0; k--)
				cout << (wordRegisters[j] >> (k - 1)) % 2 << ((k % 8 == 1) ? " " : "");
			cout << hex << "\t\t" << setfill('0') << setw(8) << wordRegisters[j] << '\n';
		}
		c = getchar();
		j = 0;
		cout << hex << "Next Message w" << setw(2) << j <<  ": " << setw(8) << messageSchedule[j] << "\nNext Prime # k" << setw(2) << j << ": " << setw(8) << curPrime;
		c = getchar();
		cout << "T0:\nT1:";
		c = getchar();

		T0 = S1(wordRegisters[4]) + Ch(wordRegisters[4], wordRegisters[5], wordRegisters[6]) + wordRegisters[7] + curPrime + messageSchedule[j];
		T1 = S0(wordRegisters[0]) + Ma(wordRegisters[0], wordRegisters[1], wordRegisters[2]);

		system("CLS");
		cout << header;
		cout << "Now hashing block " << i << ": " << "\n\n";
		cout << "Compress the message schedule into the word registers\n";
		for (j = 0; j < 8; j++)
		{
			cout << (char)(97 + j) << ": ";
			for (k = 32; k > 0; k--)
				cout << (wordRegisters[j] >> (k - 1)) % 2 << ((k % 8 == 1) ? " " : "");
			cout << hex << "\t\t" << setfill('0') << setw(8) << wordRegisters[j] << '\n';
		}
		j = 0;
		cout << hex << "Next Message w" << setw(2) << j << ": " << setw(8) << messageSchedule[j] << "\nNext Prime # k" << setw(2) << j << ": " << setw(8) << curPrime << '\n';
		cout << "T0 = S1(e) + Ch(e + f + g) + h + w[x] + k[x]\nT1 = S0(a) + Ma(a + b + c)";
		c = getchar();

		system("CLS");
		cout << header;
		cout << "Now hashing block " << i << ": " << "\n\n";
		cout << "Compress the message schedule into the word registers\n";
		for (j = 0; j < 8; j++)
		{
			cout << (char)(97 + j) << ": ";
			for (k = 32; k > 0; k--)
				cout << (wordRegisters[j] >> (k - 1)) % 2 << ((k % 8 == 1) ? " " : "");
			cout << hex << "\t\t" << setfill('0') << setw(8) << wordRegisters[j] << '\n';
		}
		j = 0;
		cout << hex << "Next Message w" << setw(2) << j << ": " << setw(8) << messageSchedule[j] << "\nNext Prime # k" << setw(2) << j << ": " << setw(8) << curPrime << '\n';
		cout << setfill('0') << "T0: " << setw(8) << T0 << "\nT1: " << setw(8) << T1;
		c = getchar();

		for (k = 7; k > 0; k--)
		{
			wordRegisters[k] = wordRegisters[k - 1];
			system("CLS");
			cout << header;
			cout << "Now hashing block " << i << ": " << "\n\n";
			cout << "Compress the message schedule into the word registers\n";
			for (l = 0; l < 8; l++)
			{
				cout << (char)(97 + l) << ": ";
				switch (l - (k - 1))
				{
				case 0: cout << '\n'; break;
				default: for (m = 32; m > 0; m--)
							cout << (wordRegisters[l] >> (m - 1)) % 2 << ((m % 8 == 1) ? " " : "");
						 cout << hex << "\t\t" << setfill('0') << setw(8) << wordRegisters[l] << ((l == k) ? " vv" : "") << '\n';
				}
			}
			cout << hex << "Next Message w" << setw(2) << j << ": " << setw(8) << messageSchedule[j] << "\nNext Prime # k" << setw(2) << j << ": " << setw(8) << curPrime << '\n';
			cout << setfill('0') << "T0: " << setw(8) << T0 << "\nT1: " << setw(8) << T1;
			c = getchar();
		}

		system("CLS");
		cout << header;
		cout << "Now hashing block " << i << ": " << "\n\n";
		cout << "Compress the message schedule into the word registers\n";
		for (l = 0; l < 8; l++)
		{
			cout << (char)(97 + l) << ": ";
			switch (l)
			{
			case 0: cout << setw(36) << setfill(' ') << "" << "\t\t" << setw(8) << "" << " + T0 + T1\n"; break;
			case 4: for (m = 32; m > 0; m--)
						cout << (wordRegisters[l] >> (m - 1)) % 2 << ((m % 8 == 1) ? " " : "");
					cout << hex << "\t\t" << setfill('0') << setw(8) << wordRegisters[l] << " + T0\n"; break;
			default: for (m = 32; m > 0; m--)
						cout << (wordRegisters[l] >> (m - 1)) % 2 << ((m % 8 == 1) ? " " : "");
					 cout << hex << "\t\t" << setfill('0') << setw(8) << wordRegisters[l] << '\n';
			}
		}
		cout << hex << "Next Message w" << setw(2) << j << ": " << setw(8) << messageSchedule[j] << "\nNext Prime # k" << setw(2) << j << ": " << setw(8) << curPrime << '\n';
		cout << setfill('0') << "T0: " << setw(8) << T0 << "\nT1: " << setw(8) << T1;
		c = getchar();
		wordRegisters[0] = T0 + T1;
		wordRegisters[4] += T0;
		
		system("CLS");
		cout << header;
		cout << "Now hashing block " << i << ": " << "\n\n";
		cout << "Compress the message schedule into the word registers\n";
		for (l = 0; l < 8; l++)
		{
			cout << (char)(97 + l) << ": ";
			for (m = 32; m > 0; m--)
				cout << (wordRegisters[l] >> (m - 1)) % 2 << ((m % 8 == 1) ? " " : "");
			cout << hex << "\t\t" << setfill('0') << setw(8) << wordRegisters[l] << '\n';
		}
		cout << hex << "Next Message w" << setw(2) << j << ": " << setw(8) << messageSchedule[j] << "\nNext Prime # k" << setw(2) << j << ": " << setw(8) << curPrime << '\n';
		cout << setfill('0') << "T0: " << setw(8) << T0 << "\nT1: " << setw(8) << T1;
		c = getchar();

		for (j = 1; j < 64; j++)
		{
			constants >> curPrime;
			T0 = S1(wordRegisters[4]) + Ch(wordRegisters[4], wordRegisters[5], wordRegisters[6]) + wordRegisters[7] + curPrime + messageSchedule[j];
			T1 = S0(wordRegisters[0]) + Ma(wordRegisters[0], wordRegisters[1], wordRegisters[2]);

			system("CLS");
			cout << header;
			cout << "Now hashing block " << i << ": " << "\n\n";
			cout << "Compress the message schedule into the word registers\n";
			for (l = 0; l < 8; l++)
			{
				cout << (char)(97 + l) << ": ";
				for (m = 32; m > 0; m--)
					cout << (wordRegisters[l] >> (m - 1)) % 2 << ((m % 8 == 1) ? " " : "");
				cout << hex << "\t\t" << setfill('0') << setw(8) << wordRegisters[l] << '\n';
			}
			cout << hex << "Next Message w" << setw(2) << j << ": " << setw(8) << messageSchedule[j] << "\nNext Prime # k" << setw(2) << j << ": " << setw(8) << curPrime << '\n';
			cout << setfill('0') << "T0: " << setw(8) << T0 << "\nT1: " << setw(8) << T1;
			c = getchar();

			for (k = 7; k > 0; k--)
				wordRegisters[k] = wordRegisters[k - 1];
			system("CLS");
			cout << header;
			cout << "Now hashing block " << i << ": " << "\n\n";
			cout << "Compress the message schedule into the word registers\n";
			for (l = 0; l < 8; l++)
			{
				cout << (char)(97 + l) << ": ";
				switch (l)
				{
				case 0: cout << '\n'; break;
				default: for (m = 32; m > 0; m--)
					cout << (wordRegisters[l] >> (m - 1)) % 2 << ((m % 8 == 1) ? " " : "");
					cout << hex << "\t\t" << setfill('0') << setw(8) << wordRegisters[l] << " vv\n";
				}
			}
			cout << hex << "Next Message w" << setw(2) << j << ": " << setw(8) << messageSchedule[j] << "\nNext Prime # k" << setw(2) << j << ": " << setw(8) << curPrime << '\n';
			cout << setfill('0') << "T0: " << setw(8) << T0 << "\nT1: " << setw(8) << T1;
			c = getchar();

			wordRegisters[0] = T0 + T1;
			wordRegisters[4] += T0;

			system("CLS");
			cout << header;
			cout << "Now hashing block " << i << ": " << "\n\n";
			cout << "Compress the message schedule into the word registers\n";
			for (l = 0; l < 8; l++)
			{
				cout << (char)(97 + l) << ": ";
				for (m = 32; m > 0; m--)
					cout << (wordRegisters[l] >> (m - 1)) % 2 << ((m % 8 == 1) ? " " : "");
				cout << hex << "\t\t" << setfill('0') << setw(8) << wordRegisters[l];
				switch (l)
				{
				case 0: cout << " + T0 + T1"; break;
				case 4: cout << " + T0"; break;
				}
				cout << '\n';
			}
			cout << hex << "Next Message w" << setw(2) << j << ": " << setw(8) << messageSchedule[j] << "\nNext Prime # k" << setw(2) << j << ": " << setw(8) << curPrime << '\n';
			cout << setfill('0') << "T0: " << setw(8) << T0 << "\nT1: " << setw(8) << T1;
			c = getchar();
		}

		system("CLS");
		cout << header;
		cout << "Now hashing block " << i << ": " << "\n\n";
		cout << "Compress the message schedule into the word registers\n";
		for (l = 0; l < 8; l++)
		{
			cout << (char)(97 + l) << ": ";
			for (m = 32; m > 0; m--)
				cout << (wordRegisters[l] >> (m - 1)) % 2 << ((m % 8 == 1) ? " " : "");
			cout << hex << "\t\t" << setfill('0') << setw(8) << wordRegisters[l] << '\n';
		}
		c = getchar();

		cout << "Add the final values of the word registers to the initial values\n";
		for (j = 0; j < 8; j++)
		{
			cout << 'H' << j << ": ";
			for (m = 32; m > 0; m--)
				cout << (prevHashValues[j] >> (m - 1)) % 2 << ((m % 8 == 1) ? " " : "");
			cout << '\t' << setw(8) << prevHashValues[j] << '\n';
		}
		c = getchar();

		system("CLS");
		cout << header;
		cout << "Now hashing block " << i << ": " << "\n\n";
		cout << "Compress the message schedule into the word registers\n";
		for (l = 0; l < 8; l++)
		{
			cout << (char)(97 + l) << ": ";
			for (m = 32; m > 0; m--)
				cout << (wordRegisters[l] >> (m - 1)) % 2 << ((m % 8 == 1) ? " " : "");
			cout << hex << "\t\t" << setfill('0') << setw(8) << wordRegisters[l] << '\n';
		}
		cout << "\nAdd the final values of the word registers to the initial values\n";
		for (j = 0; j < 8; j++)
		{
			cout << 'H' << j << ": ";
			for (m = 32; m > 0; m--)
				cout << (prevHashValues[j] >> (m - 1)) % 2 << ((m % 8 == 1) ? " " : "");
			cout << '\t' << setw(8) << prevHashValues[j] << " + " << (char)(97 + j) << '\n';
		}
		c = getchar();

		system("CLS");
		cout << header;
		cout << "Now hashing block " << i << ": " << "\n\n";
		cout << "Compress the message schedule into the word registers\n";
		for (l = 0; l < 8; l++)
		{
			cout << (char)(97 + l) << ": ";
			for (m = 32; m > 0; m--)
				cout << (wordRegisters[l] >> (m - 1)) % 2 << ((m % 8 == 1) ? " " : "");
			cout << hex << "\t\t" << setfill('0') << setw(8) << wordRegisters[l] << '\n';
		}
		for (j = 0; j < 8; j++)
			wordRegisters[j] += prevHashValues[j];
		cout << "\nAdd the final values of the word registers to the initial values\n";
		for (j = 0; j < 8; j++)
		{
			cout << 'H' << j << ": ";
			for (m = 32; m > 0; m--)
				cout << (wordRegisters[j] >> (m - 1)) % 2 << ((m % 8 == 1) ? " " : "");
			cout << '\t' << setw(8) << wordRegisters[j] << '\n';
		}
		c = getchar();
		cout << "Block " << i << " has been hashed!\n";
		c = getchar();
	}

	cout << "Concatinate the final values together\n";
	c = getchar();

	hashDigest* digest = new hashDigest;
	for (i = 0; i < 8; i++)
		digest->rawDigest[i] = wordRegisters[i];

	printDigest(*digest);
	c = getchar();

	cout << "There is the final hash!";
	c = getchar();

	delete[] hashBlocks;
	delete[] messageSchedule;
	delete[] wordRegisters;
	delete[] prevHashValues;
	constants.close();

	return digest;
}
