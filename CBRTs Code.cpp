/* Code used to obtain the remainders of the cubed roots of the 1st 64 prime numbers
*  Slightly modified version used to find initial hash values for wordRegisters*/
	fstream outputFile;
	outputFile.open("CBRTs.txt", ios::out);
	int n = 2;
	int found = 0;
	bool prime = true;
	int i;
	unsigned long cbrtn;
	while (found < 64)
	{
		i = 3;
		while (i <= sqrt(n) && prime)
		{
			prime = !(n % i == 0);
			i += 2;
		}
		if (prime)
		{
			cbrtn = (cbrt(n) - (double)((int)cbrt(n))) * pow(2, 32);
			outputFile << cbrtn << '\n';
			found++;
		}
		else prime = true;
		n += (1 + (n % 2));
	}
