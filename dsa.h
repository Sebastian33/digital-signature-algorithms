#pragma once

#include "..\..\bigint_v2\bigint\bigint.h"
#include "..\..\hashes\sha3\sha3.h"

/*According to FIPS 186-4, most of the time*/
class DSAPublicKey
{
public:
	bigint p; //prime modulus
	bigint q; //big divisor of p-1
	bigint g; //subgroup generator
	bigint y; 
};

class DSAPrivateKey
{
public:
	bigint x;
	~DSAPrivateKey();
};

class DSAEngine
{
private:
	int L;
	int N;
	DSAPublicKey *pub;
	DSAPrivateKey *prvt;
	Sha3Engine *hashFunction;
	bigint myuP;
	bigint myuQ;
public:
	/* generates new key pair
	L=1024, N=160 NOT IMPLEMENTED, yet
	L=2048, N=224
	L=2048, N=256
	L=3072, N=256*/
	DSAEngine(int L0, int N0);
	/*Should be used when one has someone's public key or
	when one has already generated key pair 
	After this constructor SetKeys method must be used*/
	DSAEngine();
	int SetKeys(int L0, int N0, DSAPublicKey *pub0, DSAPrivateKey *prvt0 = nullptr);
	~DSAEngine();

	/*absorb may be called several times if not all the data is available
	1) absorb all the data
	2) either sign absorbed data or verify signature*/
	void Absorb(void* buf, unsigned n);
	int Sign(bigint &r, bigint &s);
	int VerifySignature(const bigint &r, const bigint &s);

	void test();
};