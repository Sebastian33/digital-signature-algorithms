#include"dsa.h"
#include<iostream>

DSAPrivateKey::~DSAPrivateKey()
{
	memset(x.data, 0, sizeof(u64)*x.size);
}

DSAEngine::DSAEngine():pub(nullptr), prvt(nullptr), hashFunction(nullptr)
{}

DSAEngine::DSAEngine(int L0, int N0) :L(L0), N(N0)
{
	int cnt(0);
	bool done(false);
	int outlen(512);
	Sha3Engine gen(outlen);
	int n(L0 / outlen);
	outlen /= 64; // now in u64 size
	int qsize_bytes(N0 / 8);
	int qsize(qsize_bytes / sizeof(u64) + (qsize_bytes % sizeof(u64) > 0 ? 1 : 0));
	int psize(L0 / sizeof(u64) / 8);
	bigint q(qsize);
	bigint p(psize);
	bigint q2(qsize + 1); //2*q
	bigint c(qsize + 1);
	bigint quot(psize - qsize + 1);
	bigint domParSeed(qsize);
	bigint tmpbuf(psize);
	int testnum;
	if (L0 == 1024)
		testnum = 40;
	else if (L0 == 2048)
		testnum = 56;
	else testnum = 64;
	/*p and q generation*/
	do
	{
		do
		{
			generateRandom(domParSeed, N0);
			gen.absorb(domParSeed.data, qsize_bytes);
			gen.getHash(tmpbuf.data);
			memcpy(q.data, tmpbuf.data, qsize_bytes);
			q.hd = qsize - 1;
			q.data[q.hd] |= 1ULL << ((N0 - 1) & 63);
			q.data[0] |= 1;
		} while (!MillerRabin(q, testnum));
		lshift(q, 1, q2);
		inc(domParSeed);
		for (int counter = 0; counter < (4 * L0 - 1); counter++)
		{
			for (u64 j = 0; j < n; j++)
			{
				gen.absorb(domParSeed.data, qsize_bytes);
				gen.getHash(tmpbuf.data + j * outlen);
				inc(domParSeed);
			}
			tmpbuf.hd = psize - 1;
			tmpbuf.data[tmpbuf.hd] |= 1ULL << 63;
			div(tmpbuf, q2, quot, c);// c = X mod 2q
			inc(tmpbuf);
			sub(tmpbuf, c, p); // p = X - (c - 1)
			/*if p is prime and p > 2^(L-1)*/
			if ((p.data[psize - 1] & (1ULL << 63)) && (MillerRabin(p, testnum)))
			{
				done = true;
				break;
			}
		}

	} while (!done);
	pub = new DSAPublicKey;
	pub->p = std::move(p);
	pub->q = std::move(q);
	pub->g.resize(psize);
	pub->g.data[0] = 1;
	/* generation of an element g such that ord(g) = q*/
	myuP = myuInit(pub->p);
	myuQ = myuInit(pub->q);
	tmpbuf = pub->p;
	tmpbuf.data[0] ^= 1;// = p - 1
	div(tmpbuf, pub->q, quot, tmpbuf); //quot = p-1 / q
	tmpbuf.data[0] = 2;
	while (pub->g.isUnity())
	{
		powMod(tmpbuf, quot, myuP, pub->p, pub->g);
		inc(tmpbuf);
	}
	/* key pair generation*/
	pub->y.resize(psize);
	prvt = new DSAPrivateKey;
	do
	{
		generateRandom(prvt->x, N0);
	} while ((cmp(prvt->x, pub->q) >= 0) || (prvt->x.isUnity()));
	powMod(pub->g, prvt->x, myuP, pub->p, pub->y);

	hashFunction = new Sha3Engine(N0);
}

DSAEngine::~DSAEngine()
{
	if (pub)
	{
		delete pub;
		delete hashFunction;
	}
	if (prvt)
		delete prvt;
}

int DSAEngine::SetKeys(int L0, int N0, DSAPublicKey *pub0, DSAPrivateKey *prvt0)
{
	/*TODO: use constants with descriptive names instead of just numbers as return values
	 0 OK
	-1 NO PUBLIC KEY AND PARAMETRES
	-2 INVALID PARAMETERS
	-3 INVALID KEYS*/
	if (!pub0)
		return -1;

	int psize(L0 / sizeof(u64) / 8);
	if ((pub0->p.length() != L0) || (pub0->q.length() != N0))
		return -2;
	L = L0;
	N = N0;

	bigint tmpbuf(psize);
	bigint quot(psize);
	tmpbuf = pub0->p;
	tmpbuf.data[0] -= 1;
	/* verifying that p-1 = q*k, k in N */
	div(tmpbuf, pub0->q, quot, tmpbuf);
	if (!tmpbuf.isZero()) 
		return -2;

	myuP = myuInit(pub0->p);
	myuQ = myuInit(pub0->q);
	/* g < p*/
	if (cmp(pub0->g, pub0->p) >= 0)
		return -2;
	/*verifying that g^e != 1 mod p, where e = (p-1)/q */
	powMod(pub0->g, quot, myuP, pub0->p, tmpbuf);
	if (tmpbuf.isUnity())
		return -2;
	/* now ord(g) is truly equals q*/
	powMod(pub0->g, pub0->q, myuP, pub0->p, tmpbuf);
	if (!tmpbuf.isUnity())
		return -2;

	if (cmp(pub0->y, pub0->p) >= 0)
		return -3;
	hashFunction = new Sha3Engine(N0);
	pub = new DSAPublicKey;
	pub->g = pub0->g;
	pub->p = pub0->p;
	pub->q = pub0->q;
	pub->y = pub0->y;
	
	if (!prvt0)
		return 0;

	/*verifying that y = g^x mod p*/
	powMod(pub0->g, prvt0->x, myuP, pub0->p, tmpbuf);
	if (cmp(tmpbuf, pub0->y) != 0)
	{
		delete pub;
		delete hashFunction;
		hashFunction = nullptr;
		pub = nullptr;
		return -3;
	}
	prvt = new DSAPrivateKey;
	prvt->x = std::move(prvt0->x);
	return 0;
}

void DSAEngine::test()
{
	std::cout << pub->q.hex() << std::endl;
	std::cout << pub->p.hex() << std::endl;
	std::cout << pub->g.hex() << std::endl;
	std::cout << pub->y.hex() << std::endl;
	std::cout << prvt->x.hex() << std::endl;
}

void DSAEngine::Absorb(void* buf, unsigned n)
{
	hashFunction->absorb(buf, n);
}

int DSAEngine::Sign(bigint &r, bigint &s)
{
	if (!prvt)
		return -1;

	bigint tmp(L / sizeof(u64) / 8);
	bigint k(L / sizeof(u64) / 8);
	bigint z(L / sizeof(u64) / 8);
	generateRandom(k, N);
	/*r = (g^k mod p) mod q*/
	powMod(pub->g, k, myuP, pub->p, tmp);
	div(tmp, pub->q, tmp, r); 

	hashFunction->getHash(z.data);
	int i = N / sizeof(u64) / 8 - 1;
	while ((!z.data[i]) && (i >= 0))
	{
		i--;
	}
	z.hd = i;
	/*s = (k^-1)(z + xr) mod q*/
	mulMod(prvt->x, r, myuQ, pub->q, tmp);
	bool carry = add(z, tmp, tmp);
	if ((cmp(tmp, pub->q) >= 0) || carry)
		sub(tmp, pub->q, tmp);
	inverse(k, myuQ, pub->q, k);
	mulMod(k, tmp, myuQ, pub->q, s);

	memset(k.data, 0, (k.size - 1) * 8);
}

int DSAEngine::VerifySignature(const bigint &r, const bigint &s)
{
	bigint tmp(L / sizeof(u64) / 8);
	bigint u1(L / sizeof(u64) / 8);
	bigint u2(L / sizeof(u64) / 8);
	bigint v(L / sizeof(u64) / 8);
	inverse(s, myuQ, pub->q, tmp);
	hashFunction->getHash(u1.data);
	int i = N / sizeof(u64) / 8 - 1;
	while ((!u1.data[i]) && (i >= 0))
	{
		i--;
	}
	u1.hd = i;
	mulMod(u1, tmp, myuQ, pub->q, u1);
	mulMod(r, tmp, myuQ, pub->q, u2);
	powMod(pub->g, u1, myuP, pub->p, tmp);
	powMod(pub->y, u2, myuP, pub->p, v);
	mulMod(v, tmp, myuP, pub->p, v);
	div(v, pub->q, tmp, v);
	return cmp(v, r) == 0 ? 0 : -1;
}