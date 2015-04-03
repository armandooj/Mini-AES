/*
Mini-AES Encryption
*/

#include "miniaes.h"
#include <stdio.h>

#define NR 2 // Number of rounds
#define NB 2 // Number of columns
#define NKC 2 // Number of key coeficients

#define GET_BIT(a, k) ((a & ( 1 << k )) >> k)

typedef uint8_t state_t[NB][NB];
// Intermediate cipher result
static state_t *state;
// The original key
static const uint8_t *Key;
// Array containing NB(NR + 1) round keys
static uint8_t RoundKey[6] = {};
// MixColumn matrix
uint8_t G[] = {2, 3, 1, 2};

void PrintBits(uint8_t from, uint8_t num) {
	
	printf("[");
	int i;
	for (i = num - 1; i >= 0; i--) {
		printf(" %d ", GET_BIT(from, i));
	}
	printf("]\n");
}

void PrintState() {
	int i, j;
	for (i = 0; i < NB; i++) {
    	for (j = 0; j < NB; j++) {
 	   		printf(" %x ", (*state)[i][j]);
		}
		printf("\n");
	}
}

uint8_t Check3Bits(uint8_t number) {
	if (number > 7) {
		number ^= 0xB; // 1011
	}
	return number;
}

/* 
A = | 1 0 0 |   | y0 |   | 1 |
    | 1 1 0 | x | y1 | + | 0 | mod 2
    | 1 1 1 |   | y2 |   | 1 |
*/
uint8_t MultiplyTriple(uint8_t y) {

	uint8_t y0 = GET_BIT(y, 0);
	uint8_t y1 = GET_BIT(y, 1);
	uint8_t y2 = GET_BIT(y, 2);

	uint8_t z0 = y0 ^ 1;
	uint8_t z1 = y0 ^ y1;
	uint8_t z2 = y0 ^ y1 ^ y2 ^ 1;

	return z0 + (z1 * 2) + (z2 * 4);
}

uint8_t MultiplyPol(uint8_t pol1, uint8_t pol2) {
	
	uint8_t i = 0;
	uint8_t res = 0;
	uint8_t j, k;

	while (pol1) {
		k = pol1 & 1;
		pol1 >>= 1;
		if (k) {
			uint8_t j;
			uint8_t aux = pol2;			
			for (j = 0; j < i; j++) {
				aux <<= 1;
				if (aux & 8) {
					aux ^= 11;
				}
			}
			res ^= aux;
		}
		i++;
	}
	return res;
}

uint8_t inverse(uint8_t n) {
	uint8_t n2, n4, n6;
	n2 = MultiplyPol(n, n);
	n4 = MultiplyPol(n2, n2);
	n6 = MultiplyPol(n4, n2);
	return n6;
}

// For an entry a, computes its inverse y and then compute its transformation (weights low to high from up to bottom)
// a -> 3 bits
uint8_t SubBytes(uint8_t a) {
	// Return the inverse y
  	return MultiplyTriple(inverse(a));
}

// Generates NB(NR + 1) round keys from the cipherkey
// As opposed to the original AES, the circular shift is replaced by T := W 4i-1 <<< 2 
void KeySchedule() {

	int i;
	// The first round key is the original key
	for (i = 0; i < NKC; i++) {
		RoundKey[i] = Key[i];
	}

	int xi = 2;
	for (i = 1; i <= NR; i++) {

		printf("\nRound key iteration %d\n", i);

		uint8_t w2i = RoundKey[2 * i - 1];
		printf("w2i: %x\n", w2i);
		
		// 3 bits left cyclic shift
		uint8_t T = (w2i << 3 | w2i >> 3) & 63;
		printf("T (w2i << 3): %x\n", T);		

		// T = T1 T2
		// 3 left bits -> & 111000, and then shift them!
		uint8_t T1 = (T & 56) >> 3;
		// 3 right bits -> & 000111
		uint8_t T2 = T & 7;
		printf("T1: %x T2: %x\n", T1, T2);

		PrintBits(T, 6);
		T1 = SubBytes(T1);
		T2 = SubBytes(T2);

		// But it back together
		T = ((T1 << 3) & 56) + T2;

		// xor with 010 and then with 100 (both << 3).. and so on..
		T = T ^ (xi << 3);
		xi *= 2;

		printf("new T1: %x new T2: %x\n", T1, T2);
		printf("new T: %d\n", T);
		PrintBits(T, 6);		

		// Calculate the rest of the round keys
		RoundKey[2 * i] = RoundKey[2 * i - 2] ^ T;
		RoundKey[2 * i + 1] = RoundKey[2 * i - 1] ^ RoundKey[2 * i];
	}

	printf("\nRound keys: ");
	for (i = 0; i < 6; i++) {
		printf(" [%x] ", RoundKey[i]);
	}
	printf("\n");
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
void ShiftRows() {
	uint8_t temp;
	// second row 1 column to left
	temp = (*state)[1][1];
	(*state)[1][1] = (*state)[0][1];
	(*state)[0][1] = temp;
}

// Multiply each column seen as a polynomial (low to high degrees from up to bottom) by the G matrix
void MixColumns() {

	int i, j;
	uint8_t temp[NB][NB];

	for (i = 0; i < NB; i++) {
		// First number
		uint8_t G0S0 = MultiplyPol(G[0], (*state)[0][i]);
		int8_t G1S1 = MultiplyPol(G[1], (*state)[1][i]);
		temp[0][i] = G0S0 ^ G1S1;
		// Second number
		uint8_t G2S0 = MultiplyPol(G[2], (*state)[0][i]);
		uint8_t G3S1 = MultiplyPol(G[3], (*state)[1][i]);
		temp[1][i] = G2S0 ^ G3S1;
	}

	// Put the matrix back in the state keeping the [w1 w2 w3 w4] format
	(*state)[0][0] = temp[0][0];
	(*state)[0][1] = temp[1][0];
	(*state)[1][0] = temp[0][1];
	(*state)[1][1] = temp[1][1];
}

// Adds the round key to state.
// The round key is added to the state by an XOR function.
void AddRoundKey(uint8_t round) {

	(*state)[0][0] ^= (RoundKey[round * 2] & 56) >> 3;
	(*state)[0][1] ^= RoundKey[round * 2] & 7;
	(*state)[1][0] ^= (RoundKey[round * 2 + 1] & 56) >> 3;
	(*state)[1][1] ^= RoundKey[round * 2 + 1] & 7;
}

void BlockCopy(uint8_t *output, uint8_t *input) {
  	uint8_t i;
  	for (i = 0; i < 4; i++) {
    	output[i] = input[i];
  	}
}

void encrypt(uint8_t *input, const uint8_t *key, uint8_t *output) {

	// We are going to work always on the intermediary state matrix, fill it
	BlockCopy(output, input);
  	state = (state_t *)output;
	PrintState();

	Key = key;
	KeySchedule();

	// Start with the first round
	printf("\nAdd round key 0...\n");
	uint8_t round = 0;
	AddRoundKey(round);
	PrintState();

	printf("\nStarting rounds..\n");

	int i, j;
	for (round = 1; round < NR; round++) {

		printf("\nSubBytes...\n");	
		for (i = 0; i < NB; i++) {
			for (j = 0; j < NB; j++) {
				(*state)[i][j] = SubBytes((*state)[i][j]);
			}
		}
		PrintState();

		printf("\nShifting rows...\n");
		ShiftRows();
		PrintState();

		printf("\nMixing columns...\n");
		MixColumns();
		PrintState();
		
		printf("\nAdding round key %d...\n", round);
		AddRoundKey(round);
		PrintState();
	}

	printf("\nSubBytes...\n");
	for (i = 0; i < NB; i++) {
		for (j = 0; j < NB; j++) {
			(*state)[i][j] = SubBytes((*state)[i][j]);
		}
	}
	PrintState();

	printf("\nShifting rows...\n");
	ShiftRows();
	PrintState();

	printf("\nAdding round key %d...\n", NR);
	AddRoundKey(NR);
	PrintState();
	
	// 0x00 0x0F 0x08 0x03
	printf("\nFinal:\n");
	PrintState();

	// Put the state matrix in the output
	output[0] = (*state)[0][0];
	output[1] = (*state)[0][1];
	output[2] = (*state)[1][0];
	output[3] = (*state)[1][1];
}

void decrypt(uint8_t *input, const uint8_t *key, uint8_t *output) {
	// Exactly the same but in the opposite way
}