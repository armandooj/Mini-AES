/*
Mini AES Encryption
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

void PrintBits(uint8_t from, uint8_t num) {
	printf("[");
	int i;
	for (i = num - 1; i >= 0; i--) {
		printf(" %d ", GET_BIT(from, i));
	}
	printf("]\n");
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

// For an entry a, computes its inverse y and then compute its transformation (weights low to high from up to bottom)
uint8_t SubBytes(uint8_t a) {	

	uint8_t y;

	printf("SubBytes: ");
	PrintBits(a, 3);
	
	// TODO compute the inverse y
	y = a;
	uint8_t ay = MultiplyTriple(y);

  	return ay;
}

// Generates NB(NR + 1) round keys from the cipherkey
// As opposed to the original AES, the circular shift is replaced by T := W 4i-1 <<< 2 
void KeySchedule() {

	int i;
	// The first round key is the original key
	for (i = 0; i < NKC; i++) {
		RoundKey[i] = Key[i];
	}

	int aux = 2;
	for (i = 1; i <= NR; i++) {

		printf("\nRound %d\n", i);

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

		T1 = SubBytes(T1);
		T2 = SubBytes(T2);
		T = ((T1 << 3) & 56) + T2;
		printf("new T: %x\n", T);
		// PrintBits(T, 6);

		// First time we xor with 010 and then with 100
		T = T ^ aux;
		aux *= 2;

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

uint8_t xtime(uint8_t x) {
	// 7?
  	return ((x << 1) ^ (((x >> 7) & 1) * 0x1b));
}

// The ShiftRows() function shifts the rows in the state to the left.
// Each row is shifted with different offset.
// Offset = Row number. So the first row is not shifted.
void ShiftRows(void) {
  uint8_t temp;

  // second row 1 column to left
  temp = (*state)[1][0];
  (*state)[1][0] = (*state)[1][1];
  (*state)[1][1] = temp;
}

// Multiply each column seen as a polynomial (low to high degrees from up to bottom)
void MixColumns(void) {
  	// uint8_t i;
  	// uint8_t Tmp, Tm, t;
  	// for (i = 0; i < 3; i++) {
   //  	t = (*state)[i][0];
   //  	Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2];
   //  	Tm = (*state)[i][0] ^ (*state)[i][1];
   //  	Tm = xtime(Tm);
   //  	(*state)[i][0] ^= Tm ^ Tmp;

   //  	Tm = (*state)[i][1] ^ (*state)[i][2];
   //  	Tm = xtime(Tm);
   //  	(*state)[i][1] ^= Tm ^ Tmp;

   //  	Tm = (*state)[i][2] ^ t;
   //  	Tm = xtime(Tm);
   //  	(*state)[i][2] ^= Tm ^ Tmp;
  	// }
}

// Adds the round key to state.
// The round key is added to the state by an XOR function.
void AddRoundKey(uint8_t round) {

  	uint8_t i, j;
  	for (i = 0; i < NB; i++) {
    	for (j = 0; j < NB; j++ ) {
      		(*state)[i][j] ^= RoundKey[round * NB * 2 + i * NB + j]; // TODO verify this is correct..
    	}
  	}
}

void BlockCopy(uint8_t *output, uint8_t *input) {
  	uint8_t i;
  	for (i = 0; i < 4; i++) {
    	output[i] = input[i];
  	}
}

void PrintState() {
	int i, j;
	for (i = 0; i < NB; i++) {
    	for (j = 0; j < NB; j++ ) {
 	   		printf(" %x ", (*state)[i][j]);
		}
		printf("\n");
	}	
}

void encrypt(uint8_t *input, const uint8_t *key, uint8_t *output) {

	// TODO Should I copy the input to output one by one?
	BlockCopy(output, input);
  	state = (state_t *)input;
	PrintState();

	Key = key;
	KeySchedule();

	// Start with the first round
	printf("\nAdd round key 0...\n");
	uint8_t round = 0;
	AddRoundKey(round);
	PrintState();

	printf("\nStarting rounds..\n");

	for (round = 1; round <= NR; round++) {

		//state = SubBytes(state);

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
}

void decrypt(uint8_t* input, const uint8_t* key, uint8_t *output) {
	// Exactly the same but in the opposite way
}