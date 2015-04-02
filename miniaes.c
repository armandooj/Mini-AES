/*
Mini AES Encryption
*/

#include "miniaes.h"
#include <stdio.h>

#define NR 2 // Number of rounds
#define NB 3 // Number of columns
#define NKC 4 // Number of key coeficients

#define GET_BIT(a, k) ((a & ( 1 << k )) >> k)

typedef uint8_t state_t[NB][NB];
static state_t *state;

// The original key
static const uint8_t *Key;
// Array containing NB(NR + 1) round keys
static uint8_t RoundKey[12] = {};

uint8_t A[] = {0x04, 0x06, 0x07};

uint8_t MultiplyTriple(uint8_t y) {
	int i, j;
	uint8_t result = 0;
	for (i = 0; i < 3; i++) {
		uint8_t bit = 0;
		int pos = 0;		
		for (int j = 2; j >= 0; j--) {
			bit += GET_BIT(A[i], j) * GET_BIT(y, pos);
			// bit = 1;
			// printf(" %x x %x", GET_BIT(A[i], j), GET_BIT(y, pos));
			pos++;			
		}

		// printf("\n (%x) ", bit << i);
		result += (bit << i);
		// printf(" %x \n", GET_BIT(y, i));
	}

	return result;
}

// For an entry a, computes its inverse y and then compute its transformation (weights low to high from up to bottom)
uint8_t SubBytes(uint8_t a) {	

	uint8_t y;

	printf("%d %d %d\n", GET_BIT(a, 0), GET_BIT(a, 1), GET_BIT(a, 2));
	// TODO compute the inverse y
	y = a;
	uint8_t ay = MultiplyTriple(y);

	// Can I do it just like this?
  	return ay + 0x05 % 2;
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
		uint8_t w4i = Key[2 * i - 1];

		printf("w41: %x\n", w4i);
		// 3 bits left cyclic shift
		uint8_t T = (w4i << 1) | (w4i >> (8 - 1));
		//uint8_t T = w4i << 3;
		printf("T after shift: %x\n", T);
		
		T = SubBytes(T);
		printf("T2: %x\n", T);

		// First time we xor with 010 and then with 100
		T = T ^ aux;
		aux *= 2;

		// Calculate the rest of the round keys
		RoundKey[4 * i] = Key[4 * i - 4] ^ T;
		RoundKey[4 * i + 1] = Key[4 * i - 3] ^ Key[4 * i];
		RoundKey[4 * i + 2] = Key[4 * i - 2] ^ Key[4 * i + 1];
		RoundKey[4 * i + 3] = Key[4 * i - 1] ^ Key[4 * i + 2];
	}

	// Hard code Richard's keys for now
	// RoundKey[4] = 0x01;
	// RoundKey[5] = 0x00;
	// RoundKey[6] = 0x04;
	// RoundKey[7] = 0x00;

	// RoundKey[8] = 0x06;
	// RoundKey[9] = 0x04;
	// RoundKey[10] = 0x04;
	// RoundKey[11] = 0x00;


	printf("Round keys: ");
	for (i = 0; i < 12; i++) {
		printf("%x", RoundKey[i]);
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
  (*state)[1][1] = (*state)[1][2];
  (*state)[1][2] = temp;

  // third row 2 columns to left
  temp = (*state)[2][0];
  (*state)[2][0] = (*state)[2][2];
  (*state)[2][2] = (*state)[2][1];
  (*state)[2][1] = temp;
}

// Multiply each column seen as a polynomial (low to high degrees from up to bottom)
void MixColumns(void) {
  	uint8_t i;
  	uint8_t Tmp, Tm, t;
  	for (i = 0; i < 3; i++) {
    	t = (*state)[i][0];
    	Tmp = (*state)[i][0] ^ (*state)[i][1] ^ (*state)[i][2];
    	Tm = (*state)[i][0] ^ (*state)[i][1];
    	Tm = xtime(Tm);
    	(*state)[i][0] ^= Tm ^ Tmp;

    	Tm = (*state)[i][1] ^ (*state)[i][2];
    	Tm = xtime(Tm);
    	(*state)[i][1] ^= Tm ^ Tmp;

    	Tm = (*state)[i][2] ^ t;
    	Tm = xtime(Tm);
    	(*state)[i][2] ^= Tm ^ Tmp;
  	}
}

// Adds the round key to state.
// The round key is added to the state by an XOR function.
void AddRoundKey(uint8_t round) {

  	uint8_t i, j;
  	for (i = 0; i < NB; i++) {
    	for (j = 0; j < NB; j++ ) {
      		(*state)[i][j] ^= RoundKey[round * NB * 3 + i * NB + j]; // TODO verify this is correct..
    	}
  	}
}

void BlockCopy(uint8_t *output, uint8_t *input) {
  	uint8_t i;
  	for (i = 0; i < 9; i++) {
    	output[i] = input[i];
  	}
}

void PrintState() {
	int i, j;
	printf("\nState:\n");
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
	Key = key;

	PrintState();

	KeySchedule();

	uint8_t round = 0;

	PrintState();

	// Start with the first round
	AddRoundKey(0);

	PrintState();

	// int psh = 0;
	// for (int i = 0; i < 3; ++i) {
	// 	for (int j = 0; j < 3; ++j) {
	// 		(*state)[i][j] = psh;
	// 		psh++;
	// 	}		
	// 	/* code */
	// }

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