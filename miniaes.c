/*
Mini AES Encryption
*/

#include "miniaes.h"
#include <stdio.h>

#define NR 2 // Number of rounds
#define NB 3 // Number of columns
#define NKC 2 // Number of key coeficients

#define GET_BIT(a, k) ((a & ( 1 << k )) >> k)

typedef uint8_t state_t[NB][NB];
// Intermediate cipher result
static state_t *state;

// The original key
static const uint8_t *Key;
// Array containing NB(NR + 1) round keys
static uint8_t RoundKey[6] = {};

/* 
A = | 1 0 0 |
	| 1 1 0 |
	| 1 1 1 |
*/
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

		uint8_t w2i = RoundKey[2 * i - 1];
		printf("w2i: %x\n", w2i);
		
		// 3 bits left cyclic shift
		uint8_t T = (w2i << 3 | w2i >> 3) & 63;
		printf("T (w2i << 3): %x\n", T);
		
		// T = SubBytes(T);
		// printf("T2: %x\n", T);

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