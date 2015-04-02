#include <stdio.h>
#include <stdlib.h>
#include "miniaes.h"

int main () {

  // 011100 100001
  uint8_t key[] = {0x1C, 0x21};
  // 001 001 110 011
  uint8_t input[] = {0x01, 0x01, 0x06, 0x03};

  uint8_t output[4];
	encrypt(input, key, output);

	return 0;
}