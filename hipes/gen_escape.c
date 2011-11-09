#include <stdio.h>
#include <string.h>


int main() {
  unsigned char codes[32];
  unsigned char hex;
  int c;

  memset(codes, 0, sizeof(codes));

  for (c = 0; c <= 255; ++c) {
    if ( ( (c >= '0') && (c <= '9') ) ||
         ( (c >= 'A') && (c <= 'Z') ) ||
         ( (c >= 'a') && (c <= 'z') ) ||
         ( (c == '_') ) ||
         ( (c == '-') ) ||
         ( (c == '.') ) ) {
    } else {
      codes[c / 8] |= (1 << (7 - c % 8));
    }
  }

  for (hex = 0; hex < 32; ++hex) {
    printf("0x%02lX, ", codes[hex]);
    if (!((hex+1) % 4))
      printf("\n");
  }
  
}
