#include <stdio.h>
#include <memory.h>

void maccess(void *p) { asm volatile("movq (%0), %%rax\n" : : "c"(p) : "rax"); }

char __attribute__((aligned(4096))) secret[8192];

int main(int argc, char* argv[]) {
  char* key = "_SECRET_";
    
  if(argc >= 2) {
    key = argv[1];
  }
  size_t secret_len = strnlen(key, 64);
  
  printf("Loading secret value '%s'...\n", key);
  
  for (int i = 0; i < (4096 * 2) / 64; i += 1)
    memcpy(secret + i * 64, key, secret_len);

  // load value all the time
  while (1)
    {
      for (int i = 0; i < 100; i++)
        maccess(secret + i * 64);
    }
}
