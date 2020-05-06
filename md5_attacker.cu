#include <cstdio>
#include <iostream>
#include <cstdlib>
#include <cstdint>
#include <string>
#include "md5.cu"


// Convert Big endian to little endian
#define SWAP_INT32(x) (((x) >> 24) | (((x) & 0x00FF0000) >> 8) | (((x) & 0x0000FF00) << 8) | ((x) << 24))
#define CONST_MIN_PASSWORD_LENGTH 1
#define CONST_MAX_PASSWORD_LENGTH 7
#define CONST_CHAR_SET "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
#define CONST_CHAR_SET_LENGTH (sizeof(CONST_CHAR_SET) - 1)

using std::cout;
using std::cerr;
using std::endl;
using std::string;
using std::stoul;


__device__ __host__ bool getNextPw(char* pw_set, size_t step, size_t* length, size_t base = CONST_CHAR_SET_LENGTH) {
  size_t pos = 0;
  size_t carry = step;
  while (carry > 0 && pos < CONST_MAX_PASSWORD_LENGTH + 1) {
    size_t sum = carry + pw_set[pos];
    pw_set[pos] = sum % base;
    carry = sum / base;
    pos ++;
  }
  if (pos > *length)
    *length = pos;
  if (pos > CONST_MAX_PASSWORD_LENGTH)
    return false;
  return true;
}

__global__ void md5_attacker(size_t len, char* word_set, char *charset, char *cracked_pw, int hash_per_thread, uint32_t *target) {
  size_t idx = hash_per_thread * (blockIdx.x * blockDim.x + threadIdx.x) ;
  
  // Charset is shared by each block
  extern __shared__ char s[];
  uint32_t hash[4];
  uint32_t target_hash[4];
  char local_word_set[CONST_MAX_PASSWORD_LENGTH + 1];
  char local_word_text[CONST_MAX_PASSWORD_LENGTH + 1];
  
  // Copy from unified memory to local
  memcpy(target_hash, target, 4 * sizeof(uint32_t));
  memcpy(local_word_set, word_set, CONST_MAX_PASSWORD_LENGTH + 1);
  if (threadIdx.x == 0)
  memcpy(s, charset, sizeof(char) * CONST_CHAR_SET_LENGTH);
  
  // Synchronized here to ensure the shared variable is fully copied
  __syncthreads();
  if (!getNextPw(local_word_set, idx, &len)) return;
  for (size_t index = 0; index < hash_per_thread; index++) {
    for(size_t i = 0; i < len; i++){
      local_word_text[i] = s[local_word_set[i]];
    }
    
    // Calculate MD5 hashes
    md5((unsigned char*)local_word_text, len, hash);   
    bool isMatching = true;
    for (int j = 0; j < 4; j++) {
      if (hash[j] != target_hash[j]) {
        isMatching = false;
        break;
      }
    }
    // Find whether it's matching or nor
    if (isMatching) {
      memcpy(cracked_pw, local_word_text, len);
      return;
    } else if(!getNextPw(local_word_set, 1, &len)) 
      return;
  }
}

int main(int argc, char* argv[]) {
  if (argc != 5){
    cerr << "Error: Wrong number of argument" << endl;
    cout << "Usage: ./md5_attacker <md5_target> <block_num> <thread_num> <hash_per_thread>" << endl;
    return -1;
  } 

  string md5 = string(argv[1]);
  if (md5.length() != 32) {
    cerr << "Error: Incorrect length of target md5 hash value" << endl;
    return -1;
  }

  uint32_t *md5_target;
  char *pw_set, *cracked_pw, *char_set;

  // Allocated unified memory
  cudaMallocManaged((void**)&md5_target, sizeof(uint32_t) * 4);
  cudaMallocManaged((void**)&pw_set, sizeof(char) * (CONST_MAX_PASSWORD_LENGTH + 1));
  cudaMallocManaged((void**)&cracked_pw, sizeof(char) * (CONST_MAX_PASSWORD_LENGTH + 1));
  cudaMallocManaged((void**)&char_set, sizeof(char) * CONST_CHAR_SET_LENGTH);

  // Split the md5 hash into words and convert to little-endian
  for (size_t i = 0; i < 4; i++) {
    string hex_word = md5.substr(i * 8, 8);
    md5_target[i] = stoul(hex_word, 0, 16);
    // Convert from big-endian to little-endian 
    md5_target[i] = SWAP_INT32(md5_target[i]);
  }


  memset(pw_set, 0, CONST_MAX_PASSWORD_LENGTH + 1);
  memset(cracked_pw, 0, CONST_MAX_PASSWORD_LENGTH + 1);
  memcpy(char_set, CONST_CHAR_SET, CONST_CHAR_SET_LENGTH);
  
  size_t h_word_len = CONST_MIN_PASSWORD_LENGTH;

  const size_t block_num = stoul(argv[2]);
  const size_t thread_per_block = stoul(argv[3]);
  const size_t hash_per_thread = stoul(argv[4]);

  cudaEvent_t start;
  cudaEvent_t stop;

  cudaEventCreate(&start);
  cudaEventCreate(&stop);
  cudaEventRecord(start);

  while(true) {
    md5_attacker<<<block_num, thread_per_block, CONST_CHAR_SET_LENGTH>>>(h_word_len, pw_set, char_set, cracked_pw, hash_per_thread, md5_target);
    
    // wait to finish
    cudaDeviceSynchronize();

    // Check whether this round has found the target
    if (*cracked_pw != 0) {     
      cout << cracked_pw << endl; 
      break;
    }

    // Update the pw set for next round
    if (!getNextPw(pw_set, thread_per_block * hash_per_thread * block_num, &h_word_len)) {
      cout << "Password Not Found" << endl;
      break;
    }
  }

  float ms;
  cudaEventRecord(stop);
  cudaEventSynchronize(stop);
  cudaEventElapsedTime(&ms, start, stop);
  
  cout << ms << endl;
}
