#include "MD5.h"

#include <cstring>
#include <iomanip>
#include <iostream>
#include <sstream>

MD5::MD5() {
  finalized = false;
  count[0] = count[1] = 0;
  state[0] = 0x67452301;
  state[1] = 0xefcdab89;
  state[2] = 0x98badcfe;
  state[3] = 0x10325476;
}

void MD5::update(const unsigned char* input, size_t length) {
  size_t index = count[0] / 8 % 64;

  if ((count[0] += (length << 3)) < (length << 3)) count[1]++;
  count[1] += (length >> 29);

  size_t firstpart = 64 - index;
  size_t i;

  if (length >= firstpart) {
    memcpy(&buffer[index], input, firstpart);
    transform(buffer);

    for (i = firstpart; i + 63 < length; i += 64) transform(&input[i]);

    index = 0;
  } else {
    i = 0;
  }

  memcpy(&buffer[index], &input[i], length - i);
}

void MD5::update(const std::string& input) {
  update((const unsigned char*)input.c_str(), input.length());
}

void MD5::update(std::ifstream& stream) {
  if (!stream) return;

  std::streamsize length;
  char buffer[1024];

  while (stream.good()) {
    stream.read(buffer, 1024);
    length = stream.gcount();
    if (length > 0) update((const unsigned char*)buffer, length);
  }
}

std::string MD5::finalize() {
  if (!finalized) {
    static unsigned char padding[64] = {
        0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0,    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    unsigned char bits[8];
    encode(bits, count, 8);

    size_t index = count[0] / 8 % 64;
    size_t padLen = (index < 56) ? (56 - index) : (120 - index);
    update(padding, padLen);
    update(bits, 8);

    encode(digest, state, 16);

    finalized = true;
  }

  std::stringstream ss;
  for (int i = 0; i < 16; i++)
    ss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];

  return ss.str();
}

std::string MD5::hash(const std::string& input) {
  MD5 md5;
  md5.update(input);
  return md5.finalize();
}

std::string MD5::hashFile(const std::string& filename) {
  std::ifstream file(filename, std::ios::binary);
  if (!file) {
    return "";
  }

  MD5 md5;
  md5.update(file);
  return md5.finalize();
}

uint32_t MD5::F(uint32_t x, uint32_t y, uint32_t z) {
  return (x & y) | (~x & z);
}
uint32_t MD5::G(uint32_t x, uint32_t y, uint32_t z) {
  return (x & z) | (y & ~z);
}
uint32_t MD5::H(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }
uint32_t MD5::I(uint32_t x, uint32_t y, uint32_t z) { return y ^ (x | ~z); }

uint32_t MD5::rotate_left(uint32_t x, int n) {
  return (x << n) | (x >> (32 - n));
}

void MD5::FF(uint32_t& a, uint32_t b, uint32_t c, uint32_t d, uint32_t x,
             uint32_t s, uint32_t ac) {
  a = rotate_left(a + F(b, c, d) + x + ac, s) + b;
}

void MD5::GG(uint32_t& a, uint32_t b, uint32_t c, uint32_t d, uint32_t x,
             uint32_t s, uint32_t ac) {
  a = rotate_left(a + G(b, c, d) + x + ac, s) + b;
}

void MD5::HH(uint32_t& a, uint32_t b, uint32_t c, uint32_t d, uint32_t x,
             uint32_t s, uint32_t ac) {
  a = rotate_left(a + H(b, c, d) + x + ac, s) + b;
}

void MD5::II(uint32_t& a, uint32_t b, uint32_t c, uint32_t d, uint32_t x,
             uint32_t s, uint32_t ac) {
  a = rotate_left(a + I(b, c, d) + x + ac, s) + b;
}

void MD5::transform(const unsigned char block[64]) {
  uint32_t a = state[0], b = state[1], c = state[2], d = state[3], x[16];
  decode(x, block, 64);

  // Раунд 1
  FF(a, b, c, d, x[0], 7, 0xd76aa478);
  FF(d, a, b, c, x[1], 12, 0xe8c7b756);
  FF(c, d, a, b, x[2], 17, 0x242070db);
  FF(b, c, d, a, x[3], 22, 0xc1bdceee);
  FF(a, b, c, d, x[4], 7, 0xf57c0faf);
  FF(d, a, b, c, x[5], 12, 0x4787c62a);
  FF(c, d, a, b, x[6], 17, 0xa8304613);
  FF(b, c, d, a, x[7], 22, 0xfd469501);
  FF(a, b, c, d, x[8], 7, 0x698098d8);
  FF(d, a, b, c, x[9], 12, 0x8b44f7af);
  FF(c, d, a, b, x[10], 17, 0xffff5bb1);
  FF(b, c, d, a, x[11], 22, 0x895cd7be);
  FF(a, b, c, d, x[12], 7, 0x6b901122);
  FF(d, a, b, c, x[13], 12, 0xfd987193);
  FF(c, d, a, b, x[14], 17, 0xa679438e);
  FF(b, c, d, a, x[15], 22, 0x49b40821);

  // Раунд 2
  GG(a, b, c, d, x[1], 5, 0xf61e2562);
  GG(d, a, b, c, x[6], 9, 0xc040b340);
  GG(c, d, a, b, x[11], 14, 0x265e5a51);
  GG(b, c, d, a, x[0], 20, 0xe9b6c7aa);
  GG(a, b, c, d, x[5], 5, 0xd62f105d);
  GG(d, a, b, c, x[10], 9, 0x2441453);
  GG(c, d, a, b, x[15], 14, 0xd8a1e681);
  GG(b, c, d, a, x[4], 20, 0xe7d3fbc8);
  GG(a, b, c, d, x[9], 5, 0x21e1cde6);
  GG(d, a, b, c, x[14], 9, 0xc33707d6);
  GG(c, d, a, b, x[3], 14, 0xf4d50d87);
  GG(b, c, d, a, x[8], 20, 0x455a14ed);
  GG(a, b, c, d, x[13], 5, 0xa9e3e905);
  GG(d, a, b, c, x[2], 9, 0xfcefa3f8);
  GG(c, d, a, b, x[7], 14, 0x676f02d9);
  GG(b, c, d, a, x[12], 20, 0x8d2a4c8a);

  // Раунд 3
  HH(a, b, c, d, x[5], 4, 0xfffa3942);
  HH(d, a, b, c, x[8], 11, 0x8771f681);
  HH(c, d, a, b, x[11], 16, 0x6d9d6122);
  HH(b, c, d, a, x[14], 23, 0xfde5380c);
  HH(a, b, c, d, x[1], 4, 0xa4beea44);
  HH(d, a, b, c, x[4], 11, 0x4bdecfa9);
  HH(c, d, a, b, x[7], 16, 0xf6bb4b60);
  HH(b, c, d, a, x[10], 23, 0xbebfbc70);
  HH(a, b, c, d, x[13], 4, 0x289b7ec6);
  HH(d, a, b, c, x[0], 11, 0xeaa127fa);
  HH(c, d, a, b, x[3], 16, 0xd4ef3085);
  HH(b, c, d, a, x[6], 23, 0x4881d05);
  HH(a, b, c, d, x[9], 4, 0xd9d4d039);
  HH(d, a, b, c, x[12], 11, 0xe6db99e5);
  HH(c, d, a, b, x[15], 16, 0x1fa27cf8);
  HH(b, c, d, a, x[2], 23, 0xc4ac5665);

  // Раунд 4
  II(a, b, c, d, x[0], 6, 0xf4292244);
  II(d, a, b, c, x[7], 10, 0x432aff97);
  II(c, d, a, b, x[14], 15, 0xab9423a7);
  II(b, c, d, a, x[5], 21, 0xfc93a039);
  II(a, b, c, d, x[12], 6, 0x655b59c3);
  II(d, a, b, c, x[3], 10, 0x8f0ccc92);
  II(c, d, a, b, x[10], 15, 0xffeff47d);
  II(b, c, d, a, x[1], 21, 0x85845dd1);
  II(a, b, c, d, x[8], 6, 0x6fa87e4f);
  II(d, a, b, c, x[15], 10, 0xfe2ce6e0);
  II(c, d, a, b, x[6], 15, 0xa3014314);
  II(b, c, d, a, x[13], 21, 0x4e0811a1);
  II(a, b, c, d, x[4], 6, 0xf7537e82);
  II(d, a, b, c, x[11], 10, 0xbd3af235);
  II(c, d, a, b, x[2], 15, 0x2ad7d2bb);
  II(b, c, d, a, x[9], 21, 0xeb86d391);

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;

  memset(x, 0, sizeof(x));
}

void MD5::decode(uint32_t output[], const unsigned char input[], size_t len) {
  for (size_t i = 0, j = 0; j < len; i++, j += 4)
    output[i] = ((uint32_t)input[j]) | (((uint32_t)input[j + 1]) << 8) |
                (((uint32_t)input[j + 2]) << 16) |
                (((uint32_t)input[j + 3]) << 24);
}

void MD5::encode(unsigned char output[], const uint32_t input[], size_t len) {
  for (size_t i = 0, j = 0; j < len; i++, j += 4) {
    output[j] = input[i] & 0xff;
    output[j + 1] = (input[i] >> 8) & 0xff;
    output[j + 2] = (input[i] >> 16) & 0xff;
    output[j + 3] = (input[i] >> 24) & 0xff;
  }
}