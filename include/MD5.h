#ifndef MD5_H
#define MD5_H

#include <fstream>
#include <string>

class MD5 {
 public:
  MD5();
  void update(const unsigned char* input, size_t length);
  void update(const std::string& input);
  void update(std::ifstream& stream);
  std::string finalize();
  static std::string hash(const std::string& input);
  static std::string hashFile(const std::string& filename);

 private:
  void transform(const unsigned char block[64]);
  static void decode(uint32_t output[], const unsigned char input[],
                     size_t len);
  static void encode(unsigned char output[], const uint32_t input[],
                     size_t len);

  bool finalized;
  unsigned char buffer[64];
  uint32_t count[2];
  uint32_t state[4];
  unsigned char digest[16];

  static inline uint32_t F(uint32_t x, uint32_t y, uint32_t z);
  static inline uint32_t G(uint32_t x, uint32_t y, uint32_t z);
  static inline uint32_t H(uint32_t x, uint32_t y, uint32_t z);
  static inline uint32_t I(uint32_t x, uint32_t y, uint32_t z);
  static inline uint32_t rotate_left(uint32_t x, int n);
  static inline void FF(uint32_t& a, uint32_t b, uint32_t c, uint32_t d,
                        uint32_t x, uint32_t s, uint32_t ac);
  static inline void GG(uint32_t& a, uint32_t b, uint32_t c, uint32_t d,
                        uint32_t x, uint32_t s, uint32_t ac);
  static inline void HH(uint32_t& a, uint32_t b, uint32_t c, uint32_t d,
                        uint32_t x, uint32_t s, uint32_t ac);
  static inline void II(uint32_t& a, uint32_t b, uint32_t c, uint32_t d,
                        uint32_t x, uint32_t s, uint32_t ac);
};

#endif