#include <openssl/aead.h>
#include <openssl/curve25519.h>
#include <openssl/digest.h>
#include <openssl/hkdf.h>
#include <openssl/hmac.h>
#include <openssl/hpke.h>
#include <openssl/mem.h>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string_view>
#include <vector>

namespace {

int Nibble(char value) {
  if (value >= '0' && value <= '9') return value - '0';
  if (value >= 'a' && value <= 'f') return value - 'a' + 10;
  if (value >= 'A' && value <= 'F') return value - 'A' + 10;
  return -1;
}

bool Decode(std::string_view input, std::vector<uint8_t>* output) {
  if (input.size() % 2 != 0) return false;
  output->resize(input.size() / 2);
  for (size_t index = 0; index < output->size(); ++index) {
    const int high = Nibble(input[index * 2]);
    const int low = Nibble(input[index * 2 + 1]);
    if (high < 0 || low < 0) return false;
    (*output)[index] = static_cast<uint8_t>((high << 4) | low);
  }
  return true;
}

bool Equal(const std::vector<uint8_t>& expected,
           const std::vector<uint8_t>& actual, size_t actual_size) {
  return expected.size() == actual_size &&
         CRYPTO_memcmp(expected.data(), actual.data(), actual_size) == 0;
}

int AeadOpen(char** arguments) {
  std::vector<uint8_t> key, nonce, aad, ciphertext, expected;
  if (!Decode(arguments[2], &key) || !Decode(arguments[3], &nonce) ||
      !Decode(arguments[4], &aad) || !Decode(arguments[5], &ciphertext) ||
      !Decode(arguments[6], &expected)) {
    return 2;
  }
  EVP_AEAD_CTX* context = EVP_AEAD_CTX_new(
      EVP_aead_aes_256_gcm_siv(), key.data(), key.size(),
      EVP_AEAD_DEFAULT_TAG_LENGTH);
  if (context == nullptr) return 3;
  std::vector<uint8_t> output(ciphertext.size());
  size_t output_size = 0;
  const int opened = EVP_AEAD_CTX_open(
      context, output.data(), &output_size, output.size(), nonce.data(),
      nonce.size(), ciphertext.data(), ciphertext.size(), aad.data(), aad.size());
  EVP_AEAD_CTX_free(context);
  return opened == 1 && Equal(expected, output, output_size) ? 0 : 4;
}

int AeadReject(char** arguments) {
  std::vector<uint8_t> key, nonce, aad, ciphertext;
  if (!Decode(arguments[2], &key) || !Decode(arguments[3], &nonce) ||
      !Decode(arguments[4], &aad) || !Decode(arguments[5], &ciphertext)) {
    return 2;
  }
  EVP_AEAD_CTX* context = EVP_AEAD_CTX_new(
      EVP_aead_aes_256_gcm_siv(), key.data(), key.size(),
      EVP_AEAD_DEFAULT_TAG_LENGTH);
  if (context == nullptr) return 0;
  std::vector<uint8_t> output(ciphertext.size(), 0xa5);
  size_t output_size = 0;
  const int opened = EVP_AEAD_CTX_open(
      context, output.data(), &output_size, output.size(), nonce.data(),
      nonce.size(), ciphertext.data(), ciphertext.size(), aad.data(), aad.size());
  EVP_AEAD_CTX_free(context);
  return opened == 0 && output_size == 0 ? 0 : 4;
}

int HpkeOpen(char** arguments) {
  std::vector<uint8_t> private_key, encapsulation, info, aad, ciphertext,
      expected;
  if (!Decode(arguments[2], &private_key) ||
      !Decode(arguments[3], &encapsulation) || !Decode(arguments[4], &info) ||
      !Decode(arguments[5], &aad) || !Decode(arguments[6], &ciphertext) ||
      !Decode(arguments[7], &expected)) {
    return 2;
  }
  EVP_HPKE_KEY* key = EVP_HPKE_KEY_new();
  EVP_HPKE_CTX* context = EVP_HPKE_CTX_new();
  if (key == nullptr || context == nullptr ||
      !EVP_HPKE_KEY_init(key, EVP_hpke_xwing(), private_key.data(),
                         private_key.size()) ||
      !EVP_HPKE_CTX_setup_recipient(
          context, key, EVP_hpke_hkdf_sha256(), EVP_hpke_chacha20_poly1305(),
          encapsulation.data(), encapsulation.size(), info.data(), info.size())) {
    EVP_HPKE_CTX_free(context);
    EVP_HPKE_KEY_free(key);
    return 3;
  }
  std::vector<uint8_t> output(ciphertext.size());
  size_t output_size = 0;
  const int opened = EVP_HPKE_CTX_open(
      context, output.data(), &output_size, output.size(), ciphertext.data(),
      ciphertext.size(), aad.data(), aad.size());
  EVP_HPKE_CTX_free(context);
  EVP_HPKE_KEY_free(key);
  return opened == 1 && Equal(expected, output, output_size) ? 0 : 4;
}

int HpkeReject(char** arguments) {
  std::vector<uint8_t> private_key, encapsulation, info, aad, ciphertext;
  if (!Decode(arguments[2], &private_key) ||
      !Decode(arguments[3], &encapsulation) || !Decode(arguments[4], &info) ||
      !Decode(arguments[5], &aad) || !Decode(arguments[6], &ciphertext)) {
    return 2;
  }
  EVP_HPKE_KEY* key = EVP_HPKE_KEY_new();
  EVP_HPKE_CTX* context = EVP_HPKE_CTX_new();
  if (key == nullptr || context == nullptr) {
    EVP_HPKE_CTX_free(context);
    EVP_HPKE_KEY_free(key);
    return 3;
  }
  if (!EVP_HPKE_KEY_init(key, EVP_hpke_xwing(), private_key.data(),
                         private_key.size()) ||
      !EVP_HPKE_CTX_setup_recipient(
          context, key, EVP_hpke_hkdf_sha256(), EVP_hpke_chacha20_poly1305(),
          encapsulation.data(), encapsulation.size(), info.data(), info.size())) {
    EVP_HPKE_CTX_free(context);
    EVP_HPKE_KEY_free(key);
    return 0;
  }
  std::vector<uint8_t> output(ciphertext.size(), 0xa5);
  size_t output_size = 0;
  const int opened = EVP_HPKE_CTX_open(
      context, output.data(), &output_size, output.size(), ciphertext.data(),
      ciphertext.size(), aad.data(), aad.size());
  EVP_HPKE_CTX_free(context);
  EVP_HPKE_KEY_free(key);
  return opened == 0 && output_size == 0 ? 0 : 4;
}

int Hkdf(char** arguments) {
  std::vector<uint8_t> secret, salt, info, expected;
  if (!Decode(arguments[2], &secret) || !Decode(arguments[3], &salt) ||
      !Decode(arguments[4], &info) || !Decode(arguments[5], &expected)) {
    return 2;
  }
  std::vector<uint8_t> output(expected.size());
  const int derived =
      HKDF(output.data(), output.size(), EVP_sha256(), secret.data(),
           secret.size(), salt.data(), salt.size(), info.data(), info.size());
  return derived == 1 && Equal(expected, output, output.size()) ? 0 : 4;
}

int HmacCheck(char** arguments, bool expect_valid) {
  std::vector<uint8_t> key, message, expected;
  if (!Decode(arguments[2], &key) || !Decode(arguments[3], &message) ||
      !Decode(arguments[4], &expected)) {
    return 2;
  }
  std::vector<uint8_t> output(EVP_MAX_MD_SIZE);
  unsigned int output_size = 0;
  if (HMAC(EVP_sha256(), key.data(), key.size(), message.data(), message.size(),
           output.data(), &output_size) == nullptr) {
    return 3;
  }
  const bool valid = Equal(expected, output, output_size);
  return valid == expect_valid ? 0 : 4;
}

int Ed25519Check(char** arguments, bool expect_valid) {
  std::vector<uint8_t> public_key, message, signature;
  if (!Decode(arguments[2], &public_key) || !Decode(arguments[3], &message) ||
      !Decode(arguments[4], &signature)) {
    return 2;
  }
  bool valid = false;
  if (public_key.size() == 32 && signature.size() == 64) {
    valid = ED25519_verify(message.data(), message.size(), signature.data(),
                           public_key.data()) == 1;
  }
  return valid == expect_valid ? 0 : 4;
}

}  // namespace

int main(int argc, char** argv) {
  if (argc == 7 && std::strcmp(argv[1], "aead-open") == 0)
    return AeadOpen(argv);
  if (argc == 6 && std::strcmp(argv[1], "aead-reject") == 0)
    return AeadReject(argv);
  if (argc == 8 && std::strcmp(argv[1], "hpke-open") == 0)
    return HpkeOpen(argv);
  if (argc == 7 && std::strcmp(argv[1], "hpke-reject") == 0)
    return HpkeReject(argv);
  if (argc == 6 && std::strcmp(argv[1], "hkdf") == 0) return Hkdf(argv);
  if (argc == 5 && std::strcmp(argv[1], "hmac-valid") == 0)
    return HmacCheck(argv, true);
  if (argc == 5 && std::strcmp(argv[1], "hmac-reject") == 0)
    return HmacCheck(argv, false);
  if (argc == 5 && std::strcmp(argv[1], "ed25519-valid") == 0)
    return Ed25519Check(argv, true);
  if (argc == 5 && std::strcmp(argv[1], "ed25519-reject") == 0)
    return Ed25519Check(argv, false);
  std::fprintf(stderr, "invalid arguments\n");
  return 1;
}
