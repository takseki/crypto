#include <string>
#include <iostream>
#include <crypto++/osrng.h>
#include <crypto++/modes.h>
#include <crypto++/hex.h>

using CryptoPP::HexEncoder;
using CryptoPP::StringSource;
using CryptoPP::StringSink;
using CryptoPP::StreamTransformationFilter;
using std::cout;
using std::endl;

/**
 * reference: https://www.cryptopp.com/wiki/Advanced_Encryption_Standard
 */
class Crypto {
  //using CryptoType = CryptoPP::ECB_Mode<CryptoPP::AES>;
  //using CryptoType = CryptoPP::CBC_Mode<CryptoPP::AES>;
  using CryptoType = CryptoPP::CTR_Mode<CryptoPP::AES>;


  // defalut key length = 16byte (128bit)
  const byte KEY[CryptoPP::AES::DEFAULT_KEYLENGTH] = {
    0x39, 0x79, 0x50, 0x5f, 0x25, 0xd1, 0xf8, 0x26,
    0x38, 0x08, 0xe2, 0x95, 0x0f, 0xd4, 0xa6, 0xd2
  };

public:
  Crypto()
    : key(KEY, sizeof(KEY)),
      iv(CryptoPP::AES::BLOCKSIZE) {

    // print key
    cout << "Key : " << getHexString(key)
         << " (" << CryptoPP::AES::DEFAULT_KEYLENGTH << "byte)" << endl;

    // Generate a random IV
    rnd.GenerateBlock(iv, iv.size());

    cout << "IV  : " << getHexString(iv)
         << " (" << iv.size() << "byte)" << endl;

    encctx.reset(new CryptoType::Encryption(key, key.size(), iv));
    decctx.reset(new CryptoType::Decryption(key, key.size(), iv));
    //encctx.reset(new CryptoType::Encryption(key, key.size()));
    //decctx.reset(new CryptoType::Decryption(key, key.size()));
  }

  std::string enc(const std::string& plain) {

    // Encrypt
    std::string cipher;
    StringSource(plain, true,
                 new StreamTransformationFilter(*encctx,
                                                new StringSink(cipher)));
    cout << "coded : " << getHexString(cipher) << " (" << cipher.size() << "byte)" << endl;
    return cipher;
  }

  std::string dec(const std::string& coded) {
    // Decrypt
    std::string decoded;
    StringSource(coded, true,
                 new StreamTransformationFilter(*decctx,
                                                new StringSink(decoded)));
    return decoded;
  }

private:
  std::string getHexString(const CryptoPP::SecByteBlock& block) {
    std::string result;
    StringSource ss(block, block.size(), true,
                    new HexEncoder(new StringSink(result)));
    return result;
  }
  std::string getHexString(const std::string& block) {
    std::string result;
    StringSource ss(block, true,
                    new HexEncoder(new StringSink(result)));
    return result;
  }

private:
  CryptoPP::AutoSeededRandomPool rnd;
  CryptoPP::SecByteBlock key;
  CryptoPP::SecByteBlock iv;
  std::unique_ptr<CryptoType::Encryption> encctx;
  std::unique_ptr<CryptoType::Decryption> decctx;
};

int main()
{
  Crypto crypto;

  std::string plain = "Hello!";
  cout << "plain : " << plain << " (" << plain.size() << "byte)" << endl;;

  auto encoded = crypto.enc(plain);

  // longer than block length
  plain = "Good morning! How are you?";
  cout << "plain : " << plain << " (" << plain.size() << "byte)" << endl;;
  encoded += crypto.enc(plain);

  // wide character
  plain = "にゃーん";
  cout << "plain : " << plain << " (" << plain.size() << "byte)" << endl;;
  encoded += crypto.enc(plain);

  // include wide character
  plain = "RTT±500ms";
  cout << "plain : " << plain << " (" << plain.size() << "byte)" << endl;;
  encoded += crypto.enc(plain);

  // 連結されたものをデコード
  auto decoded = crypto.dec(encoded);
  cout << "decoded : " << decoded << endl;
}
