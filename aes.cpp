#include <string>
#include <iostream>
#include <crypto++/osrng.h>
#include <crypto++/modes.h>
#include <crypto++/hex.h>

using std::cout;
using std::endl;
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;
using CryptoPP::StringSource;
using CryptoPP::StringSink;
using CryptoPP::StreamTransformationFilter;

class Crypto {
  //using CryptoType = CryptoPP::ECB_Mode<CryptoPP::AES>;
  //using CryptoType = CryptoPP::CBC_Mode<CryptoPP::AES>;
  using CryptoType = CryptoPP::CTR_Mode<CryptoPP::AES>;

public:
  Crypto()
    : key(0x00, CryptoPP::AES::DEFAULT_KEYLENGTH),
      iv(CryptoPP::AES::BLOCKSIZE) {

    // Generate a random key
    rnd.GenerateBlock( key, key.size() );

    // Generate a random IV
    rnd.GenerateBlock(iv, iv.size());

    encctx.reset(new CryptoType::Encryption(key, key.size(), iv));
    decctx.reset(new CryptoType::Decryption(key, key.size(), iv));
    //encctx.reset(new CryptoType::Encryption(key, key.size()));
    //decctx.reset(new CryptoType::Decryption(key, key.size()));
  }

  std::string enc(const std::string& plain) {
    // Encrypt
    std::string cipher;
    StringSource( plain, true,
                  new StreamTransformationFilter( *encctx,
                                                  new StringSink( cipher )
                                                  //StreamTransformationFilter::PKCS_PADDING
                                                  //StreamTransformationFilter::ZEROS_PADDING
                    )
      );
    //cout << "cipher: " << cipher << endl;
    return cipher;
  }

  std::string dec(const std::string& coded) {
    // Decrypt
    std::string decoded;
    StringSource( coded, true,
                  new StreamTransformationFilter( *decctx,
                                                  new StringSink( decoded )
                                                  //StreamTransformationFilter::PKCS_PADDING
                                                  //StreamTransformationFilter::ZEROS_PADDING
                    )
      );
    return decoded;
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

  std::string plain = "Hello! How are you.";
  cout << "plain    : " << plain;

  auto encoded = crypto.enc(plain);

  plain = "Good morning!";
  cout << plain << endl;
  encoded += crypto.enc(plain);

  plain = "にゃーん";
  cout << plain << endl;
  encoded += crypto.enc(plain);

  plain = "RTT±500ms";
  cout << plain << endl;
  encoded += crypto.enc(plain);

  auto decoded = crypto.dec(encoded);
  cout << "decoded  : " << decoded << endl;
}
