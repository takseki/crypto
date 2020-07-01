#include <string>
#include <iostream>
#include <crypto++/osrng.h>
#include <crypto++/modes.h>
#include <crypto++/hex.h>

using std::cout;
using std::endl;
using CryptoPP::AES;
using CryptoPP::CBC_Mode;
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;
using CryptoPP::StringSource;
using CryptoPP::StringSink;
using CryptoPP::StreamTransformationFilter;

int main()
{
  CryptoPP::AutoSeededRandomPool rnd;

  // Generate a random key
  CryptoPP::SecByteBlock key(0x00, CryptoPP::AES::DEFAULT_KEYLENGTH);
  rnd.GenerateBlock( key, key.size() );

  // Generate a random IV
  CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);
  rnd.GenerateBlock(iv, iv.size());

  std::string plain = "Hello! How are you.";
  cout << "plain    : " << plain << endl;

  // Encrypt
  CBC_Mode<AES>::Encryption encctx(key, key.size(), iv);
  std::string cipher;
  StringSource( plain, true,
    new StreamTransformationFilter( encctx,
                                    new StringSink( cipher )
                                    //StreamTransformationFilter::PKCS_PADDING
                                    //StreamTransformationFilter::ZEROS_PADDING
      )
    );
  //cout << "cipher: " << cipher << endl;

  // hex encode
  std::string encoded;
  StringSource( cipher, true,
                new HexEncoder(
                  new StringSink( encoded )
                  ));
  cout << "encoded  : " << encoded << endl;

  // hex decode
  std::string decoded;
  StringSource( encoded, true,
                new HexDecoder(
                  new StringSink( decoded )
                  ));
  //cout << "decodeed : " <<  decoded << endl;

  // Decrypt
  CBC_Mode<AES>::Decryption decctx(key, key.size(), iv);
  std::string recovered;
  StringSource( decoded, true,
                new StreamTransformationFilter( decctx,
                                                new StringSink( recovered )
                                                //StreamTransformationFilter::PKCS_PADDING
                                                //StreamTransformationFilter::ZEROS_PADDING
                  )
    );
  cout << "recovered: " << recovered << endl;

}
