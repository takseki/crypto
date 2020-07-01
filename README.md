# crypto

c++ の暗号ライブラリ crypto++ のお試し。

## インストール
ubuntu の場合、
```
sudo apt install libcrypto++-dev
```

## ビルド
-lcryptopp でリンクできる。-lcprypto++ としても同じライブラリをリンクする。

## インクルードの書き方
以下のどちらでも同じ。
```
#include <cryptopp/hoge.h>
#include <crypto++/hoge.h>
```

## namespace
基本的には CrytoPP に入っているが、全部でもない。
