const crypto = require("crypto");
const bip39 = require("bip39");
const secp256k1 = require("secp256k1");
const keccak256 = require("js-sha3").keccak256;
const fs = require('fs');

const WORDLIST = JSON.parse(fs.readFileSync('wordlist.json', 'utf8'));


// 1. ニーモニックフレーズの生成
function generateMnemonic(entropyBits = 128) {
  console.log(
    "\n========================\n 1. generateMnemonic \n========================\n"
  );
  // 1. エントロピーの生成
  const entropy = crypto.randomBytes(entropyBits / 8);
  const entropyBin = Array.from(entropy)
    .map((byte) => byte.toString(2).padStart(8, "0"))
    .join("");
  console.log("---entropyBin---:", entropyBin);
  //11100010010111000110101100110111000000010110001000110110110000001101000001010100011011111001100101101000000000100101101010010010

  // 2. SHA-256でSのハッシュ値を取り、そのハッシュ値の先頭ビットからチェックサムを生成
  const hash = crypto.createHash("sha256").update(entropy).digest();
  const hashBin = Array.from(hash)
    .map((byte) => byte.toString(2).padStart(8, "0"))
    .join("");
  const checksumLength = entropyBits / 32;
  const checksum = hashBin.substring(0, checksumLength);
  console.log("---checksum---:", checksum);
  // 0101

  // 3. このチェックサムをエントロピーのビット文字列の最後に追加する
  const entropyWithChecksum = entropyBin + checksum;

  // 3. バイナリ文字列を11ビットごとに分割
  const chunks = [];
  for (let i = 0; i < entropyWithChecksum.length; i += 11) {
    chunks.push(entropyWithChecksum.slice(i, i + 11));
  }
  console.log("---chunks---:", chunks)
  // [
  //   "11100010010", "11100011010", "11001101110",
  //   "00000010110", "00100011011", "01100000011",
  //   "01000001010", "10001101111", "10011001011",
  //   "01000000000", "10010110101", "01100100000",
  // ];

  // 4. 各チャンクを整数として解釈し、ニーモニックを生成
  const mnemonic = chunks.map((bin) => WORDLIST[parseInt(bin, 2)]).join(" ");
  console.log("---mnemonic---:", mnemonic);
  //time today soccer actress casino gather donor mistake offer divorce note across

  return mnemonic;
}

// 2. ニーモニックからシードへの変換
function mnemonicToSeed(mnemonic, password = "test") {
  console.log(
    "\n========================\n 2. mnemonicToSeed \n======================== \n"
  );

  const salt = "mnemonic" + password;
  const seed = crypto.pbkdf2Sync(mnemonic, salt, 2048, 64, "sha512");
  console.log("---seed---:", seed.toString("hex"));
  // 86b7c8d3658bc1326ffe12f6b64ac60fe618eec64d7660be800d52029cb6936860b9d48dd1d24bf5159a70fae3a728418e959942c1554e2b24538fbb55fb0246

  return seed;
}

// 3. シードからマスターキーとチェーンコードの生成
function deriveMasterKey(seed) {
  console.log(
    "\n========================\n 3. deriveMasterKey \n======================== \n"
  );

  // 暗号的ハッシュ関数と共有秘密キーを使用して、データの整合性と認証を提供するためのアルゴリズム
  const hmac = crypto.createHmac("sha512", "Bitcoin seed");
  hmac.update(seed);
  const result = hmac.digest();

  const masterKey = result.slice(0, 32);
  const chainCode = result.slice(32);
  console.log("---masterKey---:", masterKey.toString("hex"));
  console.log("---chainCode---:", chainCode.toString("hex"));
  return { masterKey, chainCode };
}

// 4. マスターキーから子キーの派生
function deriveChildKey(masterKey, chainCode, index) {
  console.log(
    "\n========================\n 4. deriveChildKey \n======================== \n"
  );

  const data = Buffer.concat([masterKey, Buffer.from([index])]);

  // 前回のchainCodeをキーとして HMACの初期化
  const hmac = crypto.createHmac("sha512", chainCode);
  hmac.update(data);
  const result = hmac.digest();

  const childKey = result.slice(0, 32);
  const newChainCode = result.slice(32);
  console.log("---childKey---:", childKey.toString("hex"));
  console.log("---newChainCode---:", newChainCode.toString("hex"));
  return { childKey, chainCode: newChainCode };
}

// 5. 子キーからEthereumのアドレスを生成
function privateKeyToEthereumAddress(privateKey) {
  console.log(
    "\n========================\n 5. privateKeyToEthereumAddress \n======================== \n"
  )

  const publicKey = secp256k1.publicKeyCreate(privateKey, false).slice(1);
  const address = keccak256(publicKey).slice(-40);
  return "0x" + address;
}

const mnemonic = generateMnemonic();
const seed = mnemonicToSeed(mnemonic);
const { masterKey, chainCode } = deriveMasterKey(seed);
const { childKey } = deriveChildKey(masterKey, chainCode, 0);
const address = privateKeyToEthereumAddress(childKey);

console.log("========================")
console.log("Mnemonic:", mnemonic);
console.log("Ethereum Address:", address);