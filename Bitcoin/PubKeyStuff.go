package Bitcoin

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
	"golang.org/x/crypto/ripemd160"
)

func PublicKeyHash(mnemonic string) string {

	prv := MneMonicToPrivateKey(mnemonic)

	privKey, err := crypto.ToECDSA(prv)
	if err != nil {
		panic(err)
	}
	publicKey := crypto.FromECDSAPub(&privKey.PublicKey)
	publicKeyHash, _ := ComputeCompressedPubKeyHash(publicKey)

	publicKeyHashString := hex.EncodeToString(publicKeyHash)

	return publicKeyHashString
}

func MneMonicToPrivateKey(mnemonic string) []byte {

	seed, err := bip39.NewSeedWithErrorChecking(mnemonic, "")
	if err != nil {
		log.Fatalf("Error generating seed: %v", err)
	}

	privateKey, err := derivePrivateKey(seed, "m/44'/0'/0'/0/0")
	if err != nil {
		log.Fatalf("Error deriving private key: %v", err)
	}

	return privateKey
}

func derivePrivateKey(seed []byte, path string) ([]byte, error) {
	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		return nil, fmt.Errorf("error generating master key: %v", err)
	}

	key, err := deriveKeyFromPath(masterKey, path)
	if err != nil {
		return nil, fmt.Errorf("error deriving key from path: %v", err)
	}

	return key.Key, nil
}

func deriveKeyFromPath(masterKey *bip32.Key, path string) (*bip32.Key, error) {
	segments := parseDerivationPath(path)
	key := masterKey

	for _, segment := range segments {
		childKey, err := key.NewChildKey(segment)
		if err != nil {
			return nil, fmt.Errorf("error deriving child key: %v", err)
		}
		key = childKey
	}

	return key, nil
}

func parseDerivationPath(path string) []uint32 {
	var segments []uint32
	pathSegments := strings.Split(path, "/")[1:]

	for _, segment := range pathSegments {
		if len(segment) > 0 && segment[len(segment)-1] == '\'' {
			segment = segment[:len(segment)-1]
			index, err := strconv.Atoi(segment)
			if err != nil {
				log.Fatalf("Invalid segment: %v", err)
			}
			segments = append(segments, uint32(index)+0x80000000)
		} else {
			index, err := strconv.Atoi(segment)
			if err != nil {
				log.Fatalf("Invalid segment: %v", err)
			}
			segments = append(segments, uint32(index))
		}
	}

	return segments
}

func ComputeCompressedPubKeyHash(pubkey []byte) ([]byte, error) {
	if len(pubkey) != 65 || pubkey[0] != 0x04 {
		return nil, fmt.Errorf("expected uncompressed public key (65 bytes starting with 0x04)")
	}

	x := pubkey[1:33]
	y := pubkey[33:]

	yBig := new(big.Int).SetBytes(y)

	var prefix byte = 0x02
	if yBig.Bit(0) == 1 {
		prefix = 0x03
	}

	compressedPubKey := append([]byte{prefix}, x...)

	shaHash := sha256.Sum256(compressedPubKey)
	ripemd := ripemd160.New()
	_, err := ripemd.Write(shaHash[:])
	if err != nil {
		return nil, err
	}
	return ripemd.Sum(nil), nil
}

func P2PKHScript(pubKeyHash string) string {

	pubkeyHashByte, err := hex.DecodeString(pubKeyHash)
	if err != nil {
		return fmt.Sprintf("Error while decoding publickeyhash")
	}
	script := make([]byte, 0, 25)
	script = append(script, 0x76)              // OP_DUP
	script = append(script, 0xa9)              // OP_HASH160
	script = append(script, 0x14)              // Push 20 bytes
	script = append(script, pubkeyHashByte...) // pubKeyHash
	script = append(script, 0x88)              // OP_EQUALVERIFY
	script = append(script, 0xac)              // OP_CHECKSIG

	return hex.EncodeToString(script)
}
