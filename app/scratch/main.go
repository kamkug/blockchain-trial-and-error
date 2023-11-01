package main

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
)

type Tx struct {
	FromID string `json:"from"`
	ToID   string `json:"to"`
	Value  uint64 `json:"value"`
}

func main() {
	if err := run(); err != nil {
		log.Fatalln(err)
	}
}

func run() error {

	privateKey, err := crypto.LoadECDSA("zblock/accounts/kennedy.ecdsa")
	if err != nil {
		return fmt.Errorf("unable to load private key for node: %w", err)
	}

	tx := Tx{
		FromID: "0xF01813E4B85e178A83e29B8E7bF26BD830a25f32",
		ToID:   "Aaron",
		Value:  1000,
	}

	data, err := json.Marshal(tx)
	if err != nil {
		return fmt.Errorf("unable to marshal: %w", err)
	}

	stamp := []byte(fmt.Sprintf("\x19Ardan Signed Message:\n%d", len(data)))

	v := crypto.Keccak256(stamp, data)

	sig, err := crypto.Sign(v, privateKey)
	if err != nil {
		return fmt.Errorf("unable to sign: %w", err)
	}

	fmt.Println("SIG:", hexutil.Encode(sig))

	// ===============================================================
	// OVER THE WIRE

	publicKey, err := crypto.SigToPub(v, sig)
	if err != nil {
		return fmt.Errorf("unable to dervice public key: %w", err)
	}

	fmt.Println("PUB:", crypto.PubkeyToAddress(*publicKey).String())

	// ===============================================================

	tx = Tx{
		FromID: "0xF01813E4B85e178A83e29B8E7bF26BD830a25f32",
		ToID:   "Frank",
		Value:  250,
	}

	data, err = json.Marshal(tx)
	if err != nil {
		return fmt.Errorf("unable to marshal: %w", err)
	}

	stamp = []byte(fmt.Sprintf("\x19Ardan Signed Message:\n%d", len(data)))
	v2 := crypto.Keccak256(stamp, data)

	sig2, err := crypto.Sign(v2, privateKey)
	if err != nil {
		return fmt.Errorf("unable to sign: %w", err)
	}

	fmt.Println("SIG:", hexutil.Encode(sig2))
	// ===============================================================
	// OVER THE WIRE

	tx2 := Tx{
		FromID: "0xF01813E4B85e178A83e29B8E7bF26BD830a25f32",
		ToID:   "Frank",
		Value:  250,
	}

	data, err = json.Marshal(tx2)
	if err != nil {
		return fmt.Errorf("unable to marshal: %w", err)
	}

	stamp = []byte(fmt.Sprintf("\x19Ardan Signed Message:\n%d", len(data)))
	v2 = crypto.Keccak256(stamp, data)

	fmt.Println(v2)

	publicKey, err = crypto.SigToPub(v2, sig2)
	if err != nil {
		return fmt.Errorf("unable to dervice public key: %w", err)
	}

	fmt.Println("PUB:", crypto.PubkeyToAddress(*publicKey).String())

	s := "4c2c74d96439cc2fea1e05f83e07e0ab68f9e12671b9805b0c0a8366ebcd298f60f556a7f25e04630e73d40775cbea81ae4e99e17f29a10a9fa35d735fe5438d00"
	s = s[:128]
	s += "27"
	fmt.Printf("S value: %v\nR value: %v\nV value: %v\n", s[:64], s[64:128], s[128:])

	return nil

}
