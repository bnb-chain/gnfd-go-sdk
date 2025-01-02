package types

import (
	"encoding/hex"

	"github.com/prysmaticlabs/prysm/v5/crypto/bls"

	"cosmossdk.io/math"

	"github.com/bnb-chain/greenfield/sdk/keys"
	"github.com/cometbft/cometbft/crypto/secp256k1"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

// Account indicates the user's identity information used for interaction with Greenfield.
type Account struct {
	name string
	km   keys.KeyManager
}

// TransferDetail includes the target address and amount for token transfer.
type TransferDetail struct {
	ToAddress string
	Amount    math.Int
}

// NewAccountFromPrivateKey - Create account instance according to private key.
//
// -name: Account name.
//
// -privKey: Private key.
//
// -ret1: The pointer of the created account instance.
//
// -ret2: Error message if the privKey is not correct, otherwise returns nil.
func NewAccountFromPrivateKey(name, privKey string) (*Account, error) {
	km, err := keys.NewPrivateKeyManager(privKey)
	if err != nil {
		return nil, err
	}
	return &Account{
		name: name,
		km:   km,
	}, nil
}

// NewAccountFromMnemonic - Create account instance according to mnemonic.
//
// -name: Account name.
//
// -mnemonic: The mnemonic string.
//
// -ret1: The pointer of the created account instance.
//
// -ret2: Error message if the mnemonic is not correct, otherwise returns nil.
func NewAccountFromMnemonic(name, mnemonic string) (*Account, error) {
	km, err := keys.NewMnemonicKeyManager(mnemonic)
	if err != nil {
		return nil, err
	}
	return &Account{
		name: name,
		km:   km,
	}, nil
}

// NewAccount - Create a random new account.
//
// -name: The account name.
//
// -ret1: The pointer of the created account instance.
//
// -ret2: The private key of the created account.
//
// -ret3: Error message.
func NewAccount(name string) (*Account, string, error) {
	privKey := secp256k1.GenPrivKey()
	km, err := keys.NewPrivateKeyManager(hex.EncodeToString(privKey.Bytes()))
	if err != nil {
		return nil, "", err
	}
	return &Account{
		name: name,
		km:   km,
	}, hex.EncodeToString(privKey.Bytes()), nil
}

// NewBlsAccount - Create a random new account with bls key pairs.
//
// -name: The account name.
//
// -ret1: The pointer of the created account instance.
//
// -ret2: The bls private key of the created account.
//
// -ret3: Error message.
func NewBlsAccount(name string) (*Account, string, error) {
	blsPrivKey, _ := bls.RandKey()
	km, err := keys.NewBlsPrivateKeyManager(hex.EncodeToString(blsPrivKey.Marshal()))
	if err != nil {
		return nil, "", err
	}
	return &Account{
		name: name,
		km:   km,
	}, hex.EncodeToString(blsPrivKey.Marshal()), nil
}

// GetKeyManager - Get the key manager of the account.
func (a *Account) GetKeyManager() keys.KeyManager {
	return a.km
}

// GetAddress - Get the address of the account.
func (a *Account) GetAddress() sdk.AccAddress {
	return a.km.GetAddr()
}

// Sign - Use the account's private key to sign for the input data.
func (a *Account) Sign(unsignBytes []byte) ([]byte, error) {
	return a.km.Sign(unsignBytes)
}
