package signer

import (
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/cosmos/cosmos-sdk/testutil/testdata"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"github.com/stretchr/testify/require"
)

func TestSigner(t *testing.T) {
	privKey, _, addr := testdata.KeyEthSecp256k1TestPubAddr()
	rawdata := []byte("this is a test stringToSign content")
	// generate signed string bytes
	stringToSign := crypto.Keccak256(rawdata)

	signer := NewMsgSigner(privKey)
	signature, _, err := signer.Sign(stringToSign)
	require.NoError(t, err)
	fmt.Println("origin addr:", addr.String())

	// recover the sender addr
	recoverAcc, pk, err := RecoverAddr(stringToSign, signature)
	require.NoError(t, err)

	fmt.Println("recover sender addr:", recoverAcc.String())
	if !addr.Equals(recoverAcc) {
		t.Errorf("recover addr not same")
	}

	// verify the signature
	verifySucc := secp256k1.VerifySignature(pk.Bytes(), stringToSign, signature[:len(signature)-1])
	if !verifySucc {
		t.Errorf("verify fail")
	}
}

func TestMsgSignV1(t *testing.T) {
	// client actions: new request and sign the request
	urlmap := url.Values{}
	urlmap.Add("greenfield", "chain")
	parms := io.NopCloser(strings.NewReader(urlmap.Encode()))
	req, err := http.NewRequest("POST", "gnfd.nodereal.com", parms)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Host = "testBucket.gnfd.nodereal.com"
	req.Header.Set("X-Gnfd-Date", "11:10")

	privKey, _, addr := testdata.KeyEthSecp256k1TestPubAddr()

	authInfo := AuthInfo{
		SignType:        AuthV1,
		MetaMaskSignStr: "",
	}

	err = SignRequest(req, privKey, authInfo)
	require.NoError(t, err)

	// server actions
	// (1) get the header, verify header and check data
	authHeader := req.Header.Get(HTTPHeaderAuthorization)
	if authHeader == "" {
		t.Errorf("authorization header should not be empty")
	}

	if !strings.Contains(authHeader, AuthV1) {
		t.Errorf("auth type error")
	}

	// get stringTosign
	signStrIndex := strings.Index(authHeader, " SignedMsg=")
	index := len(" SignedMsg=") + signStrIndex

	// get Siganture
	signatureIndex := strings.Index(authHeader, "Signature=")
	signStr := authHeader[index : signatureIndex-2]

	signature := authHeader[len("Signature=")+signatureIndex:]
	sigBytes, err := hex.DecodeString(signature)
	require.NoError(t, err)

	// (2) server get sender addr
	signMsg := GetMsgToSign(req)
	if hex.EncodeToString(signMsg) != signStr {
		t.Errorf("string to sign not same")
	}

	recoverAddr, pk, err := RecoverAddr(signMsg, sigBytes)

	require.NoError(t, err)

	if !addr.Equals(recoverAddr) {
		t.Errorf("recover addr not same")
	}

	// (3) server verify the signature
	verifySucc := secp256k1.VerifySignature(pk.Bytes(), signMsg, sigBytes[:len(sigBytes)-1])
	if !verifySucc {
		t.Errorf("verify fail")
	}
}
