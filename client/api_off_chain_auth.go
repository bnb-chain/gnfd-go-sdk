package client

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/blake2b"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/rs/zerolog/log"

	httplib "github.com/bnb-chain/greenfield-common/go/http"
	"github.com/bnb-chain/greenfield-go-sdk/types"
)

// IAuthClient - Client APIs for register Greenfield off chain auth keys and make signatures.
type IAuthClient interface {
	RegisterEDDSAPublicKey(spAddress string, spEndpoint string) (string, error)
	GetNextNonce(spEndpoint string) (string, error)
	OffChainAuthSign(unsignedBytes []byte) string

	RegisterEDDSAPublicKeyV2(spEndpoint string) (string, error)
	OffChainAuthSignV2(unsignedBytes []byte) string

	ListUserPublicKeyV2(spEndpoint string, domain string) ([]string, error)
	DeleteUserPublicKeyV2(spEndpoint string, domain string, publicKeys []string) (bool, error)
}

// OffChainAuthSign - Generate EdDSA private key according to a preconfigured seed and then make the signature for given input.
//
// - unsignedBytes: The content which needs to be signed by client's EdDSA private key
//
// - ret1: The signature made by EdDSA private key of the Client.
func (c *Client) OffChainAuthSign(unsignedBytes []byte) string {
	sk, _ := generateEddsaPrivateKey(c.offChainAuthOption.Seed)
	hFunc := mimc.NewMiMC()
	sig, _ := sk.Sign(unsignedBytes, hFunc)
	authString := fmt.Sprintf("%s,Signature=%v", httplib.Gnfd1Eddsa, hex.EncodeToString(sig))
	return authString
}

// OffChainAuthSignV2 - Generate EdDSA private key according to a preconfigured seed and then make the signature for given input.
// OffChainAuthSignV2 use ed25519 curve.
//
// - unsignedBytes: The content which needs to be signed by client's EdDSA private key
//
// - ret1: The signature made by EdDSA private key of the Client.
func (c *Client) OffChainAuthSignV2(unsignedBytes []byte) string {
	sk, _ := GetEd25519PrivateKeyAndPublicKey(c.offChainAuthOptionV2.Seed)
	// Sign the message using the private key
	sig := ed25519.Sign(sk, unsignedBytes)
	authString := fmt.Sprintf("%s,Signature=%v", httplib.Gnfd2Eddsa, hex.EncodeToString(sig))
	return authString
}

// requestNonceResp is the structure for off chain auth nonce response.
type requestNonceResp struct {
	CurrentNonce     int32  `xml:"CurrentNonce"`
	NextNonce        int32  `xml:"NextNonce"`
	CurrentPublicKey string `xml:"CurrentPublicKey"`
	ExpiryDate       int64  `xml:"ExpiryDate"`
}

// ListUserPublicKeyV2Resp is the structure for off chain auth v2 ListUserPublicKeyV2 response.
type ListUserPublicKeyV2Resp struct {
	PublicKeys []string `xml:"Result"`
}

// DeleteUserPublicKeyV2Resp is the structure for off chain auth v2 DeleteUserPublicKeyV2 response.
type DeleteUserPublicKeyV2Resp struct {
	Result bool `xml:"Result"`
}

// GetNextNonce - Get the nonce value by giving user account and domain.
//
// - spEndpoint: The sp endpoint where the client means to get the next nonce
//
// - ret1: The next nonce value for the Client if it needs to register a new EdDSA public key
//
// - ret2: Return error when getting next nonce failed, otherwise return nil.
func (c *Client) GetNextNonce(spEndpoint string) (string, error) {
	header := make(map[string]string)
	header["X-Gnfd-User-Address"] = c.defaultAccount.GetAddress().String()
	header["X-Gnfd-App-Domain"] = c.offChainAuthOption.Domain

	response, err := httpGetWithHeader(spEndpoint+"/auth/request_nonce", header)
	if err != nil {
		return "0", err
	}
	authNonce := requestNonceResp{}
	// decode the xml content from response body
	err = xml.NewDecoder(bytes.NewBufferString(response)).Decode(&authNonce)
	if err != nil {
		return "0", err
	}
	return strconv.Itoa(int(authNonce.NextNonce)), nil
}

const (
	unsignedContentTemplate string = `%s wants you to sign in with your BNB Greenfield account:
%s

Register your identity public key %s

URI: %s
Version: 1
Chain ID: 5600
Issued At: %s
Expiration Time: %s
Resources:
- SP %s (name: SP_001) with nonce: %s`

	unsignedContentTemplateV2 string = `%s wants you to sign in with your BNB Greenfield account:
%s

Register your identity public key %s

URI: %s
Version: 1
Chain ID: 5600
Issued At: %s
Expiration Time: %s`
)

// RegisterEDDSAPublicKey - Register EdDSA public key of this client for the given sp address and spEndpoint.
//
// To enable EdDSA authentication, you need to config OffChainAuthOption for the client.
// The overall register process could be referred to https://github.com/bnb-chain/greenfield-storage-provider/blob/master/docs/modules/authenticator.md#workflow.
//
// The EdDSA registering process is typically used in a website, e.g. https://dcellar.io,
// which obtains a user's signature via a wallet and then posts the user's EdDSA public key to a sp.
//
// Here we also provide an SDK method to implement this process, because sometimes you might want to test if a given SP provides correct EdDSA authentication or not.
// It also helps if you want implement it on a non-browser environment.
//
// - spAddress: The sp operator address, to which this API will register client's EdDSA public key. It can be found via https://greenfield-chain.bnbchain.org/openapi#/Query/StorageProviders .
//
// - spEndpoint: The sp endpoint, to which this API will register client's EdDSA public key. It can be found via https://greenfield-chain.bnbchain.org/openapi#/Query/StorageProviders .
//
// - ret1: The register result when invoking SP UpdateUserPublicKey API.
//
// - ret2: Return error when registering failed, otherwise return nil.
func (c *Client) RegisterEDDSAPublicKey(spAddress string, spEndpoint string) (string, error) {
	appDomain := c.offChainAuthOption.Domain
	eddsaSeed := c.offChainAuthOption.Seed
	nextNonce, err := c.GetNextNonce(spEndpoint)
	if err != nil {
		return "", err
	}
	// get the EDDSA private and public key
	userEddsaPublicKeyStr := getEddsaCompressedPublicKey(eddsaSeed)
	log.Info().Msg("userEddsaPublicKeyStr is " + userEddsaPublicKeyStr)

	IssueDate := time.Now().Format(time.RFC3339)
	// ExpiryDate format := "2023-06-27T06:35:24Z"
	ExpiryDate := time.Now().Add(time.Hour * 24).Format(time.RFC3339)

	unSignedContent := fmt.Sprintf(unsignedContentTemplate, appDomain, c.defaultAccount.GetAddress().String(), userEddsaPublicKeyStr, appDomain, IssueDate, ExpiryDate, spAddress, nextNonce)

	unSignedContentHash := accounts.TextHash([]byte(unSignedContent))
	sig, _ := c.defaultAccount.GetKeyManager().Sign(unSignedContentHash)
	authString := fmt.Sprintf("%s,SignedMsg=%s,Signature=%s", httplib.Gnfd1EthPersonalSign, unSignedContent, hexutil.Encode(sig))
	authString = strings.ReplaceAll(authString, "\n", "\\n")
	headers := make(map[string]string)
	headers["x-gnfd-app-domain"] = appDomain
	headers["x-gnfd-app-reg-nonce"] = nextNonce
	headers["x-gnfd-app-reg-public-key"] = userEddsaPublicKeyStr
	headers["X-Gnfd-Expiry-Timestamp"] = ExpiryDate
	headers["authorization"] = authString
	headers["origin"] = appDomain
	headers["x-gnfd-user-address"] = c.defaultAccount.GetAddress().String()
	jsonResult, error1 := httpPostWithHeader(spEndpoint+"/auth/update_key", "{}", headers)

	return jsonResult, error1
}

// RegisterEDDSAPublicKeyV2 - Register EdDSA public key of this client for the given sp address and spEndpoint.
//
// To enable EdDSA authentication, you need to config OffChainAuthOptionV2 for the client.
// The overall register process could be referred to https://github.com/bnb-chain/greenfield-storage-provider/blob/master/docs/modules/authenticator.md#workflow.
//
// The EdDSA registering process is typically used in a website, e.g. https://dcellar.io,
// which obtains a user's signature via a wallet and then posts the user's EdDSA public key to a sp.
//
// Here we also provide an SDK method to implement this process, because sometimes you might want to test if a given SP provides correct EdDSA authentication or not.
// It also helps if you want implement it on a non-browser environment.
//
// - spEndpoint: The sp endpoint, to which this API will register client's EdDSA public key. It can be found via https://greenfield-chain.bnbchain.org/openapi#/Query/StorageProviders .
//
// - ret1: The register result when invoking SP UpdateUserPublicKey API.
//
// - ret2: Return error when registering failed, otherwise return nil.
func (c *Client) RegisterEDDSAPublicKeyV2(spEndpoint string) (string, error) {
	appDomain := c.offChainAuthOptionV2.Domain
	eddsaSeed := c.offChainAuthOptionV2.Seed

	// get the EDDSA private and public key
	_, userEddsaPublicKey := GetEd25519PrivateKeyAndPublicKey(eddsaSeed)
	userEddsaPublicKeyStr := hex.EncodeToString(userEddsaPublicKey)
	log.Info().Msg("userEddsaPublicKeyStr is " + userEddsaPublicKeyStr)

	IssueDate := time.Now().Format(time.RFC3339)
	// ExpiryDate format := "2023-06-27T06:35:24Z"
	ExpiryDate := time.Now().Add(time.Hour * 24).Format(time.RFC3339)

	unSignedContent := fmt.Sprintf(unsignedContentTemplateV2, appDomain, c.defaultAccount.GetAddress().String(), userEddsaPublicKeyStr, appDomain, IssueDate, ExpiryDate)

	unSignedContentHash := accounts.TextHash([]byte(unSignedContent))
	sig, _ := c.defaultAccount.GetKeyManager().Sign(unSignedContentHash)
	authString := fmt.Sprintf("%s,SignedMsg=%s,Signature=%s", httplib.Gnfd1EthPersonalSign, unSignedContent, hexutil.Encode(sig))
	authString = strings.ReplaceAll(authString, "\n", "\\n")
	headers := make(map[string]string)
	headers["x-gnfd-app-domain"] = appDomain
	headers["x-gnfd-app-reg-public-key"] = userEddsaPublicKeyStr
	headers["X-Gnfd-Expiry-Timestamp"] = ExpiryDate
	headers["authorization"] = authString
	headers["origin"] = appDomain
	headers["x-gnfd-user-address"] = c.defaultAccount.GetAddress().String()
	jsonResult, error1 := httpPostWithHeader(spEndpoint+"/auth/update_key_v2", "{}", headers)

	return jsonResult, error1
}

// ListUserPublicKeyV2 - List user public keys for off-chain-auth v2
// This API will list user public keys for off-chain-auth v2. So that users/dapp can know what public keys have already been registered in a given sp.
//
// - spEndpoint: The sp endpoint where the list API will send the request.
//
// - domain: The domain that this list api will query for.
//
// - ret1: The public key list for the given sp/account/domain. The account will be the client's defaultAccount.
//
// - ret2: Return error when ListUserPublicKeyV2 runs into failure.
func (c *Client) ListUserPublicKeyV2(spEndpoint string, domain string) ([]string, error) {
	header := make(map[string]string)
	header["X-Gnfd-User-Address"] = c.defaultAccount.GetAddress().String()
	header["X-Gnfd-App-Domain"] = domain

	response, err := httpGetWithHeader(spEndpoint+"/auth/keys_v2", header)
	if err != nil {
		return nil, err
	}
	listResp := ListUserPublicKeyV2Resp{}
	// decode the xml content from response body
	err = xml.NewDecoder(bytes.NewBufferString(response)).Decode(&listResp)
	if err != nil {
		return nil, err
	}
	return listResp.PublicKeys, nil
}

// DeleteUserPublicKeyV2 - Delete user public keys for off-chain-auth v2
// This API will delete user public keys for off-chain-auth v2.
//
// - spEndpoint: The sp endpoint where the delete API will send the request.
//
// - domain: The domain that this api will delete for.
//
// - publicKeys: The public keys that the invoker intends to delete
//
// - ret1: Return deletion result.
//
// - ret2: Return error when DeleteUserPublicKeyV2 runs into failure.
func (c *Client) DeleteUserPublicKeyV2(spEndpoint string, domain string, publicKeys []string) (bool, error) {
	header := make(map[string]string)
	header["X-Gnfd-User-Address"] = c.defaultAccount.GetAddress().String()
	header["X-Gnfd-App-Domain"] = domain
	stNow := time.Now().UTC()
	header[httplib.HTTPHeaderExpiryTimestamp] = stNow.Add(time.Second * types.DefaultExpireSeconds).Format(types.Iso8601DateFormatSecond)
	req, err := http.NewRequest(http.MethodPost, spEndpoint+"/auth/delete_keys_v2", strings.NewReader(strings.Join(publicKeys, ",")))
	if err != nil {
		return false, err
	}
	for key, value := range header {
		req.Header.Set(key, value)
	}
	// sign the total http request info when auth type v1
	err = c.signRequest(req)
	if err != nil {
		return false, err
	}

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	if (nil != resp) && (nil != resp.Body) {
		defer resp.Body.Close()
	}
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return false, err
	}
	deleteResp := DeleteUserPublicKeyV2Resp{}
	// decode the xml content from response body
	err = xml.NewDecoder(bytes.NewBufferString(string(body))).Decode(&deleteResp)
	if err != nil {
		return false, err
	}
	return deleteResp.Result, nil
}

func httpGetWithHeader(url string, header map[string]string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	for key, value := range header {
		req.Header.Set(key, value)
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	if (nil != resp) && (nil != resp.Body) {
		defer resp.Body.Close()
	}
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return "", err
	}
	return string(body), err
}

func httpPostWithHeader(url string, jsonStr string, header map[string]string) (string, error) {
	json := []byte(jsonStr)
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(json))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	for key, value := range header {
		req.Header.Set(key, value)
	}
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	if (nil != resp) && (nil != resp.Body) {
		defer resp.Body.Close()
	}
	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return "", readErr
	}
	return string(body), err
}

func getEddsaCompressedPublicKey(seed string) string {
	sk, err := generateEddsaPrivateKey(seed)
	if err != nil {
		return err.Error()
	}
	var buf bytes.Buffer
	buf.Write(sk.PublicKey.Bytes())
	return hex.EncodeToString(buf.Bytes())
}

// generateEddsaPrivateKey: generate eddsa private key
func generateEddsaPrivateKey(seed string) (sk *eddsa.PrivateKey, err error) {
	buf := make([]byte, 32)
	copy(buf, seed)
	reader := bytes.NewReader(buf)
	sk, err = generateKey(reader)
	return sk, err
}

func GetEd25519PrivateKeyAndPublicKey(seed string) (ed25519.PrivateKey, ed25519.PublicKey) {
	// Hash the seed to obtain a 32-byte value
	hashedSeed := sha256.Sum256([]byte(seed))
	// Derive the private key from the seed
	privateKey := ed25519.NewKeyFromSeed(hashedSeed[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)

	return privateKey, publicKey
}

const (
	sizeFr = fr.Bytes
)

func generateKey(r io.Reader) (*eddsa.PrivateKey, error) {
	//c := twistededwards.GetEdwardsCurve()

	var (
		randSrc = make([]byte, 32)
		scalar  = make([]byte, 32)
		pub     eddsa.PublicKey
	)

	// hash(h) = private_key || random_source, on 32 bytes each
	seed := make([]byte, 32)
	_, err := r.Read(seed)
	if err != nil {
		return nil, err
	}
	h := blake2b.Sum512(seed[:])
	for i := 0; i < 32; i++ {
		randSrc[i] = h[i+32]
	}

	// prune the key
	// https://tools.ietf.org/html/rfc8032#section-5.1.5, key generation

	h[0] &= 0xF8
	h[31] &= 0x7F
	h[31] |= 0x40

	// 0xFC = 1111 1100
	// convert 256 bits to 254 bits supporting bn254 curve

	h[31] &= 0xFC

	// reverse first bytes because setBytes interpret stream as big endian
	// but in eddsa specs s is the first 32 bytes in little endian
	for i, j := 0, sizeFr-1; i < sizeFr; i, j = i+1, j-1 {
		scalar[i] = h[j]
	}

	a := new(big.Int).SetBytes(scalar[:])
	for i := 253; i < 256; i++ {
		a.SetBit(a, i, 0)
	}

	copy(scalar[:], a.FillBytes(make([]byte, 32)))

	var bscalar big.Int
	bscalar.SetBytes(scalar[:])
	//pub.A.ScalarMul(&c.Base, &bscalar)

	var res [sizeFr * 3]byte
	pubkBin := pub.A.Bytes()
	subtle.ConstantTimeCopy(1, res[:sizeFr], pubkBin[:])
	subtle.ConstantTimeCopy(1, res[sizeFr:2*sizeFr], scalar[:])
	subtle.ConstantTimeCopy(1, res[2*sizeFr:], randSrc[:])

	sk := &eddsa.PrivateKey{}
	// make sure sk is not nil

	_, err = sk.SetBytes(res[:])

	return sk, err
}
