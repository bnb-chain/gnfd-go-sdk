package client

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	hashlib "github.com/bnb-chain/greenfield-common/go/hash"
	httplib "github.com/bnb-chain/greenfield-common/go/http"
	"github.com/bnb-chain/greenfield-go-sdk/pkg/utils"
	"github.com/bnb-chain/greenfield-go-sdk/types"
	sdkclient "github.com/bnb-chain/greenfield/sdk/client"
	gnfdSdkTypes "github.com/bnb-chain/greenfield/sdk/types"
	permTypes "github.com/bnb-chain/greenfield/x/permission/types"
	storageTypes "github.com/bnb-chain/greenfield/x/storage/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
)

type Client interface {
	Basic
	Bucket
	Object
	Group
	Challenge
	Account
	Payment
	SP
	Proposal
	Validator
	Distribution
	CrossChain
	FeeGrant

	GetDefaultAccount() (*types.Account, error)
	SetDefaultAccount(account *types.Account)
	EnableTrace(outputStream io.Writer, onlyTraceErr bool)
}

// client represents a Greenfield SDK client that can interact with the blockchain
// using the REST API, gRPC, or WebSocket endpoints.
type client struct {
	// The chain client is used to interact with the blockchain
	chainClient *sdkclient.GreenfieldClient
	// The HTTP client is used to send HTTP requests to the greenfield blockchain and sp
	httpClient *http.Client
	// Service provider endpoints
	spEndpoints map[string]*url.URL
	// The default account to use when sending transactions.
	defaultAccount *types.Account
	// Whether the connection to the blockchain node is secure (HTTPS) or not (HTTP).
	secure bool
	// Host is the target sp server hostname，it is the host info in the request which sent to SP
	host string
	// The user agent info
	userAgent string
	// define if trace the error request to SP
	isTraceEnabled bool
	traceOutput    io.Writer
	onlyTraceError bool
}

// Option is a configuration struct used to provide optional parameters to the client constructor.
type Option struct {
	// GrpcDialOption is the list of gRPC dial options used to configure the connection to the blockchain node.
	GrpcDialOption grpc.DialOption
	// account used to set the default account of client
	DefaultAccount *types.Account
	// Secure is a flag that specifies whether the client should use HTTPS or not.
	Secure bool
	// Transport is the HTTP transport used to send requests to the storage provider endpoint.
	Transport http.RoundTripper
	// Host is the target sp server hostname
	Host string
}

// New - instantiate greenfield chain with chain info, account info and options.
// endpoint indicates the rpc address of greenfield
func New(chainID string, endpoint string, option Option) (Client, error) {
	if endpoint == "" || chainID == "" {
		return nil, errors.New("fail to get grpcAddress and chainID to construct client")
	}
	cc, err := sdkclient.NewGreenfieldClient(endpoint, chainID)
	if err != nil {
		return nil, err
	}
	if option.DefaultAccount != nil {
		cc.SetKeyManager(option.DefaultAccount.GetKeyManager())
	}

	c := client{
		chainClient:    cc,
		httpClient:     &http.Client{Transport: option.Transport},
		userAgent:      types.UserAgent,
		defaultAccount: option.DefaultAccount, // it allows to be nil
		secure:         option.Secure,
		host:           option.Host,
	}

	// fetch sp endpoints info from chain
	spInfo, err := c.getSPUrlList()
	if err != nil {
		return nil, err
	}

	c.spEndpoints = spInfo
	return &c, nil
}

// EnableTrace support trace error info the request and the response
func (c *client) EnableTrace(output io.Writer, onlyTraceErr bool) {
	if output == nil {
		output = os.Stdout
	}

	c.onlyTraceError = onlyTraceErr

	c.traceOutput = output
	c.isTraceEnabled = true
}

// getSPUrlByBucket route url of the sp from bucket name
func (c *client) getSPUrlByBucket(bucketName string) (*url.URL, error) {
	ctx := context.Background()
	bucketInfo, err := c.HeadBucket(ctx, bucketName)
	if err != nil {
		return nil, err
	}

	primarySP := bucketInfo.GetPrimarySpAddress()
	if _, ok := c.spEndpoints[primarySP]; ok {
		return c.spEndpoints[primarySP], nil
	}
	// query sp info from chain
	newSpInfo, err := c.getSPUrlList()
	if err != nil {
		return nil, err
	}

	if _, ok := newSpInfo[primarySP]; ok {
		c.spEndpoints = newSpInfo
		return newSpInfo[primarySP], nil
	}

	return nil, fmt.Errorf("the SP endpoint %s not exists on chain", primarySP)
}

// getSPUrlByAddr route url of the sp from sp address
func (c *client) getSPUrlByAddr(address string) (*url.URL, error) {
	if _, ok := c.spEndpoints[address]; ok {
		return c.spEndpoints[address], nil
	}
	// query sp info from chain
	newSpInfo, err := c.getSPUrlList()
	if err != nil {
		return nil, err
	}

	if _, ok := newSpInfo[address]; ok {
		c.spEndpoints = newSpInfo
		return newSpInfo[address], nil
	}

	return nil, fmt.Errorf("the SP endpoint %s not exists on chain", address)
}

// getInServiceSP return the first SP endpoint which is in service in SP list
func (c *client) getInServiceSP() (*url.URL, error) {
	ctx := context.Background()
	spList, err := c.ListStorageProviders(ctx, true)
	if err != nil {
		return nil, err
	}

	if len(spList) == 0 {
		return nil, errors.New("fail to get SP endpoint")
	}

	var useHttps bool
	SPEndpoint := spList[0].Endpoint
	if strings.Contains(SPEndpoint, "https") {
		useHttps = true
	} else {
		useHttps = c.secure
	}

	urlInfo, urlErr := utils.GetEndpointURL(spList[0].Endpoint, useHttps)
	if urlErr != nil {
		return nil, urlErr
	}

	return urlInfo, nil
}

// requestMeta - contains the metadata to construct the http request.
type requestMeta struct {
	bucketName       string
	objectName       string
	urlRelPath       string     // relative path of url
	urlValues        url.Values // url values to be added into url
	rangeInfo        string
	txnMsg           string
	contentType      string
	contentLength    int64
	contentMD5Base64 string // base64 encoded md5sum
	contentSHA256    string // hex encoded sha256sum
	pieceInfo        types.QueryPieceInfo
	userAddress      string
}

// SendOptions -  options to use to send the http message
type sendOptions struct {
	method           string      // request method
	body             interface{} // request body
	disableCloseBody bool        // indicate whether to disable automatic calls to resp.Body.Close()
	txnHash          string      // the transaction hash info
	isAdminApi       bool        // indicate if it is an admin api request
}

// newRequest constructs the http request, set url, body and headers
func (c *client) newRequest(ctx context.Context, method string, meta requestMeta,
	body interface{}, txnHash string, isAdminAPi bool, endpoint *url.URL,
) (req *http.Request, err error) {
	isVirtualHost := c.isVirtualHostStyleUrl(*endpoint, meta.bucketName)
	// construct the target url
	desURL, err := c.generateURL(meta.bucketName, meta.objectName, meta.urlRelPath,
		meta.urlValues, isAdminAPi, endpoint, isVirtualHost)
	if err != nil {
		log.Error().Msg(fmt.Sprintf("generate request url on SP: %s fail, err: %s", endpoint.String(), err))
		return nil, err
	}

	var reader io.Reader
	contentType := ""
	sha256Hex := ""
	if body != nil {
		// the body content is io.Reader type
		if ObjectReader, ok := body.(io.Reader); ok {
			reader = ObjectReader
			if meta.contentType == "" {
				contentType = types.ContentDefault
			}
		} else {
			// the body content is xml type
			content, err := xml.Marshal(body)
			if err != nil {
				return nil, err
			}
			contentType = types.ContentTypeXML
			reader = bytes.NewReader(content)
			sha256Hex = utils.CalcSHA256Hex(content)
		}
	}

	// Initialize a new HTTP request for the method.
	req, err = http.NewRequestWithContext(ctx, method, desURL.String(), nil)
	if err != nil {
		return nil, err
	}

	// need to turn the body into ReadCloser
	if body == nil {
		req.Body = nil
	} else {
		req.Body = io.NopCloser(reader)
	}

	// set content length
	req.ContentLength = meta.contentLength

	// set txn hash header
	if txnHash != "" {
		req.Header.Set(types.HTTPHeaderTransactionHash, txnHash)
	}

	// set content type header
	if meta.contentType != "" {
		req.Header.Set(types.HTTPHeaderContentType, meta.contentType)
	} else if contentType != "" {
		req.Header.Set(types.HTTPHeaderContentType, contentType)
	} else {
		req.Header.Set(types.HTTPHeaderContentType, types.ContentDefault)
	}

	// set md5 header
	if meta.contentMD5Base64 != "" {
		req.Header[types.HTTPHeaderContentMD5] = []string{meta.contentMD5Base64}
	}

	// set sha256 header
	if meta.contentSHA256 != "" {
		req.Header[types.HTTPHeaderContentSHA256] = []string{meta.contentSHA256}
	} else {
		req.Header[types.HTTPHeaderContentSHA256] = []string{sha256Hex}
	}

	if meta.rangeInfo != "" && method == http.MethodGet {
		req.Header.Set(types.HTTPHeaderRange, meta.rangeInfo)
	}

	// if pieceInfo.ObjectId is not empty, other field should be set as well
	if meta.pieceInfo.ObjectId != "" {
		info := meta.pieceInfo
		req.Header.Set(types.HTTPHeaderObjectId, info.ObjectId)
		req.Header.Set(types.HTTPHeaderRedundancyIndex, strconv.Itoa(info.RedundancyIndex))
		req.Header.Set(types.HTTPHeaderPieceIndex, strconv.Itoa(info.PieceIndex))
	}

	if isAdminAPi {
		if meta.txnMsg != "" {
			req.Header.Set(types.HTTPHeaderUnsignedMsg, meta.txnMsg)
		}
	} else {
		// set request host
		if c.host != "" {
			req.Host = c.host
		} else if req.URL.Host != "" {
			req.Host = req.URL.Host
		}
	}

	if meta.userAddress != "" {
		req.Header.Set(types.HTTPHeaderUserAddress, meta.userAddress)
	}

	// set date header
	stNow := time.Now().UTC()
	req.Header.Set(types.HTTPHeaderDate, stNow.Format(types.Iso8601DateFormatSecond))

	// set user-agent
	req.Header.Set(types.HTTPHeaderUserAgent, c.userAgent)

	// sign the total http request info when auth type v1
	err = c.signRequest(req)
	if err != nil {
		return req, err
	}

	return
}

// doAPI call client.Do() to send request and read response from servers
func (c *client) doAPI(ctx context.Context, req *http.Request, meta requestMeta, closeBody bool) (*http.Response, error) {
	var cancel context.CancelFunc
	if closeBody {
		ctx, cancel = context.WithCancel(ctx)
		defer cancel()
	}
	req = req.WithContext(ctx)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		// If we got an error, and the context has been canceled,
		// the context's error is probably more useful.
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		if urlErr, ok := err.(*url.Error); ok {
			if strings.Contains(urlErr.Err.Error(), "EOF") {
				return nil, &url.Error{
					Op:  urlErr.Op,
					URL: urlErr.URL,
					Err: errors.New("Connection closed by foreign host " + urlErr.URL + ". Retry again."),
				}
			}
		}
		return nil, err
	}
	defer func() {
		if closeBody {
			utils.CloseResponse(resp)
		}
	}()

	// construct err responses and messages
	err = types.ConstructErrResponse(resp, meta.bucketName, meta.objectName)
	if err != nil {
		// dump error msg
		if c.isTraceEnabled {
			c.dumpSPMsg(req, resp)
		}
		return resp, err
	}

	// dump msg
	if c.isTraceEnabled && !c.onlyTraceError {
		c.dumpSPMsg(req, resp)
	}

	return resp, nil
}

// sendReq sends the message via REST and handles the response
func (c *client) sendReq(ctx context.Context, metadata requestMeta, opt *sendOptions, endpoint *url.URL) (res *http.Response, err error) {
	req, err := c.newRequest(ctx, opt.method, metadata, opt.body, opt.txnHash, opt.isAdminApi, endpoint)
	if err != nil {
		return nil, err
	}

	resp, err := c.doAPI(ctx, req, metadata, !opt.disableCloseBody)
	if err != nil {
		log.Error().Msg(fmt.Sprintf("do API error, url: %s, err: %s", req.URL.String(), err))
		return nil, err
	}
	return resp, nil
}

// generateURL constructs the target request url based on the parameters
func (c *client) generateURL(bucketName string, objectName string, relativePath string,
	queryValues url.Values, isAdminApi bool, endpoint *url.URL, isVirtualHost bool,
) (*url.URL, error) {
	host := endpoint.Host
	scheme := endpoint.Scheme

	// Strip port 80 and 443
	if h, p, err := net.SplitHostPort(host); err == nil {
		if scheme == "http" && p == "80" || scheme == "https" && p == "443" {
			host = h
			if ip := net.ParseIP(h); ip != nil && ip.To16() != nil {
				host = "[" + h + "]"
			}
		}
	}

	var urlStr string
	if isAdminApi {
		prefix := types.AdminURLPrefix + types.AdminURLVersion
		urlStr = scheme + "://" + host + prefix + "/"
	} else {
		urlStr = scheme + "://" + host + "/"
		if bucketName != "" {
			if isVirtualHost {
				// set virtual host url
				urlStr = scheme + "://" + bucketName + "." + host + "/"
			} else {
				// set path style url
				urlStr = urlStr + bucketName + "/"
			}

			if objectName != "" {
				urlStr += utils.EncodePath(objectName)
			}
		}
	}

	if relativePath != "" {
		urlStr += utils.EncodePath(relativePath)
	}

	if len(queryValues) > 0 {
		urlStrNew, err := utils.AddQueryValues(urlStr, queryValues)
		if err != nil {
			return nil, err
		}
		urlStr = urlStrNew
	}

	return url.Parse(urlStr)
}

// signRequest signs the request and set authorization before send to server
func (c *client) signRequest(req *http.Request) error {
	unsignedMsg := httplib.GetMsgToSign(req)

	// sign the request header info, generate the signature
	signature, err := c.MustGetDefaultAccount().Sign(unsignedMsg)
	if err != nil {
		return err
	}

	authStr := []string{
		types.AuthV1 + " " + types.SignAlgorithm,
		" SignedMsg=" + hex.EncodeToString(unsignedMsg),
		"Signature=" + hex.EncodeToString(signature),
	}

	// set auth header
	req.Header.Set(types.HTTPHeaderAuthorization, strings.Join(authStr, ", "))

	return nil
}

// returns true if virtual hosted style requests are to be used.
func (c *client) isVirtualHostStyleUrl(url url.URL, bucketName string) bool {
	if bucketName == "" {
		return false
	}
	// if the url is not a valid domain, need to set path-style
	if !utils.IsDomainNameValid(url.Host) {
		return false
	}

	if url.Scheme == "https" && strings.Contains(bucketName, ".") {
		return false
	}

	return true
}

func (c *client) dumpSPMsg(req *http.Request, resp *http.Response) {
	var err error
	defer func() {
		if err != nil {
			log.Error().Msg("dump msg err:" + err.Error())
		}
	}()
	_, err = fmt.Fprintln(c.traceOutput, "---------TRACE REQUEST---------")
	if err != nil {
		return
	}
	// write url info to trace output.
	_, err = fmt.Fprintln(c.traceOutput, req.URL.String())
	if err != nil {
		return
	}

	// dump headers
	reqTrace, err := httputil.DumpRequestOut(req, false)
	if err != nil {
		return
	}

	// write header info to trace output.
	_, err = fmt.Fprint(c.traceOutput, string(reqTrace))
	if err != nil {
		return
	}

	_, err = fmt.Fprintln(c.traceOutput, "---------TRACE RESPONSE---------")
	if err != nil {
		return
	}

	// dump response
	respInfo, err := httputil.DumpResponse(resp, true)
	if err != nil {
		return
	}

	// Write response info to trace output.
	_, err = fmt.Fprint(c.traceOutput, strings.TrimSuffix(string(respInfo), "\r\n"))
	if err != nil {
		return
	}

	_, err = fmt.Fprintln(c.traceOutput, "---------END-STRACE---------")
	if err != nil {
		return
	}
}

// GetPieceHashRoots returns primary pieces, secondary piece Hash roots list and the object size
// It is used for generate meta of object on the chain
func (c *client) GetPieceHashRoots(reader io.Reader, segSize int64,
	dataShards, parityShards int,
) ([]byte, [][]byte, int64, storageTypes.RedundancyType, error) {
	pieceHashRoots, size, redundancyType, err := hashlib.ComputeIntegrityHash(reader, segSize, dataShards, parityShards)
	if err != nil {
		return nil, nil, 0, storageTypes.REDUNDANCY_EC_TYPE, err
	}

	return pieceHashRoots[0], pieceHashRoots[1:], size, redundancyType, nil
}

// sendPutPolicyTxn broadcast the putPolicy msg and return the txn hash
func (c *client) sendPutPolicyTxn(ctx context.Context, msg *storageTypes.MsgPutPolicy, txOpts *gnfdSdkTypes.TxOption) (string, error) {
	if err := msg.ValidateBasic(); err != nil {
		return "", err
	}

	resp, err := c.chainClient.BroadcastTx(ctx, []sdk.Msg{msg}, txOpts)
	if err != nil {
		return "", err
	}

	return resp.TxResponse.TxHash, err
}

// sendDelPolicyTxn broadcast the deletePolicy msg and return the txn hash
func (c *client) sendDelPolicyTxn(ctx context.Context, operator sdk.AccAddress, resource string, principal *permTypes.Principal, txOpts *gnfdSdkTypes.TxOption) (string, error) {
	delPolicyMsg := storageTypes.NewMsgDeletePolicy(operator, resource, principal)

	if err := delPolicyMsg.ValidateBasic(); err != nil {
		return "", err
	}

	resp, err := c.chainClient.BroadcastTx(ctx, []sdk.Msg{delPolicyMsg}, txOpts)
	if err != nil {
		return "", err
	}

	return resp.TxResponse.TxHash, err
}

func (c *client) sendTxn(ctx context.Context, msg sdk.Msg, opt *gnfdSdkTypes.TxOption) (string, error) {
	if err := msg.ValidateBasic(); err != nil {
		return "", err
	}

	resp, err := c.chainClient.BroadcastTx(ctx, []sdk.Msg{msg}, opt)
	if err != nil {
		return "", err
	}
	return resp.TxResponse.TxHash, err
}

// GetDefaultAccount returns the account address of default account in client
func (c *client) GetDefaultAccount() (*types.Account, error) {
	if c.MustGetDefaultAccount() == nil {
		return nil, types.ErrorDefaultAccountNotExist
	}
	return c.MustGetDefaultAccount(), nil
}

// SetDefaultAccount will set the default account
func (c *client) SetDefaultAccount(account *types.Account) {
	c.defaultAccount = account
	c.chainClient.SetKeyManager(account.GetKeyManager())
}

func (c *client) MustGetDefaultAccount() *types.Account {
	if c.defaultAccount == nil {
		panic("Default account not exist, Use SetDefaultAccount to set ")
	}
	return c.defaultAccount
}
