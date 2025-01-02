package client

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"

	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/rs/zerolog/log"

	hashlib "github.com/bnb-chain/greenfield-common/go/hash"
	httplib "github.com/bnb-chain/greenfield-common/go/http"
	"github.com/bnb-chain/greenfield-go-sdk/pkg/utils"
	"github.com/bnb-chain/greenfield-go-sdk/types"
	sdkclient "github.com/bnb-chain/greenfield/sdk/client"
	gnfdSdkTypes "github.com/bnb-chain/greenfield/sdk/types"
	permTypes "github.com/bnb-chain/greenfield/x/permission/types"
	storageTypes "github.com/bnb-chain/greenfield/x/storage/types"
	types2 "github.com/bnb-chain/greenfield/x/virtualgroup/types"
)

// IClient - Declare all Greenfield SDK Client APIs, including APIs for interacting with Greenfield Blockchain and SPs.
type IClient interface {
	IBasicClient
	IBucketClient
	IObjectClient
	IGroupClient
	IChallengeClient
	IAccountClient
	IPaymentClient
	ISPClient
	IProposalClient
	IValidatorClient
	IDistributionClient
	ICrossChainClient
	IFeeGrantClient
	IVirtualGroupClient
	IAuthClient
}

// Client - The implementation for IClient, implement all Client APIs for Greenfield SDK.
type Client struct {
	// The chain Client is used to interact with the blockchain
	chainClient *sdkclient.GreenfieldClient
	// The HTTP Client is used to send HTTP requests to the greenfield blockchain and sp
	httpClient *http.Client
	// Service provider endpoints
	storageProviders map[uint32]*types.StorageProvider
	// The default account to use when sending transactions.
	defaultAccount *types.Account
	// Whether the connection to the blockchain node is secure (HTTPS) or not (HTTP).
	secure bool
	// Host is the target sp server hostname，it is the host info in the request which sent to SP
	host string
	// The user agent info
	userAgent string
	// define if trace the error request to SP
	isTraceEnabled       bool
	traceOutput          io.Writer
	onlyTraceError       bool
	offChainAuthOption   *OffChainAuthOption
	offChainAuthOptionV2 *OffChainAuthOptionV2
	useWebsocketConn     bool
	expireSeconds        uint64
	// forceToUseSpecifiedSpEndpointForDownloadOnly indicates a fixed SP endpoint to which to send the download request
	// If this option is set, the client can only make download requests, and can only download from the fixed endpoint
	forceToUseSpecifiedSpEndpointForDownloadOnly *url.URL
}

// Option - Configurations for providing optional parameters for the Greenfield SDK Client.
type Option struct {
	// GrpcDialOption is the list of gRPC dial options used to configure the connection to the blockchain node.
	GrpcDialOption grpc.DialOption
	// DefaultAccount is the default account of Client.
	DefaultAccount *types.Account
	// Secure is a flag that specifies whether the Client should use HTTPS or not.
	Secure bool
	// Transport is the HTTP transport used to send requests to the storage provider endpoint.
	Transport http.RoundTripper
	// Host is the target sp server hostname.
	Host string
	// OffChainAuthOption consists of a EdDSA private key and the domain where the EdDSA keys will be registered for.
	//
	// This property should not be set in most cases unless you want to use go-sdk to test if the SP support off-chain-auth feature.
	// Once this property is set, the request will be signed in "GNFD1-EDDSA" way rather than GNFD1-ECDSA.
	OffChainAuthOption *OffChainAuthOption
	// OffChainAuthOptionV2 consists of a EdDSA private key and the domain where the EdDSA keys will be registered for.
	// It uses ed25519 curve.
	// This property should not be set in most cases unless you want to use go-sdk to test if the SP support off-chain-auth-v2 feature.
	// Once this property is set, the request will be signed in "GNFD2-EDDSA" way rather than GNFD2-ECDSA.
	OffChainAuthOptionV2 *OffChainAuthOptionV2
	// UseWebSocketConn specifies that connection to Chain is via websocket.
	UseWebSocketConn bool
	// ExpireSeconds indicates the number of seconds after which the authentication of the request sent to the SP will become invalid，the default value is 1000.
	ExpireSeconds uint64
	// ForceToUseSpecifiedSpEndpointForDownloadOnly indicates a fixed SP endpoint to which to send the download request
	// If this option is set, the client can only make download requests, and can only download from the fixed endpoint
	ForceToUseSpecifiedSpEndpointForDownloadOnly string
}

// OffChainAuthOption - The optional configurations for off-chain-auth.
//
// The OffChainAuthOption consists of a EdDSA private key and the domain where the EdDSA keys will be registered for.
//
// This auth mechanism is usually used in browser-based application.
// That we support OffChainAuth configuration in go-sdk is to make the tests on off-chain-auth be convenient.
type OffChainAuthOption struct {
	// Seed is a EdDSA private key used for off-chain-auth.
	Seed string
	// Domain is the domain where the EdDSA keys will be registered for.
	Domain string
	// ShouldRegisterPubKey This should be set as true for the first time and could be set as false if the pubkey have been already been registered already.
	ShouldRegisterPubKey bool
}

// OffChainAuthOptionV2 - The optional configurations for off-chain-auth-v2.
//
// The OffChainAuthOptionV2 consists of a EdDSA private key and the domain where the EdDSA keys will be registered for.
//
// This auth mechanism is usually used in browser-based application.
// That we support OffChainAuth configuration in go-sdk is to make the tests on off-chain-auth-v2 be convenient.
type OffChainAuthOptionV2 struct {
	// Seed is a EdDSA private key used for off-chain-auth.
	Seed string
	// Domain is the domain where the EdDSA keys will be registered for.
	Domain string
	// ShouldRegisterPubKey This should be set as true for the first time and could be set as false if the pubkey have been already been registered already.
	ShouldRegisterPubKey bool
	// PublicKey This will be set automatically once the public key is registered.
	PublicKey string
}

// New - New Greenfield Go SDK Client.
//
// - chainID: The Greenfield Blockchain's chainID that the Client would interact with.
//
// - endpoint: The Greenfield Blockchain's RPC URL that the Client would interact with.
//
// - option: The optional configurations for the Client.
//
// - ret1: The new client that created, in IClient format.
//
// - ret2: Return error when new Client failed, otherwise return nil.
func New(chainID string, endpoint string, option Option) (IClient, error) {
	if endpoint == "" || chainID == "" {
		return nil, errors.New("fail to get grpcAddress and chainID to construct Client")
	}
	var (
		cc  *sdkclient.GreenfieldClient
		err error
	)
	if option.UseWebSocketConn {
		cc, err = sdkclient.NewGreenfieldClient(endpoint, chainID, sdkclient.WithWebSocketClient())
	} else {
		cc, err = sdkclient.NewGreenfieldClient(endpoint, chainID)
	}
	if err != nil {
		return nil, err
	}
	if option.DefaultAccount != nil {
		cc.SetKeyManager(option.DefaultAccount.GetKeyManager())
	}

	if option.ExpireSeconds > httplib.MaxExpiryAgeInSec {
		return nil, errors.New("the configured expire time exceeds max expire time")
	}

	c := Client{
		chainClient:      cc,
		httpClient:       &http.Client{Transport: option.Transport},
		userAgent:        types.UserAgent,
		defaultAccount:   option.DefaultAccount, // it allows to be nil
		secure:           option.Secure,
		host:             option.Host,
		storageProviders: make(map[uint32]*types.StorageProvider),
		useWebsocketConn: option.UseWebSocketConn,
		expireSeconds:    option.ExpireSeconds,
	}

	if option.ForceToUseSpecifiedSpEndpointForDownloadOnly != "" {
		var useHttps bool
		if strings.Contains(option.ForceToUseSpecifiedSpEndpointForDownloadOnly, "https") {
			useHttps = true
		} else {
			useHttps = c.secure
		}

		c.forceToUseSpecifiedSpEndpointForDownloadOnly, err = utils.GetEndpointURL(option.ForceToUseSpecifiedSpEndpointForDownloadOnly, useHttps)
		if err != nil {
			log.Error().Msg(fmt.Sprintf("fetch endpoint from option %s fail:%v", option.ForceToUseSpecifiedSpEndpointForDownloadOnly, err))
			return nil, err
		}
	} else {
		// fetch sp endpoints info from chain
		err = c.refreshStorageProviders(context.Background())
		if err != nil {
			return nil, err
		}
	}
	// register off-chain-auth pubkey to all sps
	//if option.OffChainAuthOption != nil {
	//	if option.ForceToUseSpecifiedSpEndpointForDownloadOnly != "" {
	//		return nil, errors.New("forceToUseSpecifiedSpEndpointForDownloadOnly option does not support OffChainAuthOption, please adjust option inputs and try again")
	//	}
	//	if option.OffChainAuthOption.Seed == "" || option.OffChainAuthOption.Domain == "" {
	//		return nil, errors.New("seed and domain can't be empty in OffChainAuthOption")
	//	}
	//	c.offChainAuthOption = option.OffChainAuthOption
	//	if option.OffChainAuthOption.ShouldRegisterPubKey {
	//		for _, sp := range c.storageProviders {
	//			registerResult, err := c.RegisterEDDSAPublicKey(sp.OperatorAddress.String(), sp.EndPoint.Scheme+"://"+sp.EndPoint.Host)
	//			if err != nil {
	//				log.Error().Msg(fmt.Sprintf("Fail to RegisterEDDSAPublicKey for sp : %s", sp.EndPoint))
	//			}
	//			log.Info().Msg(fmt.Sprintf("registerResult: %s", registerResult))
	//
	//		}
	//	}
	//}

	// register off-chain-auth-v2 pubkey to all sps
	if option.OffChainAuthOptionV2 != nil {
		if option.OffChainAuthOptionV2.Seed == "" || option.OffChainAuthOptionV2.Domain == "" {
			return nil, errors.New("seed and domain can't be empty in OffChainAuthOptionV2")
		}
		_, userEddsaPublicKey := GetEd25519PrivateKeyAndPublicKey(option.OffChainAuthOptionV2.Seed)
		option.OffChainAuthOptionV2.PublicKey = hex.EncodeToString(userEddsaPublicKey)

		c.offChainAuthOptionV2 = option.OffChainAuthOptionV2
		if option.OffChainAuthOptionV2.ShouldRegisterPubKey {
			for _, sp := range c.storageProviders {
				registerResult, err := c.RegisterEDDSAPublicKeyV2(sp.EndPoint.Scheme + "://" + sp.EndPoint.Host)
				if err != nil {
					log.Error().Msg(fmt.Sprintf("Fail to RegisterEDDSAPublicKeyV2 for sp : %s", sp.EndPoint))
				}
				log.Info().Msg(fmt.Sprintf("registerResult: %s", registerResult))

			}
		}
	}

	return &c, nil
}

func (c *Client) getSPUrlByBucket(bucketName string) (*url.URL, error) {
	sp, err := c.pickStorageProviderByBucket(bucketName)
	if err != nil {
		return nil, err
	}
	return sp.EndPoint, nil
}

func (c *Client) pickStorageProviderByBucket(bucketName string) (*types.StorageProvider, error) {
	ctx := context.Background()
	bucketInfo, err := c.HeadBucket(ctx, bucketName)
	if err != nil {
		return nil, err
	}

	familyResp, err := c.chainClient.GlobalVirtualGroupFamily(ctx, &types2.QueryGlobalVirtualGroupFamilyRequest{FamilyId: bucketInfo.GlobalVirtualGroupFamilyId})
	if err != nil {
		return nil, err
	}

	sp, ok := c.storageProviders[familyResp.GlobalVirtualGroupFamily.PrimarySpId]
	if ok {
		return sp, nil
	}
	// refresh the meta from blockchain
	err = c.refreshStorageProviders(ctx)
	if err != nil {
		return nil, err
	}

	sp, ok = c.storageProviders[familyResp.GlobalVirtualGroupFamily.PrimarySpId]
	if ok {
		return sp, nil
	}
	return nil, fmt.Errorf("the storage provider %d not exists on chain", familyResp.GlobalVirtualGroupFamily.PrimarySpId)
}

// getSPUrlByID route url of the sp from sp id
func (c *Client) getSPUrlByID(id uint32) (*url.URL, error) {
	sp, ok := c.storageProviders[id]
	if ok {
		return sp.EndPoint, nil
	}

	return nil, fmt.Errorf("the SP endpoint %d not exists on chain", id)
}

// getSPUrlByAddr route url of the sp from sp address
func (c *Client) getSPUrlByAddr(address string) (*url.URL, error) {
	acc, err := sdk.AccAddressFromHexUnsafe(address)
	if err != nil {
		return nil, err
	}
	for _, sp := range c.storageProviders {
		if sp.OperatorAddress.Equals(acc) {
			return sp.EndPoint, nil
		}
	}

	return nil, fmt.Errorf("the SP endpoint %s not exists on chain", address)
}

// getInServiceSP return the first SP endpoint which is in service in SP list
func (c *Client) getInServiceSP() (*url.URL, error) {
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
	method           string       // request method
	body             interface{}  // request body
	disableCloseBody bool         // indicate whether to disable automatic calls to resp.Body.Close()
	txnHash          string       // the transaction hash info
	adminInfo        AdminAPIInfo // the admin API info
}

// AdminAPIInfo - the admin api info
type AdminAPIInfo struct {
	isAdminAPI   bool // indicate if it is an admin api request
	adminVersion int  // indicate the version of admin api, the default value is 1
}

// downloadSegmentHook is hook for test
type downloadSegmentHook func(seg int64) error

var DownloadSegmentHooker downloadSegmentHook = DefaultDownloadSegmentHook

func DefaultDownloadSegmentHook(seg int64) error {
	return nil
}

// newRequest constructs the http request, set url, body and headers
func (c *Client) newRequest(ctx context.Context, method string, meta requestMeta,
	body interface{}, txnHash string, adminAPIInfo AdminAPIInfo, endpoint *url.URL,
) (req *http.Request, err error) {
	isVirtualHost := c.isVirtualHostStyleUrl(*endpoint, meta.bucketName)

	// construct the target url
	desURL, err := c.generateURL(meta.bucketName, meta.objectName, meta.urlRelPath,
		meta.urlValues, adminAPIInfo, endpoint, isVirtualHost)
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
		req.Header.Set(types.HTTPHeaderObjectID, info.ObjectId)
		req.Header.Set(types.HTTPHeaderRedundancyIndex, strconv.Itoa(info.RedundancyIndex))
		req.Header.Set(types.HTTPHeaderPieceIndex, strconv.Itoa(info.PieceIndex))
	}

	if adminAPIInfo.isAdminAPI {
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

	// set expiry for authorization
	// if the user has set the expiry seconds num, use the user option value, if not , use the default expiry value
	if c.expireSeconds == 0 {
		req.Header.Set(httplib.HTTPHeaderExpiryTimestamp, stNow.Add(time.Second*types.DefaultExpireSeconds).Format(types.Iso8601DateFormatSecond))
	} else {
		req.Header.Set(httplib.HTTPHeaderExpiryTimestamp, stNow.Add(time.Second*time.Duration(c.expireSeconds)).Format(types.Iso8601DateFormatSecond))
	}

	// set user-agent
	req.Header.Set(types.HTTPHeaderUserAgent, c.userAgent)

	// sign the total http request info when auth type v1
	err = c.signRequest(req)
	if err != nil {
		return req, err
	}

	return
}

// doAPI call Client.Do() to send request and read response from servers
func (c *Client) doAPI(ctx context.Context, req *http.Request, meta requestMeta, closeBody bool) (*http.Response, error) {
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
		if !closeBody {
			resp.Body.Close()
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
func (c *Client) sendReq(ctx context.Context, metadata requestMeta, opt *sendOptions, endpoint *url.URL) (res *http.Response, err error) {
	req, err := c.newRequest(ctx, opt.method, metadata, opt.body, opt.txnHash, opt.adminInfo, endpoint)
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

func (c *Client) SplitPartInfo(objectSize int64, configuredPartSize uint64) (totalPartsCount int, partSize int64, lastPartSize int64, err error) {
	partSizeFlt := float64(configuredPartSize)
	// Total parts count.
	totalPartsCount = int(math.Ceil(float64(objectSize) / partSizeFlt))
	// Part size.
	partSize = int64(partSizeFlt)
	// Last part size.
	lastPartSize = objectSize - int64(totalPartsCount-1)*partSize
	return totalPartsCount, partSize, lastPartSize, nil
}

// generateURL constructs the target request url based on the parameters
func (c *Client) generateURL(bucketName string, objectName string, relativePath string,
	queryValues url.Values, adminInfo AdminAPIInfo, endpoint *url.URL, isVirtualHost bool,
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
	if adminInfo.isAdminAPI {
		var prefix string
		// check the version and generate the url by the version
		if adminInfo.adminVersion == types.AdminV1Version {
			prefix = types.AdminURLPrefix + types.AdminURLV1Version
		} else if adminInfo.adminVersion == types.AdminV2Version {
			prefix = types.AdminURLPrefix + types.AdminURLV2Version
		} else {
			return nil, fmt.Errorf("invalid admin version %d", adminInfo.adminVersion)
		}
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
func (c *Client) signRequest(req *http.Request) error {
	// use offChainAuth if OffChainAuthOption is set
	if c.offChainAuthOption != nil {
		req.Header.Set("X-Gnfd-User-Address", c.defaultAccount.GetAddress().String())
		req.Header.Set("X-Gnfd-App-Domain", c.offChainAuthOption.Domain)
		unsignedMsg := httplib.GetMsgToSignInGNFD1Auth(req)
		authStr := c.OffChainAuthSign(unsignedMsg)
		// set auth header
		req.Header.Set(types.HTTPHeaderAuthorization, authStr)
		return nil
	}

	// use offChainAuth if OffChainAuthOptionV2 is set
	if c.offChainAuthOptionV2 != nil {
		req.Header.Set("X-Gnfd-User-Address", c.defaultAccount.GetAddress().String())
		req.Header.Set("X-Gnfd-App-Domain", c.offChainAuthOptionV2.Domain)
		req.Header.Set("X-Gnfd-App-Reg-Public-Key", c.offChainAuthOptionV2.PublicKey)
		unsignedMsg := httplib.GetMsgToSignInGNFD1Auth(req)
		authStr := c.OffChainAuthSignV2(unsignedMsg)
		// set auth header
		req.Header.Set(types.HTTPHeaderAuthorization, authStr)
		return nil
	}

	unsignedMsg := httplib.GetMsgToSignInGNFD1Auth(req)

	// sign the request header info, generate the signature
	signature, err := c.MustGetDefaultAccount().Sign(unsignedMsg)
	if err != nil {
		return err
	}

	authStr := []string{
		httplib.Gnfd1Ecdsa,
		"Signature=" + hex.EncodeToString(signature),
	}

	// set auth header
	req.Header.Set(types.HTTPHeaderAuthorization, strings.Join(authStr, ", "))

	return nil
}

// returns true if virtual hosted style requests are to be used.
func (c *Client) isVirtualHostStyleUrl(url url.URL, bucketName string) bool {
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

func (c *Client) dumpSPMsg(req *http.Request, resp *http.Response) {
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
func (c *Client) GetPieceHashRoots(reader io.Reader, segSize int64,
	dataShards, parityShards int,
) ([]byte, [][]byte, int64, storageTypes.RedundancyType, error) {
	pieceHashRoots, size, redundancyType, err := hashlib.ComputeIntegrityHash(reader, segSize, dataShards, parityShards, false)
	if err != nil {
		return nil, nil, 0, storageTypes.REDUNDANCY_EC_TYPE, err
	}

	return pieceHashRoots[0], pieceHashRoots[1:], size, redundancyType, nil
}

// sendPutPolicyTxn broadcast the putPolicy msg and return the txn hash
func (c *Client) sendPutPolicyTxn(ctx context.Context, msg *storageTypes.MsgPutPolicy, txOpts *gnfdSdkTypes.TxOption) (string, error) {
	if err := msg.ValidateBasic(); err != nil {
		return "", err
	}

	resp, err := c.BroadcastTx(ctx, []sdk.Msg{msg}, txOpts)
	if err != nil {
		return "", err
	}

	return resp.TxResponse.TxHash, err
}

// sendDelPolicyTxn broadcast the deletePolicy msg and return the txn hash
func (c *Client) sendDelPolicyTxn(ctx context.Context, operator sdk.AccAddress, resource string, principal *permTypes.Principal, txOpts *gnfdSdkTypes.TxOption) (string, error) {
	delPolicyMsg := storageTypes.NewMsgDeletePolicy(operator, resource, principal)

	if err := delPolicyMsg.ValidateBasic(); err != nil {
		return "", err
	}

	resp, err := c.BroadcastTx(ctx, []sdk.Msg{delPolicyMsg}, txOpts)
	if err != nil {
		return "", err
	}

	return resp.TxResponse.TxHash, err
}

func (c *Client) sendTxn(ctx context.Context, msg sdk.Msg, opt *gnfdSdkTypes.TxOption) (string, error) {
	if err := msg.ValidateBasic(); err != nil {
		return "", err
	}

	resp, err := c.BroadcastTx(ctx, []sdk.Msg{msg}, opt)
	if err != nil {
		return "", err
	}
	return resp.TxResponse.TxHash, err
}

// getEndpointByOpt return the SP endpoint by listOptions
func (c *Client) getEndpointByOpt(opts *types.EndPointOptions) (*url.URL, error) {
	var (
		endpoint *url.URL
		useHttps bool
		err      error
	)
	if opts == nil || (opts.Endpoint == "" && opts.SPAddress == "") {
		endpoint, err = c.getInServiceSP()
		if err != nil {
			log.Error().Msg(fmt.Sprintf("get in-service SP fail %s", err.Error()))
			return nil, err
		}
	} else if opts.Endpoint != "" {
		if strings.Contains(opts.Endpoint, "https") {
			useHttps = true
		} else {
			useHttps = c.secure
		}

		endpoint, err = utils.GetEndpointURL(opts.Endpoint, useHttps)
		if err != nil {
			log.Error().Msg(fmt.Sprintf("fetch endpoint from opts %s fail:%v", opts.Endpoint, err))
			return nil, err
		}
	} else if opts.SPAddress != "" {
		// get endpoint from sp address
		endpoint, err = c.getSPUrlByAddr(opts.SPAddress)
		if err != nil {
			log.Error().Msg(fmt.Sprintf("route endpoint by sp address: %s failed, err: %v", opts.SPAddress, err))
			return nil, err
		}
	}
	return endpoint, nil
}
