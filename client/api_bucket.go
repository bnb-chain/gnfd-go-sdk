package client

import (
	"context"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	govTypes "github.com/cosmos/cosmos-sdk/x/gov/types"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	gnfdsdk "github.com/bnb-chain/greenfield/sdk/types"
	gnfdTypes "github.com/bnb-chain/greenfield/types"
	"github.com/bnb-chain/greenfield/types/s3util"
	permTypes "github.com/bnb-chain/greenfield/x/permission/types"
	storageTypes "github.com/bnb-chain/greenfield/x/storage/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/tx"
	"github.com/rs/zerolog/log"

	"github.com/bnb-chain/greenfield-go-sdk/pkg/utils"
	"github.com/bnb-chain/greenfield-go-sdk/types"
)

type IBucketClient interface {
	GetCreateBucketApproval(ctx context.Context, createBucketMsg *storageTypes.MsgCreateBucket) (*storageTypes.MsgCreateBucket, error)
	// CreateBucket get approval of creating bucket and send createBucket txn to greenfield chain
	// primaryAddr indicates the HEX-encoded string of the primary storage provider address to which the bucket will be created
	CreateBucket(ctx context.Context, bucketName string, primaryAddr string, opts types.CreateBucketOptions) (string, error)
	DeleteBucket(ctx context.Context, bucketName string, opt types.DeleteBucketOption) (string, error)

	UpdateBucketVisibility(ctx context.Context, bucketName string, visibility storageTypes.VisibilityType, opt types.UpdateVisibilityOption) (string, error)
	UpdateBucketInfo(ctx context.Context, bucketName string, opts types.UpdateBucketOptions) (string, error)
	UpdateBucketPaymentAddr(ctx context.Context, bucketName string, paymentAddr sdk.AccAddress, opt types.UpdatePaymentOption) (string, error)

	HeadBucket(ctx context.Context, bucketName string) (*storageTypes.BucketInfo, error)
	HeadBucketByID(ctx context.Context, bucketID string) (*storageTypes.BucketInfo, error)
	// PutBucketPolicy put the bucket policy to the principal, return the txn hash
	// the principal can be generated by NewPrincipalWithAccount or NewPrincipalWithGroupId
	PutBucketPolicy(ctx context.Context, bucketName string, principal types.Principal, statements []*permTypes.Statement, opt types.PutPolicyOption) (string, error)
	// DeleteBucketPolicy delete the bucket policy of the principal，return the txn hash
	// the principal can be generated by NewPrincipalWithAccount or NewPrincipalWithGroupId
	DeleteBucketPolicy(ctx context.Context, bucketName string, principal types.Principal, opt types.DeletePolicyOption) (string, error)
	// GetBucketPolicy get the bucket policy info of the user specified by principalAddr.
	// principalAddr indicates the HEX-encoded string of the principal address
	GetBucketPolicy(ctx context.Context, bucketName string, principalAddr string) (*permTypes.Policy, error)
	// IsBucketPermissionAllowed check if the permission of bucket is allowed to the user.
	// userAddr indicates the HEX-encoded string of the user address
	IsBucketPermissionAllowed(ctx context.Context, userAddr string, bucketName string, action permTypes.ActionType) (permTypes.Effect, error)

	ListBuckets(ctx context.Context, opts types.ListBucketsOptions) (types.ListBucketsResult, error)
	ListBucketReadRecord(ctx context.Context, bucketName string, opts types.ListReadRecordOptions) (types.QuotaRecordInfo, error)

	GetQuotaUpdateTime(ctx context.Context, bucketName string) (int64, error)
	BuyQuotaForBucket(ctx context.Context, bucketName string, targetQuota uint64, opt types.BuyQuotaOption) (string, error)
	GetBucketReadQuota(ctx context.Context, bucketName string) (types.QuotaInfo, error)

	// ListBucketsByBucketID list buckets by bucket ids
	ListBucketsByBucketID(ctx context.Context, bucketIds []uint64, opts types.EndPointOptions) (types.ListBucketsByBucketIDResponse, error)
	GetMigrateBucketApproval(ctx context.Context, migrateBucketMsg *storageTypes.MsgMigrateBucket) (*storageTypes.MsgMigrateBucket, error)
	MigrateBucket(ctx context.Context, bucketName string, opts types.MigrateBucketOptions) (string, error)
	CancelMigrateBucket(ctx context.Context, bucketName string, opts types.CancelMigrateBucketOptions) (uint64, string, error)
	// ListBucketsByPaymentAccount list buckets by payment account
	ListBucketsByPaymentAccount(ctx context.Context, paymentAccount string, opts types.ListBucketsByPaymentAccountOptions) (types.ListBucketsByPaymentAccountResult, error)
}

// GetCreateBucketApproval returns the signature info for the approval of preCreating resources
func (c *Client) GetCreateBucketApproval(ctx context.Context, createBucketMsg *storageTypes.MsgCreateBucket) (*storageTypes.MsgCreateBucket, error) {
	unsignedBytes := createBucketMsg.GetSignBytes()

	// set the action type
	urlVal := make(url.Values)
	urlVal["action"] = []string{types.CreateBucketAction}

	reqMeta := requestMeta{
		urlValues:     urlVal,
		urlRelPath:    "get-approval",
		contentSHA256: types.EmptyStringSHA256,
		txnMsg:        hex.EncodeToString(unsignedBytes),
	}

	sendOpt := sendOptions{
		method:     http.MethodGet,
		isAdminApi: true,
	}

	primarySPAddr := createBucketMsg.GetPrimarySpAddress()
	endpoint, err := c.getSPUrlByAddr(primarySPAddr)
	if err != nil {
		log.Error().Msg(fmt.Sprintf("route endpoint by addr: %s failed, err: %s", primarySPAddr, err.Error()))
		return nil, err
	}

	resp, err := c.sendReq(ctx, reqMeta, &sendOpt, endpoint)
	if err != nil {
		return nil, err
	}

	// fetch primary signed msg from sp response
	signedRawMsg := resp.Header.Get(types.HTTPHeaderSignedMsg)
	if signedRawMsg == "" {
		return nil, errors.New("fail to fetch pre createBucket signature")
	}

	signedMsgBytes, err := hex.DecodeString(signedRawMsg)
	if err != nil {
		return nil, err
	}

	var signedMsg storageTypes.MsgCreateBucket
	storageTypes.ModuleCdc.MustUnmarshalJSON(signedMsgBytes, &signedMsg)

	return &signedMsg, nil
}

// CreateBucket get approval of creating bucket and send createBucket txn to greenfield chain, it returns the transaction hash value and error
func (c *Client) CreateBucket(ctx context.Context, bucketName string, primaryAddr string, opts types.CreateBucketOptions) (string, error) {
	address, err := sdk.AccAddressFromHexUnsafe(primaryAddr)
	if err != nil {
		return "", err
	}

	var visibility storageTypes.VisibilityType
	if opts.Visibility == storageTypes.VISIBILITY_TYPE_UNSPECIFIED {
		visibility = storageTypes.VISIBILITY_TYPE_PRIVATE // set default visibility type
	} else {
		visibility = opts.Visibility
	}

	var paymentAddr sdk.AccAddress
	if opts.PaymentAddress != "" {
		paymentAddr, err = sdk.AccAddressFromHexUnsafe(opts.PaymentAddress)
		if err != nil {
			return "", err
		}
	}

	createBucketMsg := storageTypes.NewMsgCreateBucket(c.MustGetDefaultAccount().GetAddress(), bucketName,
		visibility, address, paymentAddr, 0, nil, opts.ChargedQuota)

	err = createBucketMsg.ValidateBasic()
	if err != nil {
		return "", err
	}
	signedMsg, err := c.GetCreateBucketApproval(ctx, createBucketMsg)
	if err != nil {
		return "", err
	}

	// set the default txn broadcast mode as block mode
	if opts.TxOpts == nil {
		broadcastMode := tx.BroadcastMode_BROADCAST_MODE_SYNC
		opts.TxOpts = &gnfdsdk.TxOption{Mode: &broadcastMode}
	}
	resp, err := c.BroadcastTx(ctx, []sdk.Msg{signedMsg}, opts.TxOpts)
	if err != nil {
		return "", err
	}
	txnHash := resp.TxResponse.TxHash
	if !opts.IsAsyncMode {
		ctxTimeout, cancel := context.WithTimeout(ctx, types.ContextTimeout)
		defer cancel()
		txnResponse, err := c.WaitForTx(ctxTimeout, txnHash)
		if err != nil {
			return txnHash, fmt.Errorf("the transaction has been submitted, please check it later:%v", err)
		}
		if txnResponse.TxResult.Code != 0 {
			return txnHash, fmt.Errorf("the createBucket txn has failed with response code: %d, codespace:%s", txnResponse.TxResult.Code, txnResponse.TxResult.Codespace)
		}
	}
	return txnHash, nil
}

// DeleteBucket send DeleteBucket txn to greenfield chain and return txn hash
func (c *Client) DeleteBucket(ctx context.Context, bucketName string, opt types.DeleteBucketOption) (string, error) {
	if err := s3util.CheckValidBucketName(bucketName); err != nil {
		return "", err
	}
	delBucketMsg := storageTypes.NewMsgDeleteBucket(c.MustGetDefaultAccount().GetAddress(), bucketName)
	return c.sendTxn(ctx, delBucketMsg, opt.TxOpts)
}

// UpdateBucketVisibility update the visibilityType of bucket
func (c *Client) UpdateBucketVisibility(ctx context.Context, bucketName string,
	visibility storageTypes.VisibilityType, opt types.UpdateVisibilityOption,
) (string, error) {
	bucketInfo, err := c.HeadBucket(ctx, bucketName)
	if err != nil {
		return "", err
	}

	paymentAddr, err := sdk.AccAddressFromHexUnsafe(bucketInfo.PaymentAddress)
	if err != nil {
		return "", err
	}

	updateBucketMsg := storageTypes.NewMsgUpdateBucketInfo(c.MustGetDefaultAccount().GetAddress(), bucketName, &bucketInfo.ChargedReadQuota, paymentAddr, visibility)
	return c.sendTxn(ctx, updateBucketMsg, opt.TxOpts)
}

// UpdateBucketPaymentAddr  update the payment addr of bucket
func (c *Client) UpdateBucketPaymentAddr(ctx context.Context, bucketName string,
	paymentAddr sdk.AccAddress, opt types.UpdatePaymentOption,
) (string, error) {
	bucketInfo, err := c.HeadBucket(ctx, bucketName)
	if err != nil {
		return "", err
	}

	updateBucketMsg := storageTypes.NewMsgUpdateBucketInfo(c.MustGetDefaultAccount().GetAddress(), bucketName, &bucketInfo.ChargedReadQuota, paymentAddr, bucketInfo.Visibility)
	return c.sendTxn(ctx, updateBucketMsg, opt.TxOpts)
}

// UpdateBucketInfo update the bucket meta on chain, including read quota, payment address or visibility
func (c *Client) UpdateBucketInfo(ctx context.Context, bucketName string, opts types.UpdateBucketOptions) (string, error) {
	bucketInfo, err := c.HeadBucket(ctx, bucketName)
	if err != nil {
		return "", err
	}

	if opts.Visibility == bucketInfo.Visibility && opts.PaymentAddress == "" && opts.ChargedQuota == nil {
		return "", errors.New("no meta need to update")
	}

	var visibility storageTypes.VisibilityType
	var chargedReadQuota uint64
	var paymentAddr sdk.AccAddress

	if opts.Visibility != bucketInfo.Visibility {
		visibility = opts.Visibility
	} else {
		visibility = bucketInfo.Visibility
	}

	if opts.PaymentAddress != "" {
		paymentAddr, err = sdk.AccAddressFromHexUnsafe(opts.PaymentAddress)
		if err != nil {
			return "", err
		}
	} else {
		paymentAddr, err = sdk.AccAddressFromHexUnsafe(bucketInfo.PaymentAddress)
		if err != nil {
			return "", err
		}
	}

	if opts.ChargedQuota != nil {
		chargedReadQuota = *opts.ChargedQuota
	} else {
		chargedReadQuota = bucketInfo.ChargedReadQuota
	}

	updateBucketMsg := storageTypes.NewMsgUpdateBucketInfo(c.MustGetDefaultAccount().GetAddress(), bucketName,
		&chargedReadQuota, paymentAddr, visibility)

	// set the default txn broadcast mode as block mode
	if opts.TxOpts == nil {
		broadcastMode := tx.BroadcastMode_BROADCAST_MODE_SYNC
		opts.TxOpts = &gnfdsdk.TxOption{Mode: &broadcastMode}
	}

	return c.sendTxn(ctx, updateBucketMsg, opts.TxOpts)
}

// HeadBucket query the bucketInfo on chain, return the bucket info if exists
// return err info if bucket not exist
func (c *Client) HeadBucket(ctx context.Context, bucketName string) (*storageTypes.BucketInfo, error) {
	queryHeadBucketRequest := storageTypes.QueryHeadBucketRequest{
		BucketName: bucketName,
	}
	queryHeadBucketResponse, err := c.chainClient.HeadBucket(ctx, &queryHeadBucketRequest)
	if err != nil {
		return nil, err
	}

	return queryHeadBucketResponse.BucketInfo, nil
}

// HeadBucketByID query the bucketInfo on chain by bucketId, return the bucket info if exists
// return err info if bucket not exist
func (c *Client) HeadBucketByID(ctx context.Context, bucketID string) (*storageTypes.BucketInfo, error) {
	headBucketRequest := &storageTypes.QueryHeadBucketByIdRequest{
		BucketId: bucketID,
	}

	headBucketResponse, err := c.chainClient.HeadBucketById(ctx, headBucketRequest)
	if err != nil {
		return nil, err
	}

	return headBucketResponse.BucketInfo, nil
}

// PutBucketPolicy apply bucket policy to the principal, return the txn hash
func (c *Client) PutBucketPolicy(ctx context.Context, bucketName string, principalStr types.Principal,
	statements []*permTypes.Statement, opt types.PutPolicyOption,
) (string, error) {
	resource := gnfdTypes.NewBucketGRN(bucketName)
	principal := &permTypes.Principal{}
	if err := principal.Unmarshal([]byte(principalStr)); err != nil {
		return "", err
	}

	putPolicyMsg := storageTypes.NewMsgPutPolicy(c.MustGetDefaultAccount().GetAddress(), resource.String(),
		principal, statements, opt.PolicyExpireTime)

	return c.sendPutPolicyTxn(ctx, putPolicyMsg, opt.TxOpts)
}

// DeleteBucketPolicy delete the bucket policy of the principal
func (c *Client) DeleteBucketPolicy(ctx context.Context, bucketName string, principalStr types.Principal, opt types.DeletePolicyOption) (string, error) {
	resource := gnfdTypes.NewBucketGRN(bucketName).String()
	principal := &permTypes.Principal{}
	if err := principal.Unmarshal([]byte(principalStr)); err != nil {
		return "", err
	}

	return c.sendDelPolicyTxn(ctx, c.MustGetDefaultAccount().GetAddress(), resource, principal, opt.TxOpts)
}

// IsBucketPermissionAllowed check if the permission of bucket is allowed to the user.
func (c *Client) IsBucketPermissionAllowed(ctx context.Context, userAddr string,
	bucketName string, action permTypes.ActionType,
) (permTypes.Effect, error) {
	_, err := sdk.AccAddressFromHexUnsafe(userAddr)
	if err != nil {
		return permTypes.EFFECT_DENY, err
	}
	verifyReq := storageTypes.QueryVerifyPermissionRequest{
		Operator:   userAddr,
		BucketName: bucketName,
		ActionType: action,
	}

	verifyResp, err := c.chainClient.VerifyPermission(ctx, &verifyReq)
	if err != nil {
		return permTypes.EFFECT_DENY, err
	}

	return verifyResp.Effect, nil
}

// GetBucketPolicy get the bucket policy info of the user specified by principalAddr.
func (c *Client) GetBucketPolicy(ctx context.Context, bucketName string, principalAddr string) (*permTypes.Policy, error) {
	_, err := sdk.AccAddressFromHexUnsafe(principalAddr)
	if err != nil {
		return nil, err
	}

	resource := gnfdTypes.NewBucketGRN(bucketName).String()
	queryPolicy := storageTypes.QueryPolicyForAccountRequest{
		Resource:         resource,
		PrincipalAddress: principalAddr,
	}

	queryPolicyResp, err := c.chainClient.QueryPolicyForAccount(ctx, &queryPolicy)
	if err != nil {
		return nil, err
	}

	return queryPolicyResp.Policy, nil
}

type listBucketsByIDsResponse map[uint64]*types.BucketMeta

type bucketEntry struct {
	Id    uint64
	Value *types.BucketMeta
}

func (m *listBucketsByIDsResponse) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	*m = listBucketsByIDsResponse{}
	for {
		var e bucketEntry

		err := d.Decode(&e)
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		} else {
			(*m)[e.Id] = e.Value
		}
	}
	return nil
}

// ListBuckets list buckets for the owner
func (c *Client) ListBuckets(ctx context.Context, opts types.ListBucketsOptions) (types.ListBucketsResult, error) {
	params := url.Values{}
	params.Set("include-removed", strconv.FormatBool(opts.ShowRemovedBucket))

	account := opts.Account
	if account == "" {
		acc, err := c.GetDefaultAccount()
		if err != nil {
			log.Error().Msg(fmt.Sprintf("failed to get default account:  %s", err.Error()))
			return types.ListBucketsResult{}, err
		}
		account = acc.GetAddress().String()
	} else {
		_, err := sdk.AccAddressFromHexUnsafe(account)
		if err != nil {
			return types.ListBucketsResult{}, err
		}
	}

	reqMeta := requestMeta{
		urlValues:     params,
		contentSHA256: types.EmptyStringSHA256,
		userAddress:   account,
	}

	sendOpt := sendOptions{
		method:           http.MethodGet,
		disableCloseBody: true,
	}

	endpoint, err := c.getEndpointByOpt(&types.EndPointOptions{
		Endpoint:  opts.Endpoint,
		SPAddress: opts.SPAddress,
	})
	if err != nil {
		log.Error().Msg(fmt.Sprintf("get endpoint by option failed %s", err.Error()))
		return types.ListBucketsResult{}, err
	}

	resp, err := c.sendReq(ctx, reqMeta, &sendOpt, endpoint)
	if err != nil {
		log.Error().Msg("the list of user's buckets failed: " + err.Error())
		return types.ListBucketsResult{}, err
	}
	defer utils.CloseResponse(resp)

	listBucketsResult := types.ListBucketsResult{}
	// unmarshal the json content from response body
	buf := new(strings.Builder)
	_, err = io.Copy(buf, resp.Body)
	if err != nil {
		log.Error().Msg("the list of user's buckets failed: " + err.Error())
		return types.ListBucketsResult{}, err
	}

	bufStr := buf.String()
	err = xml.Unmarshal([]byte(bufStr), &listBucketsResult)

	// TODO(annie) remove tolerance for unmarshal err after structs got stabilized
	if err != nil {
		return types.ListBucketsResult{}, err
	}

	return listBucketsResult, nil
}

// ListBucketReadRecord returns the read record of this month, the return items should be no more than maxRecords
// ListReadRecordOption indicates the start timestamp of return read records
func (c *Client) ListBucketReadRecord(ctx context.Context, bucketName string, opts types.ListReadRecordOptions) (types.QuotaRecordInfo, error) {
	if err := s3util.CheckValidBucketName(bucketName); err != nil {
		return types.QuotaRecordInfo{}, err
	}
	timeNow := time.Now()
	timeToday := time.Date(timeNow.Year(), timeNow.Month(), timeNow.Day(), 0, 0, 0, 0, timeNow.Location())
	if opts.StartTimeStamp < 0 {
		return types.QuotaRecordInfo{}, errors.New("start timestamp  less than 0")
	}
	var startTimeStamp int64
	if opts.StartTimeStamp == 0 {
		// the timestamp of the first day of this month
		startTimeStamp = timeToday.AddDate(0, 0, -timeToday.Day()+1).UnixMicro()
	} else {
		startTimeStamp = opts.StartTimeStamp
	}
	// the timestamp of the last day of this month
	timeMonthEnd := timeToday.AddDate(0, 1, -timeToday.Day()+1).UnixMicro()

	if timeMonthEnd < startTimeStamp {
		return types.QuotaRecordInfo{}, errors.New("start timestamp larger than the end timestamp of this month")
	}

	params := url.Values{}
	params.Set("list-read-record", "")
	if opts.MaxRecords > 0 {
		params.Set("max-records", strconv.Itoa(opts.MaxRecords))
	} else {
		params.Set("max-records", strconv.Itoa(math.MaxUint32))
	}

	params.Set("start-timestamp", strconv.FormatInt(startTimeStamp, 10))
	params.Set("end-timestamp", strconv.FormatInt(timeMonthEnd, 10))

	reqMeta := requestMeta{
		urlValues:     params,
		bucketName:    bucketName,
		contentSHA256: types.EmptyStringSHA256,
	}

	sendOpt := sendOptions{
		method:           http.MethodGet,
		disableCloseBody: true,
	}

	endpoint, err := c.getSPUrlByBucket(bucketName)
	if err != nil {
		log.Error().Msg(fmt.Sprintf("route endpoint by bucket: %s failed, err: %s", bucketName, err.Error()))
		return types.QuotaRecordInfo{}, err
	}

	resp, err := c.sendReq(ctx, reqMeta, &sendOpt, endpoint)
	if err != nil {
		return types.QuotaRecordInfo{}, err
	}
	defer utils.CloseResponse(resp)

	QuotaRecords := types.QuotaRecordInfo{}
	// decode the xml content from response body
	err = xml.NewDecoder(resp.Body).Decode(&QuotaRecords)
	if err != nil {
		return types.QuotaRecordInfo{}, err
	}

	return QuotaRecords, nil
}

// GetBucketReadQuota return quota info of bucket of current month, include chain quota, free quota and consumed quota
func (c *Client) GetBucketReadQuota(ctx context.Context, bucketName string) (types.QuotaInfo, error) {
	if err := s3util.CheckValidBucketName(bucketName); err != nil {
		return types.QuotaInfo{}, err
	}

	year, month, _ := time.Now().Date()
	var date string
	if int(month) < 10 {
		date = strconv.Itoa(year) + "-" + "0" + strconv.Itoa(int(month))
	} else {
		date = strconv.Itoa(year) + "-" + strconv.Itoa(int(month))
	}

	params := url.Values{}
	params.Add("read-quota", "")
	params.Add("year-month", date)

	reqMeta := requestMeta{
		urlValues:     params,
		bucketName:    bucketName,
		contentSHA256: types.EmptyStringSHA256,
	}

	sendOpt := sendOptions{
		method:           http.MethodGet,
		disableCloseBody: true,
	}

	endpoint, err := c.getSPUrlByBucket(bucketName)
	if err != nil {
		log.Error().Msg(fmt.Sprintf("route endpoint by bucket: %s failed, err: %s", bucketName, err.Error()))
		return types.QuotaInfo{}, err
	}

	resp, err := c.sendReq(ctx, reqMeta, &sendOpt, endpoint)
	if err != nil {
		return types.QuotaInfo{}, err
	}
	defer utils.CloseResponse(resp)

	QuotaResult := types.QuotaInfo{}
	// decode the xml content from response body
	err = xml.NewDecoder(resp.Body).Decode(&QuotaResult)
	if err != nil {
		return types.QuotaInfo{}, err
	}

	return QuotaResult, nil
}

func (c *Client) GetQuotaUpdateTime(ctx context.Context, bucketName string) (int64, error) {
	resp, err := c.chainClient.QueryQuotaUpdateTime(ctx, &storageTypes.QueryQuoteUpdateTimeRequest{
		BucketName: bucketName,
	})
	if err != nil {
		return 0, err
	}
	return resp.UpdateAt, nil
}

// BuyQuotaForBucket buy the target quota of the specific bucket
// targetQuota indicates the target quota to set for the bucket
func (c *Client) BuyQuotaForBucket(ctx context.Context, bucketName string, targetQuota uint64, opt types.BuyQuotaOption) (string, error) {
	bucketInfo, err := c.HeadBucket(ctx, bucketName)
	if err != nil {
		return "", err
	}

	paymentAddr, err := sdk.AccAddressFromHexUnsafe(bucketInfo.PaymentAddress)
	if err != nil {
		return "", err
	}
	updateBucketMsg := storageTypes.NewMsgUpdateBucketInfo(c.MustGetDefaultAccount().GetAddress(), bucketName, &targetQuota, paymentAddr, bucketInfo.Visibility)

	resp, err := c.BroadcastTx(ctx, []sdk.Msg{updateBucketMsg}, opt.TxOpts)
	if err != nil {
		return "", err
	}

	return resp.TxResponse.TxHash, err
}

// ListBucketsByBucketID list buckets by bucket ids
// By inputting a collection of bucket IDs, we can retrieve the corresponding bucket data.
// If the bucket is nonexistent or has been deleted, a null value will be returned
func (c *Client) ListBucketsByBucketID(ctx context.Context, bucketIds []uint64, opts types.EndPointOptions) (types.ListBucketsByBucketIDResponse, error) {
	const MaximumListBucketsSize = 1000
	if len(bucketIds) == 0 || len(bucketIds) > MaximumListBucketsSize {
		return types.ListBucketsByBucketIDResponse{}, nil
	}

	bucketIDMap := make(map[uint64]bool)
	for _, id := range bucketIds {
		if _, ok := bucketIDMap[id]; ok {
			// repeat id keys in request
			return types.ListBucketsByBucketIDResponse{}, nil
		}
		bucketIDMap[id] = true
	}

	idStr := make([]string, len(bucketIds))
	for i, id := range bucketIds {
		idStr[i] = strconv.FormatUint(id, 10)
	}
	IDs := strings.Join(idStr, ",")

	params := url.Values{}
	params.Set("buckets-query", "")
	params.Set("ids", IDs)

	reqMeta := requestMeta{
		urlValues:     params,
		contentSHA256: types.EmptyStringSHA256,
	}

	sendOpt := sendOptions{
		method:           http.MethodGet,
		disableCloseBody: true,
	}

	endpoint, err := c.getEndpointByOpt(&opts)
	if err != nil {
		log.Error().Msg(fmt.Sprintf("get endpoint by option failed %s", err.Error()))
		return types.ListBucketsByBucketIDResponse{}, err

	}

	resp, err := c.sendReq(ctx, reqMeta, &sendOpt, endpoint)
	if err != nil {
		return types.ListBucketsByBucketIDResponse{}, err
	}
	defer utils.CloseResponse(resp)

	// unmarshal the json content from response body
	buf := new(strings.Builder)
	_, err = io.Copy(buf, resp.Body)
	if err != nil {
		log.Error().Msgf("the list of buckets in bucket ids:%v failed: %s", bucketIds, err.Error())
		return types.ListBucketsByBucketIDResponse{}, err
	}

	buckets := types.ListBucketsByBucketIDResponse{}
	bufStr := buf.String()
	err = xml.Unmarshal([]byte(bufStr), (*listBucketsByIDsResponse)(&buckets.Buckets))
	if err != nil && buckets.Buckets == nil {
		log.Error().Msgf("the list of buckets in bucket ids:%v failed: %s", bucketIds, err.Error())
		return types.ListBucketsByBucketIDResponse{}, err
	}

	return buckets, nil
}

func (c *Client) GetMigrateBucketApproval(ctx context.Context, migrateBucketMsg *storageTypes.MsgMigrateBucket) (*storageTypes.MsgMigrateBucket, error) {
	unsignedBytes := migrateBucketMsg.GetSignBytes()

	// set the action type
	urlVal := make(url.Values)
	urlVal["action"] = []string{types.MigrateBucketAction}

	reqMeta := requestMeta{
		urlValues:     urlVal,
		urlRelPath:    "get-approval",
		contentSHA256: types.EmptyStringSHA256,
		txnMsg:        hex.EncodeToString(unsignedBytes),
	}

	sendOpt := sendOptions{
		method:     http.MethodGet,
		isAdminApi: true,
	}

	primarySPID := migrateBucketMsg.DstPrimarySpId
	endpoint, err := c.getSPUrlByID(primarySPID)
	if err != nil {
		log.Error().Msg(fmt.Sprintf("route endpoint by addr: %d failed, err: %s", primarySPID, err.Error()))
		return nil, err
	}
	resp, err := c.sendReq(ctx, reqMeta, &sendOpt, endpoint)
	if err != nil {
		return nil, err
	}

	// fetch primary signed msg from sp response
	signedRawMsg := resp.Header.Get(types.HTTPHeaderSignedMsg)
	if signedRawMsg == "" {
		return nil, errors.New("fail to fetch pre createBucket signature")
	}

	signedMsgBytes, err := hex.DecodeString(signedRawMsg)
	if err != nil {
		return nil, err
	}

	var signedMsg storageTypes.MsgMigrateBucket
	storageTypes.ModuleCdc.MustUnmarshalJSON(signedMsgBytes, &signedMsg)

	return &signedMsg, nil
}

// MigrateBucket get approval of migrating bucket and send migrateBucket txn to greenfield chain, it returns the transaction hash value and error
func (c *Client) MigrateBucket(ctx context.Context, bucketName string, opts types.MigrateBucketOptions) (string, error) {
	migrateBucketMsg := storageTypes.NewMsgMigrateBucket(c.MustGetDefaultAccount().GetAddress(), bucketName, opts.DstPrimarySPID)

	err := migrateBucketMsg.ValidateBasic()
	if err != nil {
		return "", err
	}
	signedMsg, err := c.GetMigrateBucketApproval(ctx, migrateBucketMsg)
	if err != nil {
		return "", err
	}

	// set the default txn broadcast mode as block mode
	if opts.TxOpts == nil {
		broadcastMode := tx.BroadcastMode_BROADCAST_MODE_SYNC
		opts.TxOpts = &gnfdsdk.TxOption{Mode: &broadcastMode}
	}

	resp, err := c.BroadcastTx(ctx, []sdk.Msg{signedMsg}, opts.TxOpts)
	if err != nil {
		return "", err
	}
	txnHash := resp.TxResponse.TxHash
	if !opts.IsAsyncMode {
		ctxTimeout, cancel := context.WithTimeout(ctx, types.ContextTimeout)
		defer cancel()
		txnResponse, err := c.WaitForTx(ctxTimeout, txnHash)
		if err != nil {
			return txnHash, fmt.Errorf("the transaction has been submitted, please check it later:%v", err)
		}
		if txnResponse.TxResult.Code != 0 {
			return txnHash, fmt.Errorf("the migrateBucket txn has failed with response code: %d, codespace:%s", txnResponse.TxResult.Code, txnResponse.TxResult.Codespace)
		}
	}
	return txnHash, nil
}

// CancelMigrateBucket get approval of migrating bucket and send migrateBucket txn to greenfield chain, it returns the transaction hash value and error
func (c *Client) CancelMigrateBucket(ctx context.Context, bucketName string, opts types.CancelMigrateBucketOptions) (uint64, string, error) {
	govModuleAddress, err := c.GetModuleAccountByName(ctx, govTypes.ModuleName)
	if err != nil {
		return 0, "", err
	}
	cancelBucketMsg := storageTypes.NewMsgCancelMigrateBucket(
		govModuleAddress.GetAddress(), bucketName,
	)

	err = cancelBucketMsg.ValidateBasic()
	if err != nil {
		return 0, "", err
	}

	return c.SubmitProposal(ctx, []sdk.Msg{cancelBucketMsg}, opts.ProposalDepositAmount, opts.ProposalTitle, opts.ProposalSummary, types.SubmitProposalOptions{Metadata: opts.ProposalMetadata, TxOpts: opts.TxOpts})
}

// ListBucketsByPaymentAccount list bucket by payment account
func (c *Client) ListBucketsByPaymentAccount(ctx context.Context, paymentAccount string, opts types.ListBucketsByPaymentAccountOptions) (types.ListBucketsByPaymentAccountResult, error) {

	_, err := sdk.AccAddressFromHexUnsafe(paymentAccount)
	if err != nil {
		return types.ListBucketsByPaymentAccountResult{}, err
	}

	params := url.Values{}
	params.Set("payment-buckets", "")
	params.Set("payment-account", paymentAccount)

	reqMeta := requestMeta{
		urlValues:     params,
		contentSHA256: types.EmptyStringSHA256,
	}

	sendOpt := sendOptions{
		method:           http.MethodGet,
		disableCloseBody: true,
	}

	endpoint, err := c.getEndpointByOpt(&types.EndPointOptions{
		Endpoint:  opts.Endpoint,
		SPAddress: opts.SPAddress,
	})
	if err != nil {
		log.Error().Msg(fmt.Sprintf("get endpoint by option failed %s", err.Error()))
		return types.ListBucketsByPaymentAccountResult{}, err

	}

	resp, err := c.sendReq(ctx, reqMeta, &sendOpt, endpoint)
	if err != nil {
		return types.ListBucketsByPaymentAccountResult{}, err
	}
	defer utils.CloseResponse(resp)

	buf := new(strings.Builder)
	_, err = io.Copy(buf, resp.Body)
	if err != nil {
		return types.ListBucketsByPaymentAccountResult{}, errors.New("copy the response error" + err.Error())
	}

	buckets := types.ListBucketsByPaymentAccountResult{}
	bufStr := buf.String()
	err = xml.Unmarshal([]byte(bufStr), &buckets)
	if err != nil {
		return types.ListBucketsByPaymentAccountResult{}, errors.New("unmarshal response error" + err.Error())
	}

	return buckets, nil
}
