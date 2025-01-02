package client

import (
	"context"
	"encoding/hex"
	math2 "math"
	"strings"
	"time"

	"github.com/cosmos/cosmos-sdk/types/query"
	"github.com/prysmaticlabs/prysm/v5/crypto/bls"

	"cosmossdk.io/math"
	"github.com/bnb-chain/greenfield-go-sdk/pkg/utils"
	"github.com/bnb-chain/greenfield-go-sdk/types"
	gnfdSdkTypes "github.com/bnb-chain/greenfield/sdk/types"
	spTypes "github.com/bnb-chain/greenfield/x/sp/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/x/authz"
	govTypes "github.com/cosmos/cosmos-sdk/x/gov/types"
)

// ISPClient interface defines basic functions related to Storage Provider.
type ISPClient interface {
	ListStorageProviders(ctx context.Context, isInService bool) ([]spTypes.StorageProvider, error)
	GetStorageProviderInfo(ctx context.Context, SPAddr sdk.AccAddress) (*spTypes.StorageProvider, error)
	GetStoragePrice(ctx context.Context, SPAddr string) (*spTypes.SpStoragePrice, error)
	GetGlobalSpStorePrice(ctx context.Context) (*spTypes.GlobalSpStorePrice, error)
	GrantDepositForStorageProvider(ctx context.Context, spAddr string, depositAmount math.Int, opts types.GrantDepositForStorageProviderOptions) (string, error)
	CreateStorageProvider(ctx context.Context, fundingAddr, sealAddr, approvalAddr, gcAddr, maintenanceAddr, blsPubKey, blsProof, endpoint string, depositAmount math.Int, description spTypes.Description, opts types.CreateStorageProviderOptions) (uint64, string, error)
	UpdateSpStoragePrice(ctx context.Context, spAddr string, readPrice, storePrice sdk.Dec, freeReadQuota uint64, txOption gnfdSdkTypes.TxOption) (string, error)
	UpdateSpStatus(ctx context.Context, spAddr string, status spTypes.Status, duration int64, txOption gnfdSdkTypes.TxOption) (string, error)
}

// GetStoragePrice - Get the storage price details for a particular storage provider, including update time, read price, store price and .etc.
//
// - ctx: Context variables for the current API call.
//
// - spAddr: The HEX-encoded string of the storage provider address.
//
// - ret1: The specified storage provider price detail.
//
// - ret2: Return error when the request failed, otherwise return nil.
func (c *Client) GetStoragePrice(ctx context.Context, spAddr string) (*spTypes.SpStoragePrice, error) {
	spAcc, err := sdk.AccAddressFromHexUnsafe(spAddr)
	if err != nil {
		return nil, err
	}
	resp, err := c.chainClient.QuerySpStoragePrice(ctx, &spTypes.QuerySpStoragePriceRequest{
		SpAddr: spAcc.String(),
	})
	if err != nil {
		return nil, err
	}
	return &resp.SpStoragePrice, nil
}

// GetGlobalSpStorePrice - Get the global storage price details, including update time and store price.
//
// - ctx: Context variables for the current API call.
//
// - ret1: The global storage provider price detail.
//
// - ret2: Return error when the request failed, otherwise return nil.
func (c *Client) GetGlobalSpStorePrice(ctx context.Context) (*spTypes.GlobalSpStorePrice, error) {
	resp, err := c.chainClient.QueryGlobalSpStorePriceByTime(ctx, &spTypes.QueryGlobalSpStorePriceByTimeRequest{
		Timestamp: 0,
	})
	if err != nil {
		return nil, err
	}
	return &resp.GlobalSpStorePrice, nil
}

// ListStorageProviders - List the storage providers info on chain.
//
// - ctx: Context variables for the current API call.
//
// - isInService: The boolean value indicates if only display the sp with STATUS_IN_SERVICE status.
//
// - ret1: The global storage provider price detail.
//
// - ret2: Return error when the request failed, otherwise return nil.
func (c *Client) ListStorageProviders(ctx context.Context, isInService bool) ([]spTypes.StorageProvider, error) {
	request := &spTypes.QueryStorageProvidersRequest{}
	gnfdRep, err := c.chainClient.StorageProviders(ctx, request)
	if err != nil {
		return nil, err
	}

	spList := gnfdRep.GetSps()
	spInfoList := make([]spTypes.StorageProvider, 0)
	for _, info := range spList {
		if isInService && info.Status != spTypes.STATUS_IN_SERVICE {
			continue
		}
		spInfoList = append(spInfoList, *info)
	}

	return spInfoList, nil
}

// GetStorageProviderInfo - Get the specified storage providers info on chain.
//
// - ctx: Context variables for the current API call.
//
// - spAddr: The HEX-encoded string of the storage provider address.
//
// - ret1: The Storage provider detail.
//
// - ret2: Return error when the request failed, otherwise return nil.
func (c *Client) GetStorageProviderInfo(ctx context.Context, spAddr sdk.AccAddress) (*spTypes.StorageProvider, error) {
	request := &spTypes.QueryStorageProviderByOperatorAddressRequest{
		OperatorAddress: spAddr.String(),
	}

	gnfdRep, err := c.chainClient.StorageProviderByOperatorAddress(ctx, request)
	if err != nil {
		return nil, err
	}

	return gnfdRep.StorageProvider, nil
}

func (c *Client) refreshStorageProviders(ctx context.Context) error {
	gnfdRep, err := c.chainClient.StorageProviders(ctx, &spTypes.QueryStorageProvidersRequest{Pagination: &query.PageRequest{Limit: math2.MaxUint64}})
	if err != nil {
		return err
	}
	for _, spInfo := range gnfdRep.Sps {
		var useHttps bool
		if strings.Contains(spInfo.Endpoint, "https") {
			useHttps = true
		} else {
			useHttps = c.secure
		}
		urlInfo, urlErr := utils.GetEndpointURL(spInfo.Endpoint, useHttps)
		if urlErr != nil {
			return urlErr
		}
		sp := &types.StorageProvider{
			Id:              spInfo.Id,
			Status:          spInfo.Status,
			OperatorAddress: sdk.MustAccAddressFromHex(spInfo.OperatorAddress),
			ApprovalAddress: sdk.MustAccAddressFromHex(spInfo.ApprovalAddress),
			SealAddress:     sdk.MustAccAddressFromHex(spInfo.SealAddress),
			GcAddress:       sdk.MustAccAddressFromHex(spInfo.GcAddress),
			EndPoint:        urlInfo,
			Description:     spInfo.Description,
			BlsKey:          spInfo.BlsKey,
		}
		c.storageProviders[sp.Id] = sp
	}
	return nil
}

// CreateStorageProvider - Submit a CreateStorageProvider proposal and return proposalID, TxHash and err if it has.
//
// - ctx: Context variables for the current API call.
//
// - fundingAddr: The HEX-encoded string of the storage provider funding address, Used to deposit staking tokens and receive earnings.
//
// - sealAddr: The HEX-encoded string of the storage provider seal address, Used to seal the user's object.
//
// - approvalAddr: The HEX-encoded string of the storage provider approval address, Used to approve user's requests.
//
// - gcAddr: The HEX-encoded string of the storage provider gc address, it is a special address for sp and is used by sp to clean up local expired or unwanted storage.
//
// - maintenanceAddr: The HEX-encoded string of the storage provider maintenance address, it is used for SP self-testing while in maintenance mode.
//
// - blsPubKey: The HEX-encoded string of the storage provider bls public key.
//
// - blsProof: The HEX-encoded string of the storage provider bls signature.
//
// - endpoint: Storage Provider endpoint.
//
// - depositAmount: The requested amount for a proposal.
//
// - description: Description for the SP.
//
// - opts: options to specify the SP prices, and proposal details.
//
// - ret1: Proposal ID.
//
// - ret2: Transaction hash return from blockchain.
//
// - ret3: Return error when the request failed, otherwise return nil.
func (c *Client) CreateStorageProvider(ctx context.Context, fundingAddr, sealAddr, approvalAddr, gcAddr, maintenanceAddr, blsPubKey, blsProof, endpoint string, depositAmount math.Int, description spTypes.Description, opts types.CreateStorageProviderOptions) (uint64, string, error) {
	defaultAccount := c.MustGetDefaultAccount()
	govModuleAddress, err := c.GetModuleAccountByName(ctx, govTypes.ModuleName)
	if err != nil {
		return 0, "", err
	}
	if opts.ProposalDepositAmount.IsNil() {
		opts.ProposalDepositAmount = math.NewIntWithDecimal(1, gnfdSdkTypes.DecimalBNB)
	}
	if opts.ReadPrice.IsNil() {
		opts.ReadPrice = sdk.NewDec(1)
	}
	if opts.StorePrice.IsNil() {
		opts.StorePrice = sdk.NewDec(1)
	}

	fundingAcc, err := sdk.AccAddressFromHexUnsafe(fundingAddr)
	if err != nil {
		return 0, "", err
	}
	sealAcc, err := sdk.AccAddressFromHexUnsafe(sealAddr)
	if err != nil {
		return 0, "", err
	}
	approvalAcc, err := sdk.AccAddressFromHexUnsafe(approvalAddr)
	if err != nil {
		return 0, "", err
	}
	gcAcc, err := sdk.AccAddressFromHexUnsafe(gcAddr)
	if err != nil {
		return 0, "", err
	}
	maintenanceAcc, err := sdk.AccAddressFromHexUnsafe(maintenanceAddr)
	if err != nil {
		return 0, "", err
	}
	blsPubKeyBz, err := hex.DecodeString(blsPubKey)
	if err != nil {
		return 0, "", err
	}
	_, err = bls.PublicKeyFromBytes(blsPubKeyBz)
	if err != nil {
		return 0, "", err
	}
	msgCreateStorageProvider, err := spTypes.NewMsgCreateStorageProvider(
		govModuleAddress.GetAddress(),
		defaultAccount.GetAddress(),
		fundingAcc, sealAcc, approvalAcc, gcAcc, maintenanceAcc,
		description,
		endpoint,
		sdk.NewCoin(gnfdSdkTypes.Denom, depositAmount),
		opts.ReadPrice,
		opts.FreeReadQuota,
		opts.StorePrice,
		blsPubKey,
		blsProof,
	)
	if err != nil {
		return 0, "", err
	}
	err = msgCreateStorageProvider.ValidateBasic()
	if err != nil {
		return 0, "", err
	}

	return c.SubmitProposal(ctx, []sdk.Msg{msgCreateStorageProvider}, opts.ProposalDepositAmount, opts.ProposalTitle, opts.ProposalSummary, types.SubmitProposalOptions{Metadata: opts.ProposalMetaData, TxOpts: opts.TxOpts})
}

// GrantDepositForStorageProvider - Grant transaction to allow Gov module account to deduct the specified number of tokens.
//
// - ctx: Context variables for the current API call.
//
// - spAddr: The HEX-encoded string of the storage provider address.
//
// - depositAmount: The allowance of fee that allows grantee to spend up from the account of Granter.
//
// - opts: The options for customizing the transaction.
//
// - ret1: Transaction hash return from blockchain.
//
// - ret2: Return error when the request failed, otherwise return nil.
func (c *Client) GrantDepositForStorageProvider(ctx context.Context, spAddr string, depositAmount math.Int, opts types.GrantDepositForStorageProviderOptions) (string, error) {
	granter := c.MustGetDefaultAccount()
	govModuleAddress, err := c.GetModuleAccountByName(ctx, govTypes.ModuleName)
	if err != nil {
		return "", err
	}
	spAcc, err := sdk.AccAddressFromHexUnsafe(spAddr)
	if err != nil {
		return "", err
	}
	coin := sdk.NewCoin(gnfdSdkTypes.Denom, depositAmount)
	authorization := spTypes.NewDepositAuthorization(spAcc, &coin)

	if opts.Expiration == nil {
		expiration := time.Now().Add(24 * time.Hour)
		opts.Expiration = &expiration
	}
	msgGrant, err := authz.NewMsgGrant(granter.GetAddress(), govModuleAddress.GetAddress(), authorization, opts.Expiration)
	if err != nil {
		return "", err
	}
	resp, err := c.BroadcastTx(ctx, []sdk.Msg{msgGrant}, &opts.TxOpts)
	if err != nil {
		return "", err
	}
	return resp.TxResponse.TxHash, nil
}

// UpdateSpStoragePrice - Update the read price, storage price and free read quota for a particular storage provider. The sender must be the Storage provider's operator address, and SP must be STATUS_IN_SERVICE.
//
// - ctx: Context variables for the current API call.
//
// - spAddr: The HEX-encoded string of the storage provider address.
//
// - readPrice: The read price of the SP, in bnb wei per charge byte.
//
// - storePrice: The store price of the SP, in bnb wei per charge byte.
//
// - freeReadQuota: The free read quota of the SP.
//
// - TxOption: The options for customizing the transaction.
//
// - ret1: Transaction hash return from blockchain.
//
// - ret2: Return error when the request failed, otherwise return nil.
func (c *Client) UpdateSpStoragePrice(ctx context.Context, spAddr string, readPrice, storePrice sdk.Dec, freeReadQuota uint64, TxOption gnfdSdkTypes.TxOption) (string, error) {
	spAcc, err := sdk.AccAddressFromHexUnsafe(spAddr)
	if err != nil {
		return "", err
	}
	msgUpdateStoragePrice := &spTypes.MsgUpdateSpStoragePrice{
		SpAddress:     spAcc.String(),
		ReadPrice:     readPrice,
		StorePrice:    storePrice,
		FreeReadQuota: freeReadQuota,
	}
	resp, err := c.BroadcastTx(ctx, []sdk.Msg{msgUpdateStoragePrice}, &TxOption)
	if err != nil {
		return "", err
	}
	return resp.TxResponse.TxHash, nil
}

// UpdateSpStatus - Set an SP status between STATUS_IN_SERVICE and STATUS_IN_MAINTENANCE. The sender must be the Storage provider's operator address.
//
// - ctx: Context variables for the current API call.
//
// - spAddr: The HEX-encoded string of the storage provider address.
//
// - status: The desired status.
//
// - duration: duration is requested time(in second) an SP wish to stay in maintenance mode, for setting to STATUS_IN_SERVICE, duration is set to 0.
//
// - TxOption: The options for customizing the transaction.
//
// - ret1: Transaction hash return from blockchain.
//
// - ret2: Return error when the request failed, otherwise return nil.
func (c *Client) UpdateSpStatus(ctx context.Context, spAddr string, status spTypes.Status, duration int64, TxOption gnfdSdkTypes.TxOption) (string, error) {
	spAcc, err := sdk.AccAddressFromHexUnsafe(spAddr)
	if err != nil {
		return "", err
	}
	msgUpdateSpStatus := &spTypes.MsgUpdateStorageProviderStatus{
		SpAddress: spAcc.String(),
		Status:    status,
		Duration:  duration,
	}
	resp, err := c.BroadcastTx(ctx, []sdk.Msg{msgUpdateSpStatus}, &TxOption)
	if err != nil {
		return "", err
	}
	return resp.TxResponse.TxHash, nil
}
