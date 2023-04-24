package client

import (
	"context"
	"strconv"
	"time"

	"cosmossdk.io/math"
	"github.com/bnb-chain/greenfield-go-sdk/types"
	gnfdSdkTypes "github.com/bnb-chain/greenfield/sdk/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	govTypes "github.com/cosmos/cosmos-sdk/x/gov/types"
	govTypesV1 "github.com/cosmos/cosmos-sdk/x/gov/types/v1"
)

type SubmitProposalOptions struct {
	Metadata string
	TxOption gnfdSdkTypes.TxOption
}

type Proposal interface {
	SubmitProposal(ctx context.Context, msgs []sdk.Msg, depositAmount math.Int, opts SubmitProposalOptions) (uint64, string, error)
	VoteProposal(ctx context.Context, proposalID uint64, voteOption govTypesV1.VoteOption, opts VoteProposalOptions) (string, error)
	GetProposal(ctx context.Context, proposalID uint64) (*govTypesV1.Proposal, error)
}

func (c *client) SubmitProposal(ctx context.Context, msgs []sdk.Msg, depositAmount math.Int, opts SubmitProposalOptions) (uint64, string, error) {
	msgSubmitProposal, err := govTypesV1.NewMsgSubmitProposal(msgs, sdk.NewCoins(sdk.NewCoin(gnfdSdkTypes.Denom, depositAmount)), c.defaultAccount.GetAddress().String(), opts.Metadata, "test", "test", false)
	if err != nil {
		return 0, "", err
	}
	err = msgSubmitProposal.ValidateBasic()
	if err != nil {
		return 0, "", err
	}
	txResp, err := c.chainClient.BroadcastTx(ctx, []sdk.Msg{msgSubmitProposal}, &opts.TxOption)
	if err != nil {
		return 0, "", err
	}
	waitCtx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()
	waitForTx, err := c.WaitForTx(waitCtx, txResp.TxResponse.TxHash)
	if err != nil {
		return 0, "", err
	}

	key := govTypes.AttributeKeyProposalID
	for _, logs := range waitForTx.Logs {
		for _, event := range logs.Events {
			for _, attr := range event.Attributes {
				if attr.Key == key {
					proposalID, err := strconv.ParseUint(attr.Value, 10, 64)
					if err != nil {
						return 0, txResp.TxResponse.TxHash, err
					}
					return proposalID, txResp.TxResponse.TxHash, nil
				}
			}
		}
	}
	return 0, txResp.TxResponse.TxHash, types.ErrorProposalIDNotFound
}

type VoteProposalOptions struct {
	Metadata string
	TxOption gnfdSdkTypes.TxOption
}

func (c *client) VoteProposal(ctx context.Context, proposalID uint64, voteOption govTypesV1.VoteOption, opts VoteProposalOptions) (string, error) {
	msgVote := govTypesV1.NewMsgVote(c.MustGetDefaultAccount().GetAddress(), proposalID, voteOption, opts.Metadata)
	resp, err := c.chainClient.BroadcastTx(ctx, []sdk.Msg{msgVote}, &opts.TxOption)
	if err != nil {
		return "", err
	}
	return resp.TxResponse.TxHash, nil
}

func (c *client) GetProposal(ctx context.Context, proposalID uint64) (*govTypesV1.Proposal, error) {
	resp, err := c.chainClient.GovQueryClientV1.Proposal(ctx, &govTypesV1.QueryProposalRequest{ProposalId: proposalID})
	if err != nil {
		return nil, nil
	}
	return resp.Proposal, nil

}
