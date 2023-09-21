package client

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/cometbft/cometbft/votepool"
	"github.com/cosmos/cosmos-sdk/client/grpc/tmservice"

	"cosmossdk.io/errors"
	gosdktypes "github.com/bnb-chain/greenfield-go-sdk/types"
	"github.com/bnb-chain/greenfield/sdk/types"
	"github.com/cometbft/cometbft/proto/tendermint/p2p"
	ctypes "github.com/cometbft/cometbft/rpc/core/types"
	bfttypes "github.com/cometbft/cometbft/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/cosmos/cosmos-sdk/types/tx"
	"google.golang.org/grpc"
)

// IBasicClient interface defines basic functions of greenfield Client.
type IBasicClient interface {
	EnableTrace(outputStream io.Writer, onlyTraceErr bool)

	GetNodeInfo(ctx context.Context) (*p2p.DefaultNodeInfo, *tmservice.VersionInfo, error)

	GetStatus(ctx context.Context) (*ctypes.ResultStatus, error)
	GetCommit(ctx context.Context, height int64) (*ctypes.ResultCommit, error)
	GetLatestBlockHeight(ctx context.Context) (int64, error)
	GetLatestBlock(ctx context.Context) (*bfttypes.Block, error)
	GetSyncing(ctx context.Context) (bool, error)
	GetBlockByHeight(ctx context.Context, height int64) (*bfttypes.Block, error)
	GetBlockResultByHeight(ctx context.Context, height int64) (*ctypes.ResultBlockResults, error)

	GetValidatorSet(ctx context.Context) (int64, []*bfttypes.Validator, error)
	GetValidatorsByHeight(ctx context.Context, height int64) ([]*bfttypes.Validator, error)

	WaitForBlockHeight(ctx context.Context, height int64) error
	WaitForTx(ctx context.Context, hash string) (*ctypes.ResultTx, error)
	WaitForNBlocks(ctx context.Context, n int64) error
	WaitForNextBlock(ctx context.Context) error

	SimulateTx(ctx context.Context, msgs []sdk.Msg, txOpt types.TxOption, opts ...grpc.CallOption) (*tx.SimulateResponse, error)
	SimulateRawTx(ctx context.Context, txBytes []byte, opts ...grpc.CallOption) (*tx.SimulateResponse, error)
	BroadcastTx(ctx context.Context, msgs []sdk.Msg, txOpt *types.TxOption, opts ...grpc.CallOption) (*tx.BroadcastTxResponse, error)
	BroadcastRawTx(ctx context.Context, txBytes []byte, sync bool) (*sdk.TxResponse, error)

	BroadcastVote(ctx context.Context, vote votepool.Vote) error
	QueryVote(ctx context.Context, eventType int, eventHash []byte) (*ctypes.ResultQueryVote, error)
}

// EnableTrace support trace error info the request and the response
func (c *Client) EnableTrace(output io.Writer, onlyTraceErr bool) {
	if output == nil {
		output = os.Stdout
	}

	c.onlyTraceError = onlyTraceErr

	c.traceOutput = output
	c.isTraceEnabled = true
}

// GetNodeInfo returns the current node info of the greenfield that the Client is connected to.
// It takes a context as input and returns a ResultStatus object and an error (if any).
func (c *Client) GetNodeInfo(ctx context.Context) (*p2p.DefaultNodeInfo, *tmservice.VersionInfo, error) {
	nodeInfoResponse, err := c.chainClient.TmClient.GetNodeInfo(ctx, &tmservice.GetNodeInfoRequest{})
	if err != nil {
		return nil, nil, err
	}
	return nodeInfoResponse.DefaultNodeInfo, nodeInfoResponse.ApplicationVersion, nil
}

func (c *Client) GetStatus(ctx context.Context) (*ctypes.ResultStatus, error) {
	return c.chainClient.GetStatus(ctx)
}

func (c *Client) GetCommit(ctx context.Context, height int64) (*ctypes.ResultCommit, error) {
	return c.chainClient.GetCommit(ctx, height)
}

// BroadcastRawTx broadcasts raw transaction bytes to a Tendermint node.
// It takes a context, transaction bytes, and a sync boolean.
// If sync is true, the transaction is broadcast synchronously.
// If sync is false, the transaction is broadcast asynchronously.
func (c *Client) BroadcastRawTx(ctx context.Context, txBytes []byte, sync bool) (*sdk.TxResponse, error) {
	var mode tx.BroadcastMode
	if sync {
		mode = tx.BroadcastMode_BROADCAST_MODE_SYNC
	} else {
		mode = tx.BroadcastMode_BROADCAST_MODE_ASYNC
	}
	broadcastTxResponse, err := c.chainClient.TxClient.BroadcastTx(ctx, &tx.BroadcastTxRequest{TxBytes: txBytes, Mode: mode})
	if err != nil {
		return nil, err
	}
	return broadcastTxResponse.TxResponse, nil
}

// SimulateRawTx simulates the execution of a raw transaction on the blockchain without broadcasting it to the network.
// It takes a context, transaction bytes, and any additional gRPC call options.
// It returns a SimulateResponse object and an error (if any).
func (c *Client) SimulateRawTx(ctx context.Context, txBytes []byte, opts ...grpc.CallOption) (*tx.SimulateResponse, error) {
	simulateResponse, err := c.chainClient.TxClient.Simulate(
		ctx,
		&tx.SimulateRequest{
			TxBytes: txBytes,
		},
		opts...,
	)
	if err != nil {
		return nil, err
	}
	return simulateResponse, nil
}

// GetLatestBlock retrieves the latest block from the chain.
// The function returns a pointer to a Block object and any error that occurred during the operation.
func (c *Client) GetLatestBlock(ctx context.Context) (*bfttypes.Block, error) {
	res, err := c.chainClient.GetBlock(ctx, nil)
	if err != nil {
		return nil, err
	}
	return res.Block, nil
}

// GetLatestBlockHeight retrieves the height of the latest block from the chain.
// The function returns the block height and any error that occurred during the operation.
func (c *Client) GetLatestBlockHeight(ctx context.Context) (int64, error) {
	resp, err := c.GetLatestBlock(ctx)
	if err != nil {
		return 0, nil
	}
	return resp.Header.Height, nil
}

// WaitForBlockHeight waits until block height h is committed, or returns an
// error if ctx is canceled.
func (c *Client) WaitForBlockHeight(ctx context.Context, h int64) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		latestBlockHeight, err := c.GetLatestBlockHeight(ctx)
		if err != nil {
			return err
		}
		if latestBlockHeight >= h {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.Wrap(ctx.Err(), "timeout exceeded waiting for block")
		case <-ticker.C:
		}
	}
}

// WaitForNextBlock waits until next block is committed.
// It reads the current block height and then waits for another block to be
// committed, or returns an error if ctx is canceled.
func (c *Client) WaitForNextBlock(ctx context.Context) error {
	return c.WaitForNBlocks(ctx, 1)
}

// WaitForNBlocks reads the current block height and then waits for another n
// blocks to be committed, or returns an error if ctx is canceled.
func (c *Client) WaitForNBlocks(ctx context.Context, n int64) error {
	start, err := c.GetLatestBlock(ctx)
	if err != nil {
		return err
	}
	return c.WaitForBlockHeight(ctx, start.Header.Height+n)
}

// WaitForTx requests the tx from hash, if not found, waits for next block and
// tries again. Returns an error if ctx is canceled.
func (c *Client) WaitForTx(ctx context.Context, hash string) (*ctypes.ResultTx, error) {
	for {
		var (
			txResponse *ctypes.ResultTx
			err        error
			waitTxCtx  context.Context
			cancelFunc context.CancelFunc
		)

		// when websocket conn is used, use a short timeout context to achieve the retry mechanism
		if c.useWebsocketConn {
			waitTxCtx, cancelFunc = context.WithTimeout(context.Background(), gosdktypes.WaitTxContextTimeOut)
			txResponse, err = c.chainClient.Tx(waitTxCtx, hash)
			cancelFunc()
		} else {
			txResponse, err = c.chainClient.Tx(ctx, hash)
		}
		if err != nil {
			// Tx not found, wait for next block and try again
			// If websocket conn is enabled, we also want to re-try the GetTx calls by having a timeout context
			if strings.Contains(err.Error(), "not found") || (c.useWebsocketConn && (waitTxCtx.Err() == context.DeadlineExceeded)) {

				err := c.WaitForNextBlock(ctx)
				if err != nil {
					return nil, errors.Wrap(err, "waiting for next block")
				}
				continue
			}
			return nil, errors.Wrapf(err, "fetching tx '%s'", hash)
		}
		// `nil` could mean the transaction is in the mempool, invalidated, or was not sent in the first place.
		if txResponse == nil {
			err := c.WaitForNextBlock(ctx)
			if err != nil {
				return nil, errors.Wrap(err, "waiting for next block")
			}
			continue
		}
		// Tx found
		return txResponse, nil
	}
}

// BroadcastTx broadcasts a transaction containing the provided messages to the chain.
// The function returns a pointer to a BroadcastTxResponse and any error that occurred during the operation.
func (c *Client) BroadcastTx(ctx context.Context, msgs []sdk.Msg, txOpt *types.TxOption, opts ...grpc.CallOption) (*tx.BroadcastTxResponse, error) {
	resp, err := c.chainClient.BroadcastTx(ctx, msgs, txOpt, opts...)
	if err != nil {
		return nil, err
	}
	if resp.TxResponse.Code != 0 {
		return resp, fmt.Errorf("the tx has failed with response code: %d, codespace:%s", resp.TxResponse.Code, resp.TxResponse.Codespace)
	}
	return resp, nil
}

// SimulateTx simulates a transaction containing the provided messages on the chain.
// The function returns a pointer to a SimulateResponse and any error that occurred during the operation.
func (c *Client) SimulateTx(ctx context.Context, msgs []sdk.Msg, txOpt types.TxOption, opts ...grpc.CallOption) (*tx.SimulateResponse, error) {
	return c.chainClient.SimulateTx(ctx, msgs, &txOpt, opts...)
}

// GetSyncing retrieves the syncing status of the node. If true, means the node is catching up the latest block.
// The function returns a boolean indicating whether the node is syncing and any error that occurred during the operation.
func (c *Client) GetSyncing(ctx context.Context) (bool, error) {
	syncing, err := c.chainClient.GetSyncing(ctx, &tmservice.GetSyncingRequest{})
	if err != nil {
		return false, err
	}
	return syncing.Syncing, nil
}

// GetBlockByHeight retrieves the block at the given height from the chain.
// The function returns a pointer to a Block object and any error that occurred during the operation.
func (c *Client) GetBlockByHeight(ctx context.Context, height int64) (*bfttypes.Block, error) {
	blockByHeight, err := c.chainClient.GetBlock(ctx, &height)
	if err != nil {
		return nil, err
	}
	return blockByHeight.Block, nil
}

func (c *Client) GetBlockResultByHeight(ctx context.Context, height int64) (*ctypes.ResultBlockResults, error) {
	return c.chainClient.GetBlockResults(ctx, &height)
}

// GetValidatorSet retrieves the latest validator set from the chain.
func (c *Client) GetValidatorSet(ctx context.Context) (int64, []*bfttypes.Validator, error) {
	validatorSetResponse, err := c.chainClient.GetValidators(ctx, nil)
	if err != nil {
		return 0, nil, err
	}
	return validatorSetResponse.BlockHeight, validatorSetResponse.Validators, nil
}

// GetValidatorsByHeight retrieves the validator set from the chain.
func (c *Client) GetValidatorsByHeight(ctx context.Context, height int64) ([]*bfttypes.Validator, error) {
	validatorSetResponse, err := c.chainClient.GetValidators(ctx, &height)
	if err != nil {
		return nil, err
	}
	return validatorSetResponse.Validators, nil
}

func (c *Client) BroadcastVote(ctx context.Context, vote votepool.Vote) error {
	return c.chainClient.BroadcastVote(ctx, vote)
}

func (c *Client) QueryVote(ctx context.Context, eventType int, eventHash []byte) (*ctypes.ResultQueryVote, error) {
	return c.chainClient.QueryVote(ctx, eventType, eventHash)
}
