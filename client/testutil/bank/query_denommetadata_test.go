package bank

import (
	"context"
	gnfdclient "github.com/bnb-chain/gnfd-go-sdk/client/grpc"
	"github.com/bnb-chain/gnfd-go-sdk/keys"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestBankDenomMetadata(t *testing.T) {
	km, err := keys.NewPrivateKeyManager("e3ac46e277677f0f103774019d03bd89c7b4b5ecc554b2650bd5d5127992c20c")
	assert.NoError(t, err)
	client := gnfdclient.NewGreenlandClientWithKeyManager("localhost:9090", "greenfield_9000-121", km)

	query := banktypes.QueryDenomMetadataRequest{
		Denom:   "bnb",
	}
	res, err := client.BankQueryClient.DenomMetadata(context.Background(), &query)
	assert.NoError(t, err)

	println(res.Metadata)
	println(res.GetMetadata())
	println(res.String())
}
