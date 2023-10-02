package blockvalidation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"

	bellatrixapi "github.com/attestantio/go-builder-client/api/bellatrix"
	capellaapi "github.com/attestantio/go-builder-client/api/capella"
	"github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	bellatrixUtil "github.com/attestantio/go-eth2-client/util/bellatrix"
	"github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/misc"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/utils"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/eth"
	"github.com/ethereum/go-ethereum/eth/tracers/logger"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/miner"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/rpc"
)

type BlacklistedAddresses []common.Address

type AccessVerifier struct {
	blacklistedAddresses map[common.Address]struct{}
}

func (a *AccessVerifier) verifyTraces(tracer *logger.AccessListTracer) error {
	log.Trace("x", "tracer.AccessList()", tracer.AccessList())
	for _, accessTuple := range tracer.AccessList() {
		// TODO: should we ignore common.Address{}?
		if _, found := a.blacklistedAddresses[accessTuple.Address]; found {
			log.Info("bundle accesses blacklisted address", "address", accessTuple.Address)
			return fmt.Errorf("blacklisted address %s in execution trace", accessTuple.Address.String())
		}
	}

	return nil
}

func (a *AccessVerifier) isBlacklisted(addr common.Address) error {
	if _, present := a.blacklistedAddresses[addr]; present {
		return fmt.Errorf("transaction from blacklisted address %s", addr.String())
	}
	return nil
}

func (a *AccessVerifier) verifyTransactions(signer types.Signer, txs types.Transactions) error {
	for _, tx := range txs {
		from, err := types.Sender(signer, tx)
		if err == nil {
			if _, present := a.blacklistedAddresses[from]; present {
				return fmt.Errorf("transaction from blacklisted address %s", from.String())
			}
		}
		to := tx.To()
		if to != nil {
			if _, present := a.blacklistedAddresses[*to]; present {
				return fmt.Errorf("transaction to blacklisted address %s", to.String())
			}
		}
	}
	return nil
}

func NewAccessVerifierFromFile(path string) (*AccessVerifier, error) {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var ba BlacklistedAddresses
	if err := json.Unmarshal(bytes, &ba); err != nil {
		return nil, err
	}

	blacklistedAddresses := make(map[common.Address]struct{}, len(ba))
	for _, address := range ba {
		blacklistedAddresses[address] = struct{}{}
	}

	return &AccessVerifier{
		blacklistedAddresses: blacklistedAddresses,
	}, nil
}

type BlockValidationConfig struct {
	BlacklistSourceFilePath string
	// If set to true, proposer payment is assumed to be in the last transaction of the block.
	ForceLastTxPayment bool
}

// Register adds catalyst APIs to the full node.
func Register(stack *node.Node, backend *eth.Ethereum, cfg BlockValidationConfig) error {
	var accessVerifier *AccessVerifier
	if cfg.BlacklistSourceFilePath != "" {
		var err error
		accessVerifier, err = NewAccessVerifierFromFile(cfg.BlacklistSourceFilePath)
		if err != nil {
			return err
		}
	}

	stack.RegisterAPIs([]rpc.API{
		{
			Namespace: "flashbots",
			Service:   NewBlockValidationAPI(backend, accessVerifier, cfg.ForceLastTxPayment),
		},
	})
	return nil
}

type BlockValidationAPI struct {
	eth            *eth.Ethereum
	accessVerifier *AccessVerifier
	// If set to true, proposer payment is assumed to be in the last transaction of the block.
	forceLastTxPayment bool
}

// NewConsensusAPI creates a new consensus api for the given backend.
// The underlying blockchain needs to have a valid terminal total difficulty set.
func NewBlockValidationAPI(eth *eth.Ethereum, accessVerifier *AccessVerifier, forceLastTxPayment bool) *BlockValidationAPI {
	return &BlockValidationAPI{
		eth:                eth,
		accessVerifier:     accessVerifier,
		forceLastTxPayment: forceLastTxPayment,
	}
}

type BuilderBlockValidationRequest struct {
	bellatrixapi.SubmitBlockRequest
	RegisteredGasLimit uint64 `json:"registered_gas_limit,string"`
}

func (api *BlockValidationAPI) ValidateBuilderSubmissionV1(params *BuilderBlockValidationRequest) error {
	// TODO: fuzztest, make sure the validation is sound
	// TODO: handle context!

	if params.ExecutionPayload == nil {
		return errors.New("nil execution payload")
	}
	payload := params.ExecutionPayload
	block, err := engine.ExecutionPayloadToBlock(payload)
	if err != nil {
		return err
	}

	if params.Message.ParentHash != phase0.Hash32(block.ParentHash()) {
		return fmt.Errorf("incorrect ParentHash %s, expected %s", params.Message.ParentHash.String(), block.ParentHash().String())
	}

	if params.Message.BlockHash != phase0.Hash32(block.Hash()) {
		return fmt.Errorf("incorrect BlockHash %s, expected %s", params.Message.BlockHash.String(), block.Hash().String())
	}

	if params.Message.GasLimit != block.GasLimit() {
		return fmt.Errorf("incorrect GasLimit %d, expected %d", params.Message.GasLimit, block.GasLimit())
	}

	if params.Message.GasUsed != block.GasUsed() {
		return fmt.Errorf("incorrect GasUsed %d, expected %d", params.Message.GasUsed, block.GasUsed())
	}

	feeRecipient := common.BytesToAddress(params.Message.ProposerFeeRecipient[:])
	expectedProfit := params.Message.Value.ToBig()

	var vmconfig vm.Config
	var tracer *logger.AccessListTracer = nil
	if api.accessVerifier != nil {
		if err := api.accessVerifier.isBlacklisted(block.Coinbase()); err != nil {
			return err
		}
		if err := api.accessVerifier.isBlacklisted(feeRecipient); err != nil {
			return err
		}
		if err := api.accessVerifier.verifyTransactions(types.LatestSigner(api.eth.BlockChain().Config()), block.Transactions()); err != nil {
			return err
		}
		isPostMerge := true // the call is PoS-native
		timestamp := params.SubmitBlockRequest.ExecutionPayload.Timestamp
		precompiles := vm.ActivePrecompiles(api.eth.APIBackend.ChainConfig().Rules(new(big.Int).SetUint64(params.ExecutionPayload.BlockNumber), isPostMerge, timestamp))
		tracer = logger.NewAccessListTracer(nil, common.Address{}, common.Address{}, precompiles)
		vmconfig = vm.Config{Tracer: tracer, Debug: true}
	}

	err = api.eth.BlockChain().ValidatePayload(block, feeRecipient, expectedProfit, params.RegisteredGasLimit, vmconfig, api.forceLastTxPayment)
	if err != nil {
		log.Error("invalid payload", "hash", payload.BlockHash.String(), "number", payload.BlockNumber, "parentHash", payload.ParentHash.String(), "err", err)
		return err
	}

	if api.accessVerifier != nil && tracer != nil {
		if err := api.accessVerifier.verifyTraces(tracer); err != nil {
			return err
		}
	}

	log.Info("validated block", "hash", block.Hash(), "number", block.NumberU64(), "parentHash", block.ParentHash())
	return nil
}

type BuilderBlockValidationRequestV2 struct {
	capellaapi.SubmitBlockRequest
	RegisteredGasLimit uint64      `json:"registered_gas_limit,string"`
	WithdrawalsRoot    common.Hash `json:"withdrawals_root"`
}

func (r *BuilderBlockValidationRequestV2) UnmarshalJSON(data []byte) error {
	params := &struct {
		RegisteredGasLimit uint64      `json:"registered_gas_limit,string"`
		WithdrawalsRoot    common.Hash `json:"withdrawals_root"`
	}{}
	err := json.Unmarshal(data, params)
	if err != nil {
		return err
	}
	r.RegisteredGasLimit = params.RegisteredGasLimit
	r.WithdrawalsRoot = params.WithdrawalsRoot

	blockRequest := new(capellaapi.SubmitBlockRequest)
	err = json.Unmarshal(data, &blockRequest)
	if err != nil {
		return err
	}
	r.SubmitBlockRequest = *blockRequest
	return nil
}

func (api *BlockValidationAPI) ValidateBuilderSubmissionV2(params *BuilderBlockValidationRequestV2) error {
	// TODO: fuzztest, make sure the validation is sound
	// TODO: handle context!
	if params.ExecutionPayload == nil {
		return errors.New("nil execution payload")
	}
	payload := params.ExecutionPayload
	block, err := engine.ExecutionPayloadV2ToBlock(payload)
	if err != nil {
		return err
	}

	if params.Message.ParentHash != phase0.Hash32(block.ParentHash()) {
		return fmt.Errorf("incorrect ParentHash %s, expected %s", params.Message.ParentHash.String(), block.ParentHash().String())
	}

	if params.Message.BlockHash != phase0.Hash32(block.Hash()) {
		return fmt.Errorf("incorrect BlockHash %s, expected %s", params.Message.BlockHash.String(), block.Hash().String())
	}

	if params.Message.GasLimit != block.GasLimit() {
		return fmt.Errorf("incorrect GasLimit %d, expected %d", params.Message.GasLimit, block.GasLimit())
	}

	if params.Message.GasUsed != block.GasUsed() {
		return fmt.Errorf("incorrect GasUsed %d, expected %d", params.Message.GasUsed, block.GasUsed())
	}

	feeRecipient := common.BytesToAddress(params.Message.ProposerFeeRecipient[:])
	expectedProfit := params.Message.Value.ToBig()

	var vmconfig vm.Config
	var tracer *logger.AccessListTracer = nil
	if api.accessVerifier != nil {
		if err := api.accessVerifier.isBlacklisted(block.Coinbase()); err != nil {
			return err
		}
		if err := api.accessVerifier.isBlacklisted(feeRecipient); err != nil {
			return err
		}
		if err := api.accessVerifier.verifyTransactions(types.LatestSigner(api.eth.BlockChain().Config()), block.Transactions()); err != nil {
			return err
		}
		isPostMerge := true // the call is PoS-native
		precompiles := vm.ActivePrecompiles(api.eth.APIBackend.ChainConfig().Rules(new(big.Int).SetUint64(params.ExecutionPayload.BlockNumber), isPostMerge, params.ExecutionPayload.Timestamp))
		tracer = logger.NewAccessListTracer(nil, common.Address{}, common.Address{}, precompiles)
		vmconfig = vm.Config{Tracer: tracer, Debug: true}
	}

	err = api.eth.BlockChain().ValidatePayload(block, feeRecipient, expectedProfit, params.RegisteredGasLimit, vmconfig, api.forceLastTxPayment)
	if err != nil {
		log.Error("invalid payload", "hash", payload.BlockHash.String(), "number", payload.BlockNumber, "parentHash", payload.ParentHash.String(), "err", err)
		return err
	}

	if api.accessVerifier != nil && tracer != nil {
		if err := api.accessVerifier.verifyTraces(tracer); err != nil {
			return err
		}
	}

	log.Info("validated block", "hash", block.Hash(), "number", block.NumberU64(), "parentHash", block.ParentHash())
	return nil
}

type TobValidationRequest struct {
	TobTxs               bellatrixUtil.ExecutionPayloadTransactions
	ParentHash           string
	ProposerFeeRecipient string
}

type IntermediateTobValidationRequest struct {
	TobTxs               []byte `json:"tob_txs"`
	ParentHash           string `json:"parent_hash"`
	ProposerFeeRecipient string `json:"proposer_fee_recipient"`
}

func (t *TobValidationRequest) MarshalJson() ([]byte, error) {
	sszedTobTxs, err := t.TobTxs.MarshalSSZ()
	if err != nil {
		return nil, err
	}

	intermediateStruct := IntermediateTobValidationRequest{
		TobTxs:               sszedTobTxs,
		ParentHash:           t.ParentHash,
		ProposerFeeRecipient: t.ProposerFeeRecipient,
	}

	return json.Marshal(intermediateStruct)
}

func (t *TobValidationRequest) UnmarshalJson(data []byte) error {
	var intermediateJson IntermediateTobValidationRequest
	err := json.Unmarshal(data, &intermediateJson)
	if err != nil {
		return err
	}

	err = t.TobTxs.UnmarshalSSZ(intermediateJson.TobTxs)
	if err != nil {
		return err
	}
	t.ParentHash = intermediateJson.ParentHash

	return nil
}

func (api *BlockValidationAPI) ValidateTobSubmission(params *TobValidationRequest) error {
	parentBlock, err := api.eth.APIBackend.BlockByHash(context.Background(), common.HexToHash(params.ParentHash))
	if err != nil {
		return err
	}

	statedb, parentHeader, err := api.eth.APIBackend.StateAndHeaderByNumber(context.Background(), rpc.BlockNumber(parentBlock.NumberU64()))
	if err != nil {
		return fmt.Errorf("failed to get parent block header: %w", err)
	}
	header := types.Header{
		ParentHash: parentHeader.Hash(),
		Number:     new(big.Int).Add(parentHeader.Number, common.Big1),
		GasLimit:   parentHeader.GasLimit,
		Time:       parentHeader.Time + 12,
		Difficulty: new(big.Int).Set(parentHeader.Difficulty),
		Coinbase:   parentHeader.Coinbase,
		BaseFee:    misc.CalcBaseFee(api.eth.APIBackend.ChainConfig(), parentHeader),
	}
	gp := new(core.GasPool).AddGas(header.GasLimit)

	transactionBytes := make([][]byte, len(params.TobTxs.Transactions))
	for i, txHexBytes := range params.TobTxs.Transactions {
		transactionBytes[i] = txHexBytes[:]
	}
	decodedTobTxs, err := engine.DecodeTransactions(transactionBytes)
	if err != nil {
		return err
	}

	// check if payout tx is present at the end
	payoutTx := decodedTobTxs[len(decodedTobTxs)-1]
	if payoutTx.To() != nil && payoutTx.To().String() != params.ProposerFeeRecipient {
		return fmt.Errorf("payout tx recipient %s does not match proposer fee recipient %s", payoutTx.To().String(), params.ProposerFeeRecipient)
	}
	if payoutTx.Data() != nil {
		return fmt.Errorf("payout tx data is malformed")
	}
	if payoutTx.Value().Cmp(big.NewInt(0)) == 0 {
		return fmt.Errorf("payout tx value is zero")
	}

	for i, tx := range decodedTobTxs {
		if tx.To() == nil {
			return fmt.Errorf("tx: %s is a contract creation tx. ontract creation txs are not allowed", tx.Hash())
		}
		statedb.SetTxContext(tx.Hash(), i)
		tmpGasUsed := uint64(0)
		receipt, err := core.ApplyTransaction(api.eth.APIBackend.ChainConfig(), api.eth.BlockChain(), &header.Coinbase, gp, statedb, &header, tx, &tmpGasUsed, vm.Config{}, nil)
		if err != nil {
			return err
		}
		if receipt.Status != types.ReceiptStatusSuccessful {
			return fmt.Errorf("tx with hash %s reverted", tx.Hash())
		}
	}

	return nil
}

type BlockAssemblerRequest struct {
	TobTxs             bellatrixUtil.ExecutionPayloadTransactions
	RobPayload         capellaapi.SubmitBlockRequest
	RegisteredGasLimit uint64
}

type IntermediateBlockAssemblerRequest struct {
	TobTxs             []byte `json:"tob_txs"`
	RobPayload         []byte `json:"rob_payload"`
	RegisteredGasLimit uint64 `json:"registered_gas_limit,string"`
}

func (r *BlockAssemblerRequest) MarshalJSON() ([]byte, error) {
	sszedTobTxs, err := r.TobTxs.MarshalSSZ()
	if err != nil {
		return nil, err
	}
	encodedRobPayload, err := r.RobPayload.MarshalJSON()
	if err != nil {
		return nil, err
	}
	intermediateStruct := IntermediateBlockAssemblerRequest{
		TobTxs:             sszedTobTxs,
		RobPayload:         encodedRobPayload,
		RegisteredGasLimit: r.RegisteredGasLimit,
	}

	return json.Marshal(intermediateStruct)
}

func (b *BlockAssemblerRequest) UnmarshalJSON(data []byte) error {
	var intermediateJson IntermediateBlockAssemblerRequest
	err := json.Unmarshal(data, &intermediateJson)
	if err != nil {
		return err
	}
	err = b.TobTxs.UnmarshalSSZ(intermediateJson.TobTxs)
	if err != nil {
		return err
	}
	b.RegisteredGasLimit = intermediateJson.RegisteredGasLimit
	blockRequest := new(capellaapi.SubmitBlockRequest)
	err = json.Unmarshal(intermediateJson.RobPayload, &blockRequest)
	if err != nil {
		return err
	}
	b.RobPayload = *blockRequest

	return nil
}

func (api *BlockValidationAPI) BlockAssembler(params *BlockAssemblerRequest) (*capella.ExecutionPayload, error) {
	log.Info("BlockAssembler", "tobTxs", len(params.TobTxs.Transactions), "robPayload", params.RobPayload)
	transactionBytes := make([][]byte, len(params.TobTxs.Transactions))
	for i, txHexBytes := range params.TobTxs.Transactions {
		transactionBytes[i] = txHexBytes[:]
	}
	decodedTobTxs, err := engine.DecodeTransactions(transactionBytes)
	if err != nil {
		return nil, err
	}

	robBlock, err := engine.ExecutionPayloadV2ToBlock(params.RobPayload.ExecutionPayload)
	if err != nil {
		return nil, err
	}

	tobTxs := types.Transactions(decodedTobTxs)

	withdrawals := make(types.Withdrawals, len(params.RobPayload.ExecutionPayload.Withdrawals))
	for i, withdrawal := range params.RobPayload.ExecutionPayload.Withdrawals {
		withdrawals[i] = &types.Withdrawal{
			Index:     uint64(withdrawal.Index),
			Validator: uint64(withdrawal.ValidatorIndex),
			Address:   common.Address(withdrawal.Address),
			Amount:    uint64(withdrawal.Amount),
		}
	}

	robTxs := robBlock.Transactions()
	block, err := api.eth.Miner().PayloadAssembler(&miner.BuildPayloadArgs{
		Parent:       common.Hash(params.RobPayload.ExecutionPayload.ParentHash),
		Timestamp:    params.RobPayload.ExecutionPayload.Timestamp,
		FeeRecipient: common.Address(params.RobPayload.ExecutionPayload.FeeRecipient),
		GasLimit:     params.RegisteredGasLimit,
		Random:       params.RobPayload.ExecutionPayload.PrevRandao,
		Withdrawals:  withdrawals,
		BlockHook:    nil,
		AssemblerTxs: miner.AssemblerTxLists{
			TobTxs: &tobTxs,
			RobTxs: &robTxs,
		},
	})
	if err != nil {
		return nil, err
	}
	resolvedBlock := block.ResolveFull()
	if resolvedBlock == nil {
		return nil, errors.New("unable to resolve block")
	}
	if resolvedBlock.ExecutionPayload == nil {
		return nil, errors.New("nil execution payload")
	}

	finalPayload, err := engine.ExecutableDataToCapellaExecutionPayload(resolvedBlock.ExecutionPayload)
	if err != nil {
		return nil, err
	}

	parent := api.eth.BlockChain().GetBlockByHash(resolvedBlock.ExecutionPayload.ParentHash)
	if parent == nil {
		return nil, errors.New("parent block not found")
	}

	calculatedGasLimit := utils.CalcGasLimit(parent.GasLimit(), params.RegisteredGasLimit)
	if calculatedGasLimit != resolvedBlock.ExecutionPayload.GasLimit {
		return nil, errors.New("incorrect gas limit set")
	}

	return finalPayload, nil
}
