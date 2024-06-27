// SPDX-License-Identifier: AGPL-3.0

pragma solidity 0.8.20;

import "./lib/DepositContractV2.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/utils/SafeERC20Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC20/extensions/IERC20MetadataUpgradeable.sol";
import "../lib/TokenWrapped.sol";
import "../interfaces/IBasePolygonZkEVMGlobalExitRoot.sol";
import "../interfaces/IBridgeMessageReceiver.sol";
import "./interfaces/IPolygonZkEVMBridgeV2.sol";
import "../lib/EmergencyManager.sol";
import "../lib/GlobalExitRootLib.sol";

/**
 * PolygonZkEVMBridge that will be deployed on Ethereum and all Polygon rollups
 * Contract responsible to manage the token interactions with other networks
 */
contract PolygonZkEVMBridgeV2 is
    DepositContractV2,
    EmergencyManager,
    IPolygonZkEVMBridgeV2
{
    using SafeERC20Upgradeable for IERC20Upgradeable;

    // Wrapped Token information struct
    struct TokenInformation {
        uint32 originNetwork;
        address originTokenAddress;
    }

    // bytes4(keccak256(bytes("permit(address,address,uint256,uint256,uint8,bytes32,bytes32)")));
    bytes4 private constant _PERMIT_SIGNATURE = 0xd505accf;

    // bytes4(keccak256(bytes("permit(address,address,uint256,uint256,bool,uint8,bytes32,bytes32)")));
    bytes4 private constant _PERMIT_SIGNATURE_DAI = 0x8fcbaf0c;

    // Mainnet identifier
    uint32 private constant _MAINNET_NETWORK_ID = 0;

    // ZkEVM identifier
    uint32 private constant _ZKEVM_NETWORK_ID = 1;

    // Leaf type asset
    uint8 private constant _LEAF_TYPE_ASSET = 0;

    // Leaf type message
    uint8 private constant _LEAF_TYPE_MESSAGE = 1;

    // Nullifier offset
    uint256 private constant _MAX_LEAFS_PER_NETWORK = 2 ** 32;

    // Indicate where's the mainnet flag bit in the global index
    uint256 private constant _GLOBAL_INDEX_MAINNET_FLAG = 2 ** 64;

    // Init code of the erc20 wrapped token, to deploy a wrapped token the constructor parameters must be appended
    bytes public baseInitByteCodeWrappedToken =
        hex"61010060405234801562000011575f80fd5b5060405162001b2238038062001b22833981016040819052620000349162000282565b828260036200004483826200038d565b5060046200005382826200038d565b50503360c0525060ff811660e05246608081905262000072906200007f565b60a0525062000455915050565b5f7f8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f620000ab6200012c565b805160209182012060408051808201825260018152603160f81b90840152805192830193909352918101919091527fc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc66060820152608081018390523060a082015260c001604051602081830303815290604052805190602001209050919050565b6060600380546200013d9062000301565b80601f01602080910402602001604051908101604052809291908181526020018280546200016b9062000301565b8015620001ba5780601f106200019057610100808354040283529160200191620001ba565b820191905f5260205f20905b8154815290600101906020018083116200019c57829003601f168201915b5050505050905090565b634e487b7160e01b5f52604160045260245ffd5b5f82601f830112620001e8575f80fd5b81516001600160401b0380821115620002055762000205620001c4565b604051601f8301601f19908116603f01168101908282118183101715620002305762000230620001c4565b816040528381526020925086838588010111156200024c575f80fd5b5f91505b838210156200026f578582018301518183018401529082019062000250565b5f93810190920192909252949350505050565b5f805f6060848603121562000295575f80fd5b83516001600160401b0380821115620002ac575f80fd5b620002ba87838801620001d8565b94506020860151915080821115620002d0575f80fd5b50620002df86828701620001d8565b925050604084015160ff81168114620002f6575f80fd5b809150509250925092565b600181811c908216806200031657607f821691505b6020821081036200033557634e487b7160e01b5f52602260045260245ffd5b50919050565b601f82111562000388575f81815260208120601f850160051c81016020861015620003635750805b601f850160051c820191505b8181101562000384578281556001016200036f565b5050505b505050565b81516001600160401b03811115620003a957620003a9620001c4565b620003c181620003ba845462000301565b846200033b565b602080601f831160018114620003f7575f8415620003df5750858301515b5f19600386901b1c1916600185901b17855562000384565b5f85815260208120601f198616915b82811015620004275788860151825594840194600190910190840162000406565b50858210156200044557878501515f19600388901b60f8161c191681555b5050505050600190811b01905550565b60805160a05160c05160e0516116846200049e5f395f61023301525f8181610309015281816105c201526106a901525f61053d01525f818161037b015261050701526116845ff3fe608060405234801561000f575f80fd5b5060043610610179575f3560e01c80637ecebe00116100d2578063a9059cbb11610088578063dd62ed3e11610063578063dd62ed3e146103b0578063f8a8fd6d146103f5578063ffa1ad74146103fc575f80fd5b8063a9059cbb14610363578063cd0d009614610376578063d505accf1461039d575f80fd5b80639dc29fac116100b85780639dc29fac146102f1578063a3c573eb14610304578063a457c2d714610350575f80fd5b80637ecebe00146102ca57806395d89b41146102e9575f80fd5b806330adf81f11610132578063395093511161010d578063395093511461026d57806340c10f191461028057806370a0823114610295575f80fd5b806330adf81f1461020a578063313ce567146102315780633644e51514610265575f80fd5b806318160ddd1161016257806318160ddd146101be57806320606b70146101d057806323b872dd146101f7575f80fd5b806306fdde031461017d578063095ea7b31461019b575b5f80fd5b610185610438565b60405161019291906113d6565b60405180910390f35b6101ae6101a9366004611467565b6104c8565b6040519015158152602001610192565b6002545b604051908152602001610192565b6101c27f8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f81565b6101ae61020536600461148f565b6104e1565b6101c27f6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c981565b7f00000000000000000000000000000000000000000000000000000000000000005b60405160ff9091168152602001610192565b6101c2610504565b6101ae61027b366004611467565b61055f565b61029361028e366004611467565b6105aa565b005b6101c26102a33660046114c8565b73ffffffffffffffffffffffffffffffffffffffff165f9081526020819052604090205490565b6101c26102d83660046114c8565b60056020525f908152604090205481565b610185610682565b6102936102ff366004611467565b610691565b61032b7f000000000000000000000000000000000000000000000000000000000000000081565b60405173ffffffffffffffffffffffffffffffffffffffff9091168152602001610192565b6101ae61035e366004611467565b610760565b6101ae610371366004611467565b610830565b6101c27f000000000000000000000000000000000000000000000000000000000000000081565b6102936103ab3660046114e8565b61083d565b6101c26103be366004611555565b73ffffffffffffffffffffffffffffffffffffffff9182165f90815260016020908152604080832093909416825291909152205490565b6007610253565b6101856040518060400160405280600181526020017f310000000000000000000000000000000000000000000000000000000000000081525081565b60606003805461044790611586565b80601f016020809104026020016040519081016040528092919081815260200182805461047390611586565b80156104be5780601f10610495576101008083540402835291602001916104be565b820191905f5260205f20905b8154815290600101906020018083116104a157829003601f168201915b5050505050905090565b5f336104d5818585610b6e565b60019150505b92915050565b5f336104ee858285610d21565b6104f9858585610df7565b506001949350505050565b5f7f0000000000000000000000000000000000000000000000000000000000000000461461053a5761053546611064565b905090565b507f000000000000000000000000000000000000000000000000000000000000000090565b335f81815260016020908152604080832073ffffffffffffffffffffffffffffffffffffffff871684529091528120549091906104d590829086906105a5908790611604565b610b6e565b3373ffffffffffffffffffffffffffffffffffffffff7f00000000000000000000000000000000000000000000000000000000000000001614610674576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152603060248201527f546f6b656e577261707065643a3a6f6e6c794272696467653a204e6f7420506f60448201527f6c79676f6e5a6b45564d4272696467650000000000000000000000000000000060648201526084015b60405180910390fd5b61067e828261112b565b5050565b60606004805461044790611586565b3373ffffffffffffffffffffffffffffffffffffffff7f00000000000000000000000000000000000000000000000000000000000000001614610756576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152603060248201527f546f6b656e577261707065643a3a6f6e6c794272696467653a204e6f7420506f60448201527f6c79676f6e5a6b45564d42726964676500000000000000000000000000000000606482015260840161066b565b61067e828261121c565b335f81815260016020908152604080832073ffffffffffffffffffffffffffffffffffffffff8716845290915281205490919083811015610823576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152602560248201527f45524332303a2064656372656173656420616c6c6f77616e63652062656c6f7760448201527f207a65726f000000000000000000000000000000000000000000000000000000606482015260840161066b565b6104f98286868403610b6e565b5f336104d5818585610df7565b834211156108cc576040517f08c379a0000000000000000000000000000000000000000000000000000000008152602060048201526024808201527f546f6b656e577261707065643a3a7065726d69743a204578706972656420706560448201527f726d697400000000000000000000000000000000000000000000000000000000606482015260840161066b565b73ffffffffffffffffffffffffffffffffffffffff87165f90815260056020526040812080547f6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9918a918a918a91908661092583611617565b9091555060408051602081019690965273ffffffffffffffffffffffffffffffffffffffff94851690860152929091166060840152608083015260a082015260c0810186905260e0016040516020818303038152906040528051906020012090505f61098f610504565b6040517f19010000000000000000000000000000000000000000000000000000000000006020820152602281019190915260428101839052606201604080517fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe081840301815282825280516020918201205f80855291840180845281905260ff89169284019290925260608301879052608083018690529092509060019060a0016020604051602081039080840390855afa158015610a50573d5f803e3d5ffd5b50506040517fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0015191505073ffffffffffffffffffffffffffffffffffffffff811615801590610acb57508973ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff16145b610b57576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152602760248201527f546f6b656e577261707065643a3a7065726d69743a20496e76616c696420736960448201527f676e617475726500000000000000000000000000000000000000000000000000606482015260840161066b565b610b628a8a8a610b6e565b50505050505050505050565b73ffffffffffffffffffffffffffffffffffffffff8316610c10576040517f08c379a0000000000000000000000000000000000000000000000000000000008152602060048201526024808201527f45524332303a20617070726f76652066726f6d20746865207a65726f2061646460448201527f7265737300000000000000000000000000000000000000000000000000000000606482015260840161066b565b73ffffffffffffffffffffffffffffffffffffffff8216610cb3576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152602260248201527f45524332303a20617070726f766520746f20746865207a65726f20616464726560448201527f7373000000000000000000000000000000000000000000000000000000000000606482015260840161066b565b73ffffffffffffffffffffffffffffffffffffffff8381165f8181526001602090815260408083209487168084529482529182902085905590518481527f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b92591015b60405180910390a3505050565b73ffffffffffffffffffffffffffffffffffffffff8381165f908152600160209081526040808320938616835292905220547fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8114610df15781811015610de4576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601d60248201527f45524332303a20696e73756666696369656e7420616c6c6f77616e6365000000604482015260640161066b565b610df18484848403610b6e565b50505050565b73ffffffffffffffffffffffffffffffffffffffff8316610e9a576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152602560248201527f45524332303a207472616e736665722066726f6d20746865207a65726f20616460448201527f6472657373000000000000000000000000000000000000000000000000000000606482015260840161066b565b73ffffffffffffffffffffffffffffffffffffffff8216610f3d576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152602360248201527f45524332303a207472616e7366657220746f20746865207a65726f206164647260448201527f6573730000000000000000000000000000000000000000000000000000000000606482015260840161066b565b73ffffffffffffffffffffffffffffffffffffffff83165f9081526020819052604090205481811015610ff2576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152602660248201527f45524332303a207472616e7366657220616d6f756e742065786365656473206260448201527f616c616e63650000000000000000000000000000000000000000000000000000606482015260840161066b565b73ffffffffffffffffffffffffffffffffffffffff8481165f81815260208181526040808320878703905593871680835291849020805487019055925185815290927fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef910160405180910390a3610df1565b5f7f8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f61108e610438565b8051602091820120604080518082018252600181527f310000000000000000000000000000000000000000000000000000000000000090840152805192830193909352918101919091527fc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc66060820152608081018390523060a082015260c001604051602081830303815290604052805190602001209050919050565b73ffffffffffffffffffffffffffffffffffffffff82166111a8576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152601f60248201527f45524332303a206d696e7420746f20746865207a65726f206164647265737300604482015260640161066b565b8060025f8282546111b99190611604565b909155505073ffffffffffffffffffffffffffffffffffffffff82165f81815260208181526040808320805486019055518481527fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef910160405180910390a35050565b73ffffffffffffffffffffffffffffffffffffffff82166112bf576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152602160248201527f45524332303a206275726e2066726f6d20746865207a65726f2061646472657360448201527f7300000000000000000000000000000000000000000000000000000000000000606482015260840161066b565b73ffffffffffffffffffffffffffffffffffffffff82165f9081526020819052604090205481811015611374576040517f08c379a000000000000000000000000000000000000000000000000000000000815260206004820152602260248201527f45524332303a206275726e20616d6f756e7420657863656564732062616c616e60448201527f6365000000000000000000000000000000000000000000000000000000000000606482015260840161066b565b73ffffffffffffffffffffffffffffffffffffffff83165f818152602081815260408083208686039055600280548790039055518581529192917fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef9101610d14565b5f6020808352835180828501525f5b81811015611401578581018301518582016040015282016113e5565b505f6040828601015260407fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0601f8301168501019250505092915050565b803573ffffffffffffffffffffffffffffffffffffffff81168114611462575f80fd5b919050565b5f8060408385031215611478575f80fd5b6114818361143f565b946020939093013593505050565b5f805f606084860312156114a1575f80fd5b6114aa8461143f565b92506114b86020850161143f565b9150604084013590509250925092565b5f602082840312156114d8575f80fd5b6114e18261143f565b9392505050565b5f805f805f805f60e0888a0312156114fe575f80fd5b6115078861143f565b96506115156020890161143f565b95506040880135945060608801359350608088013560ff81168114611538575f80fd5b9699959850939692959460a0840135945060c09093013592915050565b5f8060408385031215611566575f80fd5b61156f8361143f565b915061157d6020840161143f565b90509250929050565b600181811c9082168061159a57607f821691505b6020821081036115d1577f4e487b71000000000000000000000000000000000000000000000000000000005f52602260045260245ffd5b50919050565b7f4e487b71000000000000000000000000000000000000000000000000000000005f52601160045260245ffd5b808201808211156104db576104db6115d7565b5f7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8203611647576116476115d7565b506001019056fea2646970667358221220fcd216ad57ad61319f9c9a0e3b55094f5fdd4cb3db733a338a2962602de0dbc864736f6c63430008140033";

    /**
     * @notice Function to update the baseInitByteCodeWrappedToken
     */
    function updateBaseInitTokenWrapper(bytes calldata newWrappedToken) external {
        baseInitByteCodeWrappedToken = newWrappedToken;
    }

    /**
     * @notice Function to get the baseInitByteCodeWrappedToken
     */
    function getBaseInitTokenWrapper() external view returns (bytes memory bytecode) {
        return baseInitByteCodeWrappedToken;
    }

    // Network identifier
    uint32 public networkID;

    // Global Exit Root address
    IBasePolygonZkEVMGlobalExitRoot public globalExitRootManager;

    // Last updated deposit count to the global exit root manager
    uint32 public lastUpdatedDepositCount;

    // Leaf index --> claimed bit map
    mapping(uint256 => uint256) public claimedBitMap;

    // keccak256(OriginNetwork || tokenAddress) --> Wrapped token address
    mapping(bytes32 => address) public tokenInfoToWrappedToken;

    // Wrapped token Address --> Origin token information
    mapping(address => TokenInformation) public wrappedTokenToTokenInfo;

    // Rollup manager address, previously PolygonZkEVM
    /// @custom:oz-renamed-from polygonZkEVMaddress
    address public polygonRollupManager;

    // Native address
    address public gasTokenAddress;

    // Native address
    uint32 public gasTokenNetwork;

    // Gas token metadata
    bytes public gasTokenMetadata;

    // WETH address
    TokenWrapped public WETHToken;

    /**
     * @dev Emitted when bridge assets or messages to another network
     */
    event BridgeEvent(
        uint8 leafType,
        uint32 originNetwork,
        address originAddress,
        uint32 destinationNetwork,
        address destinationAddress,
        uint256 amount,
        bytes metadata,
        uint32 depositCount
    );

    /**
     * @dev Emitted when a claim is done from another network
     */
    event ClaimEvent(
        uint256 globalIndex,
        uint32 originNetwork,
        address originAddress,
        address destinationAddress,
        uint256 amount
    );

    /**
     * @dev Emitted when a new wrapped token is created
     */
    event NewWrappedToken(
        uint32 originNetwork,
        address originTokenAddress,
        address wrappedTokenAddress,
        bytes metadata
    );

    /**
     * Disable initalizers on the implementation following the best practices
     */
    constructor() {
        _disableInitializers();
    }

    /**
     * @param _networkID networkID
     * @param _gasTokenAddress gas token address
     * @param _gasTokenNetwork gas token network
     * @param _globalExitRootManager global exit root manager address
     * @param _polygonRollupManager polygonZkEVM address
     * @notice The value of `_polygonRollupManager` on the L2 deployment of the contract will be address(0), so
     * emergency state is not possible for the L2 deployment of the bridge, intentionally
     * @param _gasTokenMetadata Abi encoded gas token metadata
     */
    function initialize(
        uint32 _networkID,
        address _gasTokenAddress,
        uint32 _gasTokenNetwork,
        IBasePolygonZkEVMGlobalExitRoot _globalExitRootManager,
        address _polygonRollupManager,
        bytes memory _gasTokenMetadata
    ) external virtual initializer {
        networkID = _networkID;
        globalExitRootManager = _globalExitRootManager;
        polygonRollupManager = _polygonRollupManager;

        // Set gas token
        if (_gasTokenAddress == address(0)) {
            // Gas token will be ether
            if (_gasTokenNetwork != 0) {
                revert GasTokenNetworkMustBeZeroOnEther();
            }
            // WETHToken, gasTokenAddress and gasTokenNetwork will be 0
            // gasTokenMetadata will be empty
        } else {
            // Gas token will be an erc20
            gasTokenAddress = _gasTokenAddress;
            gasTokenNetwork = _gasTokenNetwork;
            gasTokenMetadata = _gasTokenMetadata;

            // Create a wrapped token for WETH, with salt == 0
            WETHToken = _deployWrappedToken(
                0, // salt
                abi.encode("Wrapped Ether", "WETH", 18)
            );
        }

        // Initialize OZ contracts
        __ReentrancyGuard_init();
    }

    modifier onlyRollupManager() {
        if (polygonRollupManager != msg.sender) {
            revert OnlyRollupManager();
        }
        _;
    }

    /**
     * @notice Deposit add a new leaf to the merkle tree
     * note If this function is called with a reentrant token, it would be possible to `claimTokens` in the same call
     * Reducing the supply of tokens on this contract, and actually locking tokens in the contract.
     * Therefore we recommend to third parties bridges that if they do implement reentrant call of `beforeTransfer` of some reentrant tokens
     * do not call any external address in that case
     * note User/UI must be aware of the existing/available networks when choosing the destination network
     * @param destinationNetwork Network destination
     * @param destinationAddress Address destination
     * @param amount Amount of tokens
     * @param token Token address, 0 address is reserved for ether
     * @param forceUpdateGlobalExitRoot Indicates if the new global exit root is updated or not
     * @param permitData Raw data of the call `permit` of the token
     */
    function bridgeAsset(
        uint32 destinationNetwork,
        address destinationAddress,
        uint256 amount,
        address token,
        bool forceUpdateGlobalExitRoot,
        bytes calldata permitData
    ) public payable virtual ifNotEmergencyState nonReentrant {
        if (destinationNetwork == networkID) {
            revert DestinationNetworkInvalid();
        }

        address originTokenAddress;
        uint32 originNetwork;
        bytes memory metadata;
        uint256 leafAmount = amount;

        if (token == address(0)) {
            // Check gas token transfer
            if (msg.value != amount) {
                revert AmountDoesNotMatchMsgValue();
            }

            // Set gas token parameters
            originNetwork = gasTokenNetwork;
            originTokenAddress = gasTokenAddress;
            metadata = gasTokenMetadata;
        } else {
            // Check msg.value is 0 if tokens are bridged
            if (msg.value != 0) {
                revert MsgValueNotZero();
            }

            // Check if it's WETH, this only applies on L2 networks with gasTokens
            // In case ether is the native token, WETHToken will be 0, and the address 0 is already checked
            if (token == address(WETHToken)) {
                // Burn tokens
                TokenWrapped(token).burn(msg.sender, amount);

                // Both origin network and originTokenAddress will be 0
                // Metadata will be empty
            } else {
                TokenInformation memory tokenInfo = wrappedTokenToTokenInfo[
                    token
                ];

                if (tokenInfo.originTokenAddress != address(0)) {
                    // The token is a wrapped token from another network

                    // Burn tokens
                    TokenWrapped(token).burn(msg.sender, amount);

                    originTokenAddress = tokenInfo.originTokenAddress;
                    originNetwork = tokenInfo.originNetwork;
                } else {
                    // Use permit if any
                    if (permitData.length != 0) {
                        _permit(token, amount, permitData);
                    }

                    // In order to support fee tokens check the amount received, not the transferred
                    uint256 balanceBefore = IERC20Upgradeable(token).balanceOf(
                        address(this)
                    );
                    IERC20Upgradeable(token).safeTransferFrom(
                        msg.sender,
                        address(this),
                        amount
                    );
                    uint256 balanceAfter = IERC20Upgradeable(token).balanceOf(
                        address(this)
                    );

                    // Override leafAmount with the received amount
                    leafAmount = balanceAfter - balanceBefore;

                    originTokenAddress = token;
                    originNetwork = networkID;
                }
                // Encode metadata
                metadata = getTokenMetadata(token);
            }
        }

        emit BridgeEvent(
            _LEAF_TYPE_ASSET,
            originNetwork,
            originTokenAddress,
            destinationNetwork,
            destinationAddress,
            leafAmount,
            metadata,
            uint32(depositCount)
        );

        _addLeaf(
            getLeafValue(
                _LEAF_TYPE_ASSET,
                originNetwork,
                originTokenAddress,
                destinationNetwork,
                destinationAddress,
                leafAmount,
                keccak256(metadata)
            )
        );

        // Update the new root to the global exit root manager if set by the user
        if (forceUpdateGlobalExitRoot) {
            _updateGlobalExitRoot();
        }
    }

    /**
     * @notice Bridge message and send ETH value
     * note User/UI must be aware of the existing/available networks when choosing the destination network
     * @param destinationNetwork Network destination
     * @param destinationAddress Address destination
     * @param forceUpdateGlobalExitRoot Indicates if the new global exit root is updated or not
     * @param metadata Message metadata
     */
    function bridgeMessage(
        uint32 destinationNetwork,
        address destinationAddress,
        bool forceUpdateGlobalExitRoot,
        bytes calldata metadata
    ) external payable ifNotEmergencyState {
        // If exist a gas token, only allow call this function without value
        if (msg.value != 0 && address(WETHToken) != address(0)) {
            revert NoValueInMessagesOnGasTokenNetworks();
        }

        _bridgeMessage(
            destinationNetwork,
            destinationAddress,
            msg.value,
            forceUpdateGlobalExitRoot,
            metadata
        );
    }

    /**
     * @notice Bridge message and send ETH value
     * note User/UI must be aware of the existing/available networks when choosing the destination network
     * @param destinationNetwork Network destination
     * @param destinationAddress Address destination
     * @param amountWETH Amount of WETH tokens
     * @param forceUpdateGlobalExitRoot Indicates if the new global exit root is updated or not
     * @param metadata Message metadata
     */
    function bridgeMessageWETH(
        uint32 destinationNetwork,
        address destinationAddress,
        uint256 amountWETH,
        bool forceUpdateGlobalExitRoot,
        bytes calldata metadata
    ) external ifNotEmergencyState {
        // If native token is ether, disable this function
        if (address(WETHToken) == address(0)) {
            revert NativeTokenIsEther();
        }

        // Burn wETH tokens
        WETHToken.burn(msg.sender, amountWETH);

        _bridgeMessage(
            destinationNetwork,
            destinationAddress,
            amountWETH,
            forceUpdateGlobalExitRoot,
            metadata
        );
    }

    /**
     * @notice Bridge message and send ETH value
     * @param destinationNetwork Network destination
     * @param destinationAddress Address destination
     * @param amountEther Amount of ether along with the message
     * @param forceUpdateGlobalExitRoot Indicates if the new global exit root is updated or not
     * @param metadata Message metadata
     */
    function _bridgeMessage(
        uint32 destinationNetwork,
        address destinationAddress,
        uint256 amountEther,
        bool forceUpdateGlobalExitRoot,
        bytes calldata metadata
    ) internal {
        if (destinationNetwork == networkID) {
            revert DestinationNetworkInvalid();
        }

        emit BridgeEvent(
            _LEAF_TYPE_MESSAGE,
            networkID,
            msg.sender,
            destinationNetwork,
            destinationAddress,
            amountEther,
            metadata,
            uint32(depositCount)
        );

        _addLeaf(
            getLeafValue(
                _LEAF_TYPE_MESSAGE,
                networkID,
                msg.sender,
                destinationNetwork,
                destinationAddress,
                amountEther,
                keccak256(metadata)
            )
        );

        // Update the new root to the global exit root manager if set by the user
        if (forceUpdateGlobalExitRoot) {
            _updateGlobalExitRoot();
        }
    }

    /**
     * @notice Verify merkle proof and withdraw tokens/ether
     * @param smtProofLocalExitRoot Smt proof to proof the leaf against the network exit root
     * @param smtProofRollupExitRoot Smt proof to proof the rollupLocalExitRoot against the rollups exit root
     * @param globalIndex Global index is defined as:
     * | 191 bits |    1 bit     |   32 bits   |     32 bits    |
     * |    0     |  mainnetFlag | rollupIndex | localRootIndex |
     * note that only the rollup index will be used only in case the mainnet flag is 0
     * note that global index do not assert the unused bits to 0.
     * This means that when synching the events, the globalIndex must be decoded the same way that in the Smart contract
     * to avoid possible synch attacks
     * @param mainnetExitRoot Mainnet exit root
     * @param rollupExitRoot Rollup exit root
     * @param originNetwork Origin network
     * @param originTokenAddress  Origin token address, 0 address is reserved for ether
     * @param destinationNetwork Network destination
     * @param destinationAddress Address destination
     * @param amount Amount of tokens
     * @param metadata Abi encoded metadata if any, empty otherwise
     */
    function claimAsset(
        bytes32[_DEPOSIT_CONTRACT_TREE_DEPTH] calldata smtProofLocalExitRoot,
        bytes32[_DEPOSIT_CONTRACT_TREE_DEPTH] calldata smtProofRollupExitRoot,
        uint256 globalIndex,
        bytes32 mainnetExitRoot,
        bytes32 rollupExitRoot,
        uint32 originNetwork,
        address originTokenAddress,
        uint32 destinationNetwork,
        address destinationAddress,
        uint256 amount,
        bytes calldata metadata
    ) external ifNotEmergencyState {
        // Destination network must be this networkID
        if (destinationNetwork != networkID) {
            revert DestinationNetworkInvalid();
        }

        // Verify leaf exist and it does not have been claimed
        _verifyLeaf(
            smtProofLocalExitRoot,
            smtProofRollupExitRoot,
            globalIndex,
            mainnetExitRoot,
            rollupExitRoot,
            getLeafValue(
                _LEAF_TYPE_ASSET,
                originNetwork,
                originTokenAddress,
                destinationNetwork,
                destinationAddress,
                amount,
                keccak256(metadata)
            )
        );

        // Transfer funds
        if (originTokenAddress == address(0)) {
            if (address(WETHToken) == address(0)) {
                // Ether is the native token
                /* solhint-disable avoid-low-level-calls */
                (bool success, ) = destinationAddress.call{value: amount}(
                    new bytes(0)
                );
                if (!success) {
                    revert EtherTransferFailed();
                }
            } else {
                // Claim wETH
                WETHToken.mint(destinationAddress, amount);
            }
        } else {
            // Check if it's gas token
            if (
                originTokenAddress == gasTokenAddress &&
                gasTokenNetwork == originNetwork
            ) {
                // Transfer gas token
                /* solhint-disable avoid-low-level-calls */
                (bool success, ) = destinationAddress.call{value: amount}(
                    new bytes(0)
                );
                if (!success) {
                    revert EtherTransferFailed();
                }
            } else {
                // Transfer tokens
                if (originNetwork == networkID) {
                    // The token is an ERC20 from this network
                    IERC20Upgradeable(originTokenAddress).safeTransfer(
                        destinationAddress,
                        amount
                    );
                } else {
                    // The tokens is not from this network
                    // Create a wrapper for the token if not exist yet
                    bytes32 tokenInfoHash = keccak256(
                        abi.encodePacked(originNetwork, originTokenAddress)
                    );
                    address wrappedToken = tokenInfoToWrappedToken[
                        tokenInfoHash
                    ];

                    if (wrappedToken == address(0)) {
                        // Get ERC20 metadata

                        // Create a new wrapped erc20 using create2
                        TokenWrapped newWrappedToken = _deployWrappedToken(
                            tokenInfoHash,
                            metadata
                        );

                        // Mint tokens for the destination address
                        newWrappedToken.mint(destinationAddress, amount);

                        // Create mappings
                        tokenInfoToWrappedToken[tokenInfoHash] = address(
                            newWrappedToken
                        );

                        wrappedTokenToTokenInfo[
                            address(newWrappedToken)
                        ] = TokenInformation(originNetwork, originTokenAddress);

                        emit NewWrappedToken(
                            originNetwork,
                            originTokenAddress,
                            address(newWrappedToken),
                            metadata
                        );
                    } else {
                        // Use the existing wrapped erc20
                        TokenWrapped(wrappedToken).mint(
                            destinationAddress,
                            amount
                        );
                    }
                }
            }
        }

        emit ClaimEvent(
            globalIndex,
            originNetwork,
            originTokenAddress,
            destinationAddress,
            amount
        );
    }

    /**
     * @notice Verify merkle proof and execute message
     * If the receiving address is an EOA, the call will result as a success
     * Which means that the amount of ether will be transferred correctly, but the message
     * will not trigger any execution
     * @param smtProofLocalExitRoot Smt proof to proof the leaf against the exit root
     * @param smtProofRollupExitRoot Smt proof to proof the rollupLocalExitRoot against the rollups exit root
     * @param globalIndex Global index is defined as:
     * | 191 bits |    1 bit     |   32 bits   |     32 bits    |
     * |    0     |  mainnetFlag | rollupIndex | localRootIndex |
     * note that only the rollup index will be used only in case the mainnet flag is 0
     * note that global index do not assert the unused bits to 0.
     * This means that when synching the events, the globalIndex must be decoded the same way that in the Smart contract
     * to avoid possible synch attacks
     * @param mainnetExitRoot Mainnet exit root
     * @param rollupExitRoot Rollup exit root
     * @param originNetwork Origin network
     * @param originAddress Origin address
     * @param destinationNetwork Network destination
     * @param destinationAddress Address destination
     * @param amount message value
     * @param metadata Abi encoded metadata if any, empty otherwise
     */
    function claimMessage(
        bytes32[_DEPOSIT_CONTRACT_TREE_DEPTH] calldata smtProofLocalExitRoot,
        bytes32[_DEPOSIT_CONTRACT_TREE_DEPTH] calldata smtProofRollupExitRoot,
        uint256 globalIndex,
        bytes32 mainnetExitRoot,
        bytes32 rollupExitRoot,
        uint32 originNetwork,
        address originAddress,
        uint32 destinationNetwork,
        address destinationAddress,
        uint256 amount,
        bytes calldata metadata
    ) external ifNotEmergencyState {
        // Destination network must be this networkID
        if (destinationNetwork != networkID) {
            revert DestinationNetworkInvalid();
        }

        // Verify leaf exist and it does not have been claimed
        _verifyLeaf(
            smtProofLocalExitRoot,
            smtProofRollupExitRoot,
            globalIndex,
            mainnetExitRoot,
            rollupExitRoot,
            getLeafValue(
                _LEAF_TYPE_MESSAGE,
                originNetwork,
                originAddress,
                destinationNetwork,
                destinationAddress,
                amount,
                keccak256(metadata)
            )
        );

        // Execute message
        bool success;
        if (address(WETHToken) == address(0)) {
            // Native token is ether
            // Transfer ether
            /* solhint-disable avoid-low-level-calls */
            (success, ) = destinationAddress.call{value: amount}(
                abi.encodeCall(
                    IBridgeMessageReceiver.onMessageReceived,
                    (originAddress, originNetwork, metadata)
                )
            );
        } else {
            // Mint wETH tokens
            WETHToken.mint(destinationAddress, amount);

            // Execute message
            /* solhint-disable avoid-low-level-calls */
            (success, ) = destinationAddress.call(
                abi.encodeCall(
                    IBridgeMessageReceiver.onMessageReceived,
                    (originAddress, originNetwork, metadata)
                )
            );
        }

        if (!success) {
            revert MessageFailed();
        }

        emit ClaimEvent(
            globalIndex,
            originNetwork,
            originAddress,
            destinationAddress,
            amount
        );
    }

    /**
     * @notice Returns the precalculated address of a wrapper using the token information
     * Note Updating the metadata of a token is not supported.
     * Since the metadata has relevance in the address deployed, this function will not return a valid
     * wrapped address if the metadata provided is not the original one.
     * @param originNetwork Origin network
     * @param originTokenAddress Origin token address, 0 address is reserved for ether
     * @param name Name of the token
     * @param symbol Symbol of the token
     * @param decimals Decimals of the token
     */
    function precalculatedWrapperAddress(
        uint32 originNetwork,
        address originTokenAddress,
        string memory name,
        string memory symbol,
        uint8 decimals
    ) public view returns (address) {
        bytes32 salt = keccak256(
            abi.encodePacked(originNetwork, originTokenAddress)
        );

        bytes32 hashCreate2 = keccak256(
            abi.encodePacked(
                bytes1(0xff),
                address(this),
                salt,
                keccak256(
                    abi.encodePacked(
                        baseInitByteCodeWrappedToken,
                        abi.encode(name, symbol, decimals)
                    )
                )
            )
        );

        // Last 20 bytes of hash to address
        return address(uint160(uint256(hashCreate2)));
    }

    /**
     * @notice Returns the address of a wrapper using the token information if already exist
     * @param originNetwork Origin network
     * @param originTokenAddress Origin token address, 0 address is reserved for ether
     */
    function getTokenWrappedAddress(
        uint32 originNetwork,
        address originTokenAddress
    ) external view returns (address) {
        return
            tokenInfoToWrappedToken[
                keccak256(abi.encodePacked(originNetwork, originTokenAddress))
            ];
    }

    /**
     * @notice Function to activate the emergency state
     " Only can be called by the Polygon ZK-EVM in extreme situations
     */
    function activateEmergencyState() external onlyRollupManager {
        _activateEmergencyState();
    }

    /**
     * @notice Function to deactivate the emergency state
     " Only can be called by the Polygon ZK-EVM
     */
    function deactivateEmergencyState() external onlyRollupManager {
        _deactivateEmergencyState();
    }

    /**
     * @notice Verify leaf and checks that it has not been claimed
     * @param smtProofLocalExitRoot Smt proof
     * @param smtProofRollupExitRoot Smt proof
     * @param globalIndex Index of the leaf
     * @param mainnetExitRoot Mainnet exit root
     * @param rollupExitRoot Rollup exit root
     * @param leafValue leaf value
     */
    function _verifyLeaf(
        bytes32[_DEPOSIT_CONTRACT_TREE_DEPTH] calldata smtProofLocalExitRoot,
        bytes32[_DEPOSIT_CONTRACT_TREE_DEPTH] calldata smtProofRollupExitRoot,
        uint256 globalIndex,
        bytes32 mainnetExitRoot,
        bytes32 rollupExitRoot,
        bytes32 leafValue
    ) internal {
        // Check blockhash where the global exit root was set
        // Note that previusly timestamps were setted, since in only checked if != 0 it's ok
        uint256 blockHashGlobalExitRoot = globalExitRootManager
            .globalExitRootMap(
                GlobalExitRootLib.calculateGlobalExitRoot(
                    mainnetExitRoot,
                    rollupExitRoot
                )
            );

        // check that this global exit root exist
        if (blockHashGlobalExitRoot == 0) {
            revert GlobalExitRootInvalid();
        }

        uint32 leafIndex;
        uint32 sourceBridgeNetwork;

        // Get origin network from global index
        if (globalIndex & _GLOBAL_INDEX_MAINNET_FLAG != 0) {
            // the network is mainnet, therefore sourceBridgeNetwork is 0

            // Last 32 bits are leafIndex
            leafIndex = uint32(globalIndex);

            if (
                !verifyMerkleProof(
                    leafValue,
                    smtProofLocalExitRoot,
                    leafIndex,
                    mainnetExitRoot
                )
            ) {
                revert InvalidSmtProof();
            }
        } else {
            // the network is a rollup, therefore sourceBridgeNetwork must be decoded
            uint32 indexRollup = uint32(globalIndex >> 32);
            sourceBridgeNetwork = indexRollup + 1;

            // Last 32 bits are leafIndex
            leafIndex = uint32(globalIndex);

            // Verify merkle proof agains rollup exit root
            if (
                !verifyMerkleProof(
                    calculateRoot(leafValue, smtProofLocalExitRoot, leafIndex),
                    smtProofRollupExitRoot,
                    indexRollup,
                    rollupExitRoot
                )
            ) {
                revert InvalidSmtProof();
            }
        }

        // Set and check nullifier
        _setAndCheckClaimed(leafIndex, sourceBridgeNetwork);
    }

    /**
     * @notice Function to check if an index is claimed or not
     * @param leafIndex Index
     * @param sourceBridgeNetwork Origin network
     */
    function isClaimed(
        uint32 leafIndex,
        uint32 sourceBridgeNetwork
    ) external view returns (bool) {
        uint256 globalIndex;

        // For consistency with the previous setted nullifiers
        if (
            networkID == _MAINNET_NETWORK_ID &&
            sourceBridgeNetwork == _ZKEVM_NETWORK_ID
        ) {
            globalIndex = uint256(leafIndex);
        } else {
            globalIndex =
                uint256(leafIndex) +
                uint256(sourceBridgeNetwork) *
                _MAX_LEAFS_PER_NETWORK;
        }
        (uint256 wordPos, uint256 bitPos) = _bitmapPositions(globalIndex);
        uint256 mask = (1 << bitPos);
        return (claimedBitMap[wordPos] & mask) == mask;
    }

    /**
     * @notice Function to check that an index is not claimed and set it as claimed
     * @param leafIndex Index
     * @param sourceBridgeNetwork Origin network
     */
    function _setAndCheckClaimed(
        uint32 leafIndex,
        uint32 sourceBridgeNetwork
    ) private {
        uint256 globalIndex;

        // For consistency with the previous setted nullifiers
        if (
            networkID == _MAINNET_NETWORK_ID &&
            sourceBridgeNetwork == _ZKEVM_NETWORK_ID
        ) {
            globalIndex = uint256(leafIndex);
        } else {
            globalIndex =
                uint256(leafIndex) +
                uint256(sourceBridgeNetwork) *
                _MAX_LEAFS_PER_NETWORK;
        }
        (uint256 wordPos, uint256 bitPos) = _bitmapPositions(globalIndex);
        uint256 mask = 1 << bitPos;
        uint256 flipped = claimedBitMap[wordPos] ^= mask;
        if (flipped & mask == 0) {
            revert AlreadyClaimed();
        }
    }

    /**
     * @notice Function to update the globalExitRoot if the last deposit is not submitted
     */
    function updateGlobalExitRoot() external {
        if (lastUpdatedDepositCount < depositCount) {
            _updateGlobalExitRoot();
        }
    }

    /**
     * @notice Function to update the globalExitRoot
     */
    function _updateGlobalExitRoot() internal {
        lastUpdatedDepositCount = uint32(depositCount);
        globalExitRootManager.updateExitRoot(getRoot());
    }

    /**
     * @notice Function decode an index into a wordPos and bitPos
     * @param index Index
     */
    function _bitmapPositions(
        uint256 index
    ) private pure returns (uint256 wordPos, uint256 bitPos) {
        wordPos = uint248(index >> 8);
        bitPos = uint8(index);
    }

    /**
     * @notice Function to call token permit method of extended ERC20
     + @param token ERC20 token address
     * @param amount Quantity that is expected to be allowed
     * @param permitData Raw data of the call `permit` of the token
     */
    function _permit(
        address token,
        uint256 amount,
        bytes calldata permitData
    ) internal {
        bytes4 sig = bytes4(permitData[:4]);
        if (sig == _PERMIT_SIGNATURE) {
            (
                address owner,
                address spender,
                uint256 value,
                uint256 deadline,
                uint8 v,
                bytes32 r,
                bytes32 s
            ) = abi.decode(
                    permitData[4:],
                    (
                        address,
                        address,
                        uint256,
                        uint256,
                        uint8,
                        bytes32,
                        bytes32
                    )
                );
            if (owner != msg.sender) {
                revert NotValidOwner();
            }
            if (spender != address(this)) {
                revert NotValidSpender();
            }

            if (value != amount) {
                revert NotValidAmount();
            }

            // we call without checking the result, in case it fails and he doesn't have enough balance
            // the following transferFrom should be fail. This prevents DoS attacks from using a signature
            // before the smartcontract call
            /* solhint-disable avoid-low-level-calls */
            address(token).call(
                abi.encodeWithSelector(
                    _PERMIT_SIGNATURE,
                    owner,
                    spender,
                    value,
                    deadline,
                    v,
                    r,
                    s
                )
            );
        } else {
            if (sig != _PERMIT_SIGNATURE_DAI) {
                revert NotValidSignature();
            }

            (
                address holder,
                address spender,
                uint256 nonce,
                uint256 expiry,
                bool allowed,
                uint8 v,
                bytes32 r,
                bytes32 s
            ) = abi.decode(
                    permitData[4:],
                    (
                        address,
                        address,
                        uint256,
                        uint256,
                        bool,
                        uint8,
                        bytes32,
                        bytes32
                    )
                );

            if (holder != msg.sender) {
                revert NotValidOwner();
            }

            if (spender != address(this)) {
                revert NotValidSpender();
            }

            // we call without checking the result, in case it fails and he doesn't have enough balance
            // the following transferFrom should be fail. This prevents DoS attacks from using a signature
            // before the smartcontract call
            /* solhint-disable avoid-low-level-calls */
            address(token).call(
                abi.encodeWithSelector(
                    _PERMIT_SIGNATURE_DAI,
                    holder,
                    spender,
                    nonce,
                    expiry,
                    allowed,
                    v,
                    r,
                    s
                )
            );
        }
    }

    /**
     * @notice Internal function that uses create2 to deploy the wrapped tokens
     * @param salt Salt used in create2 params,
     * tokenInfoHash will be used as salt for all wrappeds except for bridge native WETH, that will be bytes32(0)
     * @param constructorArgs Encoded constructor args for the wrapped token
     */
    function _deployWrappedToken(
        bytes32 salt,
        bytes memory constructorArgs
    ) internal returns (TokenWrapped newWrappedToken) {
        bytes memory initBytecode = abi.encodePacked(
            baseInitByteCodeWrappedToken,
            constructorArgs
        );

        /// @solidity memory-safe-assembly
        assembly {
            newWrappedToken := create2(
                0,
                add(initBytecode, 0x20),
                mload(initBytecode),
                salt
            )
        }
        if (address(newWrappedToken) == address(0))
            revert FailedTokenWrappedDeployment();
    }

    // Helpers to safely get the metadata from a token, inspired by https://github.com/traderjoe-xyz/joe-core/blob/main/contracts/MasterChefJoeV3.sol#L55-L95

    /**
     * @notice Provides a safe ERC20.symbol version which returns 'NO_SYMBOL' as fallback string
     * @param token The address of the ERC-20 token contract
     */
    function _safeSymbol(address token) internal view returns (string memory) {
        (bool success, bytes memory data) = address(token).staticcall(
            abi.encodeCall(IERC20MetadataUpgradeable.symbol, ())
        );
        return success ? _returnDataToString(data) : "NO_SYMBOL";
    }

    /**
     * @notice  Provides a safe ERC20.name version which returns 'NO_NAME' as fallback string.
     * @param token The address of the ERC-20 token contract.
     */
    function _safeName(address token) internal view returns (string memory) {
        (bool success, bytes memory data) = address(token).staticcall(
            abi.encodeCall(IERC20MetadataUpgradeable.name, ())
        );
        return success ? _returnDataToString(data) : "NO_NAME";
    }

    /**
     * @notice Provides a safe ERC20.decimals version which returns '18' as fallback value.
     * Note Tokens with (decimals > 255) are not supported
     * @param token The address of the ERC-20 token contract
     */
    function _safeDecimals(address token) internal view returns (uint8) {
        (bool success, bytes memory data) = address(token).staticcall(
            abi.encodeCall(IERC20MetadataUpgradeable.decimals, ())
        );
        return success && data.length == 32 ? abi.decode(data, (uint8)) : 18;
    }

    /**
     * @notice Function to convert returned data to string
     * returns 'NOT_VALID_ENCODING' as fallback value.
     * @param data returned data
     */
    function _returnDataToString(
        bytes memory data
    ) internal pure returns (string memory) {
        if (data.length >= 64) {
            return abi.decode(data, (string));
        } else if (data.length == 32) {
            // Since the strings on bytes32 are encoded left-right, check the first zero in the data
            uint256 nonZeroBytes;
            while (nonZeroBytes < 32 && data[nonZeroBytes] != 0) {
                nonZeroBytes++;
            }

            // If the first one is 0, we do not handle the encoding
            if (nonZeroBytes == 0) {
                return "NOT_VALID_ENCODING";
            }
            // Create a byte array with nonZeroBytes length
            bytes memory bytesArray = new bytes(nonZeroBytes);
            for (uint256 i = 0; i < nonZeroBytes; i++) {
                bytesArray[i] = data[i];
            }
            return string(bytesArray);
        } else {
            return "NOT_VALID_ENCODING";
        }
    }

    /**
     * @notice Returns the encoded token metadata
     * @param token Address of the token
     */

    function getTokenMetadata(
        address token
    ) public view returns (bytes memory) {
        return
            abi.encode(
                _safeName(token),
                _safeSymbol(token),
                _safeDecimals(token)
            );
    }

    /**
     * @notice Returns the precalculated address of a wrapper using the token address
     * Note Updating the metadata of a token is not supported.
     * Since the metadata has relevance in the address deployed, this function will not return a valid
     * wrapped address if the metadata provided is not the original one.
     * @param originNetwork Origin network
     * @param originTokenAddress Origin token address, 0 address is reserved for ether
     * @param token Address of the token to calculate the wrapper address
     */
    function calculateTokenWrapperAddress(
        uint32 originNetwork,
        address originTokenAddress,
        address token
    ) external view returns (address) {
        return
            precalculatedWrapperAddress(
                originNetwork,
                originTokenAddress,
                _safeName(token),
                _safeSymbol(token),
                _safeDecimals(token)
            );
    }
}
