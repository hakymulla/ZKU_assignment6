// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.7.3;
pragma experimental ABIEncoderV2;

import "./HarmonyParser.sol";
import "./lib/SafeCast.sol";
import "@openzeppelin/contracts-upgradeable/math/SafeMathUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/AccessControlUpgradeable.sol";
// import "openzeppelin-solidity/contracts/utils/Pausable.sol";
import "@openzeppelin/contracts-upgradeable/utils/PausableUpgradeable.sol";
// import "openzeppelin-solidity/contracts/proxy/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/proxy/Initializable.sol";

contract HarmonyLightClient is
    Initializable,
    PausableUpgradeable,
    AccessControlUpgradeable
{
    using SafeCast for *;
    using SafeMathUpgradeable for uint256;

    struct BlockHeader {
        bytes32 parentHash;
        bytes32 stateRoot;
        bytes32 transactionsRoot;
        bytes32 receiptsRoot;
        uint256 number;
        uint256 epoch;
        uint256 shard;
        uint256 time;
        bytes32 mmrRoot;
        bytes32 hash;
    }

    event CheckPoint(
        bytes32 stateRoot,
        bytes32 transactionsRoot,
        bytes32 receiptsRoot,
        uint256 number,
        uint256 epoch,
        uint256 shard,
        uint256 time,
        bytes32 mmrRoot,
        bytes32 hash
    );

    BlockHeader firstBlock;
    BlockHeader lastCheckPointBlock;

    // epoch to block numbers, as there could be >=1 mmr entries per epoch
    mapping(uint256 => uint256[]) epochCheckPointBlockNumbers;

    // block number to BlockHeader
    mapping(uint256 => BlockHeader) checkPointBlocks;

    mapping(uint256 => mapping(bytes32 => bool)) epochMmrRoots;

    uint8 relayerThreshold;

    event RelayerThresholdChanged(uint256 newThreshold);
    event RelayerAdded(address relayer);
    event RelayerRemoved(address relayer);

    bytes32 public constant RELAYER_ROLE = keccak256("RELAYER_ROLE");

// A modifier to check if the method caller has an admin role
    modifier onlyAdmin() {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender), "sender doesn't have admin role");
        _;
    }

// A modifier to check if the method caller has a relayer role
    modifier onlyRelayers() {
        require(hasRole(RELAYER_ROLE, msg.sender), "sender doesn't have relayer role");
        _;
    }

// A function to that calls the _pause method, can only be called by admin
    function adminPauseLightClient() external onlyAdmin {
        _pause();
    }

// A function to that calls the _unpause method, can only be called by admin
    function adminUnpauseLightClient() external onlyAdmin {
        _unpause();
    }

// The renounceAdmin takes an address as input and can only be called by an admin
// checks if the caller of the function isn't the same address passed as input
// grants the address passed as input an admin role (with the with the grantRole function)
// revokes the admin role of the caller of the function i.e msg.sender (with the renounceRole functio)
    function renounceAdmin(address newAdmin) external onlyAdmin {
        require(msg.sender != newAdmin, 'cannot renounce self');
        grantRole(DEFAULT_ADMIN_ROLE, newAdmin);
        renounceRole(DEFAULT_ADMIN_ROLE, msg.sender);
    }

// The adminChangeRelayerThreshold takes a uint256  as input and can only be called by an admin
// the input is converted to Uint8
// and the RelayerThresholdChanged event is emmited with the input
    function adminChangeRelayerThreshold(uint256 newThreshold) external onlyAdmin {
        relayerThreshold = newThreshold.toUint8();
        emit RelayerThresholdChanged(newThreshold);
    }

// The adminAddRelayer takes an address as input and can only be called by an admin
// checks if the inputted address doesn't have the relayer role (i.e if the address is not a relayer)
// grants the inputed address a relayer role (with the grantRole functio)
// the RelayerAdded event is emitted with the inputted address
    function adminAddRelayer(address relayerAddress) external onlyAdmin {
        require(!hasRole(RELAYER_ROLE, relayerAddress), "addr already has relayer role!");
        grantRole(RELAYER_ROLE, relayerAddress);
        emit RelayerAdded(relayerAddress);
    }

// The adminRemoveRelayer takes an address as input and can only be called by an admin
// checks if the inputted address have the relayer role (i.e if the address is already a relayer)
// revokes the relayer role from the address
// the RelayerRemoved event is emiited
    function adminRemoveRelayer(address relayerAddress) external onlyAdmin {
        require(hasRole(RELAYER_ROLE, relayerAddress), "addr doesn't have relayer role!");
        revokeRole(RELAYER_ROLE, relayerAddress);
        emit RelayerRemoved(relayerAddress);
    }

// the initialize function takes firstRlpHeader, a list initialRelayers and initialRelayerThreshold as input
// header of type HarmonyParser.BlockHeader is saved in memory, the input firstRlpHeader is passed as an argument to the  toBlockHeader function of HarmonyParser library which returns a BlockHeader
// the firstBlock BlockHeader struct is updated with the returned BlockHeader header 
// epochCheckPointBlockNumbers mapping is uppdated with header.epoch and header.number
// checkPointBlocks mapping is updated
// epochMmrRoots mapping is updated
// relayerThreshold public variable is updated to the initialRelayerThreshold
// the caller of the function (msg.sender) is given the DEFAULT_ADMIN_ROLE
// and all address in the initialRelayers arrays are granted RELAYER_ROLE

    function initialize(
        bytes memory firstRlpHeader,
        address[] memory initialRelayers,
        uint8 initialRelayerThreshold
    ) external initializer {
        HarmonyParser.BlockHeader memory header = HarmonyParser.toBlockHeader(
            firstRlpHeader
        );
        
        firstBlock.parentHash = header.parentHash;
        firstBlock.stateRoot = header.stateRoot;
        firstBlock.transactionsRoot = header.transactionsRoot;
        firstBlock.receiptsRoot = header.receiptsRoot;
        firstBlock.number = header.number;
        firstBlock.epoch = header.epoch;
        firstBlock.shard = header.shardID;
        firstBlock.time = header.timestamp;
        firstBlock.mmrRoot = HarmonyParser.toBytes32(header.mmrRoot);
        firstBlock.hash = header.hash;
        
        epochCheckPointBlockNumbers[header.epoch].push(header.number);
        checkPointBlocks[header.number] = firstBlock;

        epochMmrRoots[header.epoch][firstBlock.mmrRoot] = true;

        relayerThreshold = initialRelayerThreshold;
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
        for (uint256 i; i < initialRelayers.length; i++) {
            grantRole(RELAYER_ROLE, initialRelayers[i]);
        }

    }

// the submitCheckpoint takes one input rlpHeader and can only be called by address with RELAYER_ROLE
// header of type HarmonyParser.BlockHeader is saved in memory, the input firstRlpHeader is passed as an argument to the  toBlockHeader function of HarmonyParser library which returns a BlockHeader
// a BlockHeader struct  called checkPointBlock is created in memory and updated with the returned BlockHeader header 
// epochCheckPointBlockNumbers mapping is uppdated with header.epoch and header.number
// checkPointBlocks mapping is updated
// epochMmrRoots mapping is updated
// the CheckPoint event is emitted with the checkPointBlock struct data
    function submitCheckpoint(bytes memory rlpHeader) external onlyRelayers whenNotPaused {
        HarmonyParser.BlockHeader memory header = HarmonyParser.toBlockHeader(
            rlpHeader
        );

        BlockHeader memory checkPointBlock;
        
        checkPointBlock.parentHash = header.parentHash;
        checkPointBlock.stateRoot = header.stateRoot;
        checkPointBlock.transactionsRoot = header.transactionsRoot;
        checkPointBlock.receiptsRoot = header.receiptsRoot;
        checkPointBlock.number = header.number;
        checkPointBlock.epoch = header.epoch;
        checkPointBlock.shard = header.shardID;
        checkPointBlock.time = header.timestamp;
        checkPointBlock.mmrRoot = HarmonyParser.toBytes32(header.mmrRoot);
        checkPointBlock.hash = header.hash;
        
        epochCheckPointBlockNumbers[header.epoch].push(header.number);
        checkPointBlocks[header.number] = checkPointBlock;

        epochMmrRoots[header.epoch][checkPointBlock.mmrRoot] = true;
        emit CheckPoint(
            checkPointBlock.stateRoot,
            checkPointBlock.transactionsRoot,
            checkPointBlock.receiptsRoot,
            checkPointBlock.number,
            checkPointBlock.epoch,
            checkPointBlock.shard,
            checkPointBlock.time,
            checkPointBlock.mmrRoot,
            checkPointBlock.hash
        );
    }


// the getLatestCheckPoint function takes as input blockNumber and epoch
// checks if the lenght of epoch in epochCheckPointBlockNumbers mapping isn't empty
//  creates an array memory from the output of epoch in checkPointBlockNumbers
// gets the latest checkPointBlockNumber and returns the BlockHeader of the latest checkPointBlockNumber from checkPointBlocks
    function getLatestCheckPoint(uint256 blockNumber, uint256 epoch)
        public
        view
        returns (BlockHeader memory checkPointBlock)
    {
        require(
            epochCheckPointBlockNumbers[epoch].length > 0,
            "no checkpoints for epoch"
        );
        uint256[] memory checkPointBlockNumbers = epochCheckPointBlockNumbers[epoch];
        uint256 nearest = 0;
        for (uint256 i = 0; i < checkPointBlockNumbers.length; i++) {
            uint256 checkPointBlockNumber = checkPointBlockNumbers[i];
            if (
                checkPointBlockNumber > blockNumber &&
                checkPointBlockNumber < nearest
            ) {
                nearest = checkPointBlockNumber;
            }
        }
        checkPointBlock = checkPointBlocks[nearest];
    }

// the isValidCheckPoint takes as input epoch and mmrRoot
// return a bool from the epochMmrRoots mapping
    function isValidCheckPoint(uint256 epoch, bytes32 mmrRoot) public view returns (bool status) {
        return epochMmrRoots[epoch][mmrRoot];
    }
}
