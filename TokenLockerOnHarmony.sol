// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.7.3;
pragma experimental ABIEncoderV2;

import "@openzeppelin/contracts-upgradeable/math/SafeMathUpgradeable.sol";
import "./EthereumLightClient.sol";
import "./EthereumProver.sol";
import "./TokenLocker.sol";

contract TokenLockerOnHarmony is TokenLocker, OwnableUpgradeable {
    using RLPReader for RLPReader.RLPItem;
    using RLPReader for bytes;
    using SafeMathUpgradeable for uint256;
    using SafeERC20Upgradeable for IERC20Upgradeable;

    EthereumLightClient public lightclient;

    mapping(bytes32 => bool) public spentReceipt;

    function initialize() external initializer {
        __Ownable_init();
    }

// the changeLightClient function can onlt be called by the owner odf the contract
// this function changes the EthereumLightClient
    function changeLightClient(EthereumLightClient newClient)
        external
        onlyOwner
    {
        lightclient = newClient;
    }

// the bind function can onlt be called by the owner odf the contract
// this function changes an address
    function bind(address otherSide) external onlyOwner {
        otherSideBridge = otherSide;
    }

// the validateAndExecuteProof function takes as input blockNo, rootHash, mptkey, proof
// the blockHash of the blockNo  is retrievd from the blocksByHeight mapping from EthereumLightClient 
// the VerifyReceiptsHash function from EthereumLightClient is called to check if the blockHash is the same as rootHash
// the blockHash, rootHash, mptkey is hashed and stored in receiptHash
// checks the receiptHash value in spentReceipt mapping , to make sure its false (double spending)
// the validateMPTProof from the EthereumProver library is called
// and returns a value whose inclusion is proved or an empty byte array for a proof of exclusion
// spentReceipt mapping is updated
// 

    function validateAndExecuteProof(
        uint256 blockNo,
        bytes32 rootHash,
        bytes calldata mptkey,
        bytes calldata proof
    ) external {
        bytes32 blockHash = bytes32(lightclient.blocksByHeight(blockNo, 0));
        require(
            lightclient.VerifyReceiptsHash(blockHash, rootHash),
            "wrong receipt hash"
        );
        bytes32 receiptHash = keccak256(
            abi.encodePacked(blockHash, rootHash, mptkey)
        );
        require(spentReceipt[receiptHash] == false, "double spent!");
        bytes memory rlpdata = EthereumProver.validateMPTProof(
            rootHash,
            mptkey,
            proof
        );
        spentReceipt[receiptHash] = true;
        uint256 executedEvents = execute(rlpdata);
        require(executedEvents > 0, "no valid event");
    }
}
