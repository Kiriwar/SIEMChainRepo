// SPDX-License-Identifier: MIT
pragma solidity ^0.6.12;

contract MessageStorage {
    // A state variable to store the message string
    address public owner;
    
    constructor() public {
        //Called only once when deploy 
        //This method will set whoever is the one who deploy this contract tobe owner of this contract
        owner = msg.sender;
    }

// Events are logged but NOT stored in contract state
event EpochFinalized(
    uint256 indexed epochId,
    string rootHash,
    string batchHash,
    uint256 timestamp,
    address submitter
);

function finalizeEpoch(uint256 epochId, string memory root, string memory batch) public {
    emit EpochFinalized(epochId, root, batch, block.timestamp, msg.sender);  // Log history
}
}
