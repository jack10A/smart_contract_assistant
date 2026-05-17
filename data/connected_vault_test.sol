// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract ConnectedVault {
    mapping(address => uint256) public balances;
    address public owner;
    address public plugin;
    uint256 public unlockTime;

    constructor(address _plugin) {
        owner = msg.sender;
        plugin = _plugin;
        unlockTime = block.timestamp + 1 days;
    }

    receive() external payable {
        balances[msg.sender] += msg.value;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(block.timestamp >= unlockTime, "vault locked");
        require(balances[msg.sender] >= amount, "insufficient balance");

        (bool sent, ) = msg.sender.call{value: amount}("");
        require(sent, "transfer failed");

        balances[msg.sender] -= amount;
    }

    function executePlugin(bytes calldata data) external {
        require(msg.sender == owner, "only owner");
        (bool ok, ) = plugin.delegatecall(data);
        require(ok, "plugin failed");
    }

    function extendLock(uint256 secondsToAdd) external {
        require(msg.sender == owner, "only owner");
        unlockTime = block.timestamp + secondsToAdd;
    }
}
