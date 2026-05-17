// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract DaoProblemVault {
    mapping(address => uint256) public balances;
    address public owner;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    constructor() {
        owner = msg.sender;
    }

    receive() external payable {
        deposit();
    }

    function deposit() public payable {
        require(msg.value > 0, "deposit required");
        balances[msg.sender] += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function withdraw(uint256 amount) external {
        require(amount > 0, "amount required");
        require(balances[msg.sender] >= amount, "insufficient balance");

        (bool sent, ) = msg.sender.call{value: amount}("");
        require(sent, "transfer failed");

        balances[msg.sender] -= amount;
        emit Withdrawal(msg.sender, amount);
    }
}
