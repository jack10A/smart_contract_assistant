// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract DaoSolutionVault {
    mapping(address => uint256) public balances;
    address public owner;
    bool private locked;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    modifier nonReentrant() {
        require(!locked, "reentrant call blocked");
        locked = true;
        _;
        locked = false;
    }

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

    function withdraw(uint256 amount) external nonReentrant {
        require(amount > 0, "amount required");
        uint256 userBalance = balances[msg.sender];
        require(userBalance >= amount, "insufficient balance");

        balances[msg.sender] = userBalance - amount;

        (bool sent, ) = msg.sender.call{value: amount}("");
        require(sent, "transfer failed");

        emit Withdrawal(msg.sender, amount);
    }
}
