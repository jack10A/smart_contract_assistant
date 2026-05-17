pragma solidity ^0.4.24;

contract SecurityTest {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;
    address public owner;

    constructor() public {
        owner = msg.sender;
    }

    // 1. REENTRANCY (RE)
    // Vulnerable: State variable updated AFTER the external call
    function withdrawAll() public {
        uint256 amount = balances[msg.sender];
        require(amount > 0);
        
        if (msg.sender.call.value(amount)()) {
            balances[msg.sender] = 0; 
        }
    }

    // 2. INTEGER OVERFLOW (OF)
    // Vulnerable: No SafeMath used in Solidity 0.4.24
    function contribute(uint256 _amount) public payable {
        balances[msg.sender] += _amount;
        totalSupply += _amount; // totalSupply can overflow
    }

    // 3. TIMESTAMP DEPENDENCY (TP)
    // Vulnerable: block.timestamp can be manipulated by miners
    function luckyDraw() public view returns (bool) {
        if (block.timestamp % 2 == 0) {
            return true;
        }
        return false;
    }

    // 4. DANGEROUS DELEGATECALL (DE)
    // Vulnerable: Allows arbitrary execution of code in this contract's context
    function executeAction(address _target, bytes _data) public {
        require(msg.sender == owner);
        if (!_target.delegatecall(_data)) {
            revert();
        }
    }
}