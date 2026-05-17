pragma solidity ^0.4.24;

contract SlitherTest {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() public {
        owner = msg.sender;
    }

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdrawAll() public {
        uint256 amount = balances[msg.sender];

        require(amount > 0);

        msg.sender.call.value(amount)();

        balances[msg.sender] = 0;
    }

    function runPlugin(address _plugin, bytes _data) public {
        require(msg.sender == owner);

        _plugin.delegatecall(_data);
    }

    function lottery() public view returns (bool) {
        return block.timestamp % 2 == 0;
    }

    function sendEther(address _to) public payable {
        _to.send(msg.value);
    }
}
