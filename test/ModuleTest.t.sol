// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./SafeERC4337ModuleTestLib.t.sol";

contract ModuleTest is SafeERC4337ModuleTestLib {
    function setUp() public override {
        super.setUp();
    }

    function testSendTx() public {
        exec4337Transaction(address(0x420), 10 gwei, bytes(""), 0, bytes(""));
        require(address(0x420).balance == 10 gwei, "Balance not updated");
    }
}
