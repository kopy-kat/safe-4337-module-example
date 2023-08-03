// SPDX-License-Identifier: LGPL-3.0-only
pragma solidity >=0.8.0 <0.9.0;

contract InitModule {
    address internal SENTINEL_ADDRESS = address(0x1);

    function initialise(address module) external {
        // Enable safe module
        bytes32 moduleSlot = keccak256(abi.encode(module, 1));
        bytes32 sentinelModuleSlot = keccak256(abi.encode(SENTINEL_ADDRESS, 1));
        assembly {
            sstore(moduleSlot, sload(0x00))
            sstore(sentinelModuleSlot, module)
            mstore(0x80, module)
            log1(
                0x80,
                0x20,
                // keccak256("EnabledModule(address)")
                0xecdf3a3effea5783a3c4c2140e677577666428d44ed9d474a0b3a4c9943f8440
            )
        }
    }
}
