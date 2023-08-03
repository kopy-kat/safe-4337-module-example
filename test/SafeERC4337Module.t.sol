// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/Test.sol";

import "@safe/Safe.sol";
import "@safe/proxies/SafeProxyFactory.sol";
import "@safe/proxies/SafeProxy.sol";

import "@aa/core/EntryPoint.sol";

import {SafeERC4337Module} from "../src/SafeERC4337Module.sol";

contract SafeERC4337ModuleTest is Test {
    // Singletons
    Safe internal singleton;

    // Factories
    SafeProxyFactory internal proxyFactory;

    // Salt
    uint256 safeSalt = 0;

    // ERC4337 Entrypoint
    EntryPoint internal entrypoint;

    // Safe ERC4337 Module
    SafeERC4337Module internal safe4337Module;

    // Safe owner
    uint256 constant privateKey =
        0x8da4ef21b864d2cc526dbdb2a120bd2874c36c9d0a1fb7f8c63d7f7a8b41de8f;

    function setUp() public virtual {
        singleton = new Safe();

        proxyFactory = new SafeProxyFactory();

        entrypoint = new EntryPoint();

        // Safe ERC4337 Module
        safe4337Module = new SafeERC4337Module(address(entrypoint));
    }

    // Calculate UserOpHash to be used for the signature
    function getUserOpHash(
        address target,
        uint256 value,
        bytes memory data,
        uint8 operation // {0: Call, 1: DelegateCall}
    ) internal returns (bytes32) {
        bytes memory callData = getSafe4337TxCalldata(
            target,
            value,
            data,
            operation
        );
        UserOperation memory userOp = getPartialUserOp(callData);
        bytes32 userOpHash = entrypoint.getUserOpHash(userOp);
        return userOpHash;
    }

    // Execute a transaction on the Safe using the Safe4337Module
    function exec4337Transaction(
        address target,
        uint256 value,
        bytes memory callData,
        uint8 operation, // {0: Call, 1: DelegateCall}
        bytes memory signature
    ) public {
        bytes memory data = getSafe4337TxCalldata(
            target,
            value,
            callData,
            operation
        );

        if (signature.length == 0) {
            // TODO: generate default signature
            signature = bytes("");
        }
        exec4337Transaction(data, signature);
    }

    // Execute a transaction on the Safe using the Safe4337Module and arbitrary tx data and signature
    function exec4337Transaction(
        bytes memory data,
        bytes memory signature
    ) public {
        // Create UserOp array
        UserOperation[] memory userOps = new UserOperation[](1);

        // Construct UserOp
        userOps[0] = getPartialUserOp(data);
        userOps[0].signature = signature;

        // Send 1 ETH to Safe
        if (userOps[0].sender.balance < 1 ether) {
            vm.deal(userOps[0].sender, 1 ether);
        }

        // Send UserOp to Entrypoint
        entrypoint.handleOps(userOps, payable(address(0x69)));
    }

    function getSafeInitializer() public returns (bytes memory) {
        // Initial owner of safe
        address safeOwner = vm.addr(privateKey);

        // Add ERC4337 module on Safe deployment
        InitialModule[] memory modules = new InitialModule[](1);
        modules[0] = InitialModule({
            moduleAddress: address(safe4337Module),
            salt: 0,
            initializer: bytes("")
        });

        // Initial owners of Safe
        address[] memory owners = new address[](1);
        owners[0] = safeOwner;
        return
            abi.encodeWithSelector(
                Safe.setup.selector,
                owners, // owners
                1, // threshold
                address(0), // init module
                bytes(""), // init module calldata
                safe4337Module, // fallbackHandler
                address(0), // payment token
                0, // payment
                address(0) // payment receiver
            );
    }

    function getSafeAddress() public returns (address) {
        // Get initializer
        bytes memory initializer = getSafeInitializer();

        // Safe deployment data
        bytes memory deploymentData = abi.encodePacked(
            type(SafeProxy).creationCode,
            uint256(uint160(address(singleton)))
        );
        // Get salt
        // bytes32 salt = keccak256(abi.encodePacked(keccak256(initializer), saltNonce));
        bytes32 salt = keccak256(
            abi.encodePacked(keccak256(initializer), safeSalt)
        );
        bytes32 hash = keccak256(
            abi.encodePacked(
                bytes1(0xff),
                address(proxyFactory),
                salt,
                keccak256(deploymentData)
            )
        );
        return address(uint160(uint256(hash)));
    }

    function isDeployed(address _addr) private view returns (bool) {
        uint32 size;
        assembly {
            size := extcodesize(_addr)
        }
        return (size > 0);
    }

    function getCreate2Address(
        bytes memory bytecode,
        uint256 _salt
    ) public view returns (address) {
        bytes32 hash = keccak256(
            abi.encodePacked(
                bytes1(0xff),
                address(this),
                _salt,
                keccak256(bytecode)
            )
        );
        return address(uint160(uint256(hash)));
    }

    function getSafe4337TxCalldata(
        address target,
        uint256 value,
        bytes memory data,
        uint8 operation // {0: Call, 1: DelegateCall}
    ) internal returns (bytes memory) {
        // Get Safe address
        address sender = getSafeAddress();

        // Get nonce from Entrypoint
        uint256 nonce = entrypoint.getNonce(sender, 0);

        return
            abi.encodeWithSignature(
                "checkAndExecTransactionFromModule(address,address,uint256,bytes,uint8,uint256)",
                sender,
                target,
                value,
                data,
                operation,
                nonce
            );
    }

    function getPartialUserOp(
        bytes memory data
    ) internal returns (UserOperation memory) {
        // Get Safe address
        bytes memory initializer = getSafeInitializer();
        address sender = getSafeAddress();

        // Get Safe initCode
        bytes memory initCode;
        if (isDeployed(sender) == false) {
            initCode = abi.encodePacked(
                address(proxyFactory),
                abi.encodeWithSelector(
                    proxyFactory.createProxyWithNonce.selector,
                    address(singleton),
                    initializer,
                    safeSalt
                )
            );
        }

        // Get nonce from Entrypoint
        uint256 nonce = entrypoint.getNonce(sender, 0);

        UserOperation memory userOp = UserOperation({
            sender: sender,
            nonce: nonce,
            initCode: initCode,
            callData: data,
            callGasLimit: 2e6,
            verificationGasLimit: 2e6,
            preVerificationGas: 2e6,
            maxFeePerGas: 1,
            maxPriorityFeePerGas: 1,
            paymasterAndData: bytes(""),
            signature: bytes("")
        });
        return userOp;
    }
}
