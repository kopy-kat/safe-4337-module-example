# Safe 4337 Module Draft

Note: This is a draft of a Safe 4337 Module. It is not complete and definitely not ready for production use. Use at your own risk.

## How to run the tests

1. Install the submodules using `forge install`
2. Run `forge test` to run the tests

## How to use

1. Deploy the 4337 module
2. Add the module to the safe by calling `enableModule(address module)` on the Safe
3. Enable the 4337 module as the Safe fallback handler
4. Call the Safe from the Entrypoint using a UserOperation
