## Contract Deployment Input JSON

To resolve dependencies between the contract deployments, a `.json` file named [Deployment_input.json](script/json/Deployment_input.json) is created in this [script/json](script/json) folder and populated with contract addresses for the following contracts after they are deployed (either as single deployments or part of the single run deployment for all contracts):
* BlocklockSender (proxy address)
* DecryptionSender (proxy address)
* SignatureSchemeAddressProvider

The addresses from this input file are read in by scripts using them. To overwrite the addresses in this file, replace them with the relevant address for each contract.

For example, running the following command writes a JSON property `{"signatureSchemeAddressProviderAddress": "0x7D020A4E3D8795581Ec06E0e57701dDCf7B19EDF"}` to the Deployment_input.json file:

```bash
forge script script/single-deployments/DeploySignatureSchemeAddressProvider.s.sol:DeploySignatureSchemeAddressProvider --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast --slow 
```