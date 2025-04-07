import { HardhatUserConfig } from "hardhat/config";
require("hardhat-tracer");

// foundry support
import "@nomicfoundation/hardhat-foundry";
import "@nomicfoundation/hardhat-toolbox";

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.28",
    settings: {
      optimizer: {
        enabled: true,
        runs: 20000
      }
    }
  },
};

export default config;