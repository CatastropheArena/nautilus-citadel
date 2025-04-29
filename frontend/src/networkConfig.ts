// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
import { getFullnodeUrl } from "@mysten/sui/client";
import { createNetworkConfig } from "@mysten/dapp-kit";

const EXAMPLE_PACKAGE_ID = "0xac5e532633c4254435242a2e64a0e92e7f9c1331d142a6d2c02330a1a9042c23";
const ENCLAVE_CONFIG_OBJECT_ID = "0xa2660be2a193646fae16c8e337d584342034d44a2288d53c99644012efc01123";
const ENCLAVE_OBJECT_ID = "0x7bd92db51df9730c8887445d22109e3d200b0ba19bd92c461da77d0aad7b4e79";

const { networkConfig, useNetworkVariable, useNetworkVariables } =
  createNetworkConfig({
    testnet: {
      url: getFullnodeUrl("testnet"),
      variables: {
        examplePackageId: EXAMPLE_PACKAGE_ID,
        enclaveObjId: ENCLAVE_OBJECT_ID,
        enclaveConfigObjId: ENCLAVE_CONFIG_OBJECT_ID,
      },
    },
  });

export { useNetworkVariable, useNetworkVariables, networkConfig };
