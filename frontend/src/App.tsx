// Copyright (c), Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0
import {
  ConnectButton,
  useCurrentAccount,
  useSignAndExecuteTransaction,
  useSuiClient,
} from "@mysten/dapp-kit";
import { Transaction } from "@mysten/sui/transactions";
import { Box, Button, Card, Container, Flex } from "@radix-ui/themes";
import React, { useEffect, useState } from "react";
import { useNetworkVariable } from "./networkConfig";
import { fromBase64, toHex, fromHex } from "@mysten/sui/utils";
import { bcs } from "@mysten/sui/bcs";

const API_URL = import.meta.env.VITE_API_URL || "";

const EnclaveConfigMove = bcs.struct("EnclaveConfig", {
  id: bcs.Address,
  name: bcs.string(),
  pcr0: bcs.vector(bcs.u8()),
  pcr1: bcs.vector(bcs.u8()),
  pcr2: bcs.vector(bcs.u8()),
});

function App() {
  const ENCLAVE_CONFIG_OBJ_ID = useNetworkVariable("enclaveConfigObjId");
  const EXAMPLE_PACKAGE_ID = useNetworkVariable("examplePackageId");
  const ENCLAVE_OBJ_ID = useNetworkVariable("enclaveObjId");

  const currentAccount = useCurrentAccount();
  const [userUrl, setUserUrl] = useState("");
  const [objectUrl, setObjectUrl] = useState("");
  const suiClient = useSuiClient();
  const [pcr0, setPcr0] = useState<string>("");
  const [pcr1, setPcr1] = useState<string>("");
  const [pcr2, setPcr2] = useState<string>("");
  const [error, setError] = useState<string | null>(null);
  const { mutate: signAndExecute } = useSignAndExecuteTransaction({
    execute: async ({ bytes, signature }) =>
      await suiClient.executeTransactionBlock({
        transactionBlock: bytes,
        signature,
        options: {
          showRawEffects: true,
          showEffects: true,
        },
      }),
  });

  useEffect(() => {
    const fetchPCRs = async () => {
      try {
        const res = await suiClient.getObject({
          id: ENCLAVE_CONFIG_OBJ_ID,
          options: {
            showBcs: true,
          },
        });

        if (!res || res.error || !res.data) {
          throw new Error(`missing enclave config object`);
        }

        if (!res.data.bcs || !("bcsBytes" in res.data.bcs)) {
          throw new Error(`Invalid enclave config object`);
        }

        const config = EnclaveConfigMove.parse(fromBase64(res.data.bcs.bcsBytes));
        setPcr0(toHex(new Uint8Array(config.pcr0)));
        setPcr1(toHex(new Uint8Array(config.pcr1)));
        setPcr2(toHex(new Uint8Array(config.pcr2)));
      } catch (error) {
        console.error("Error fetching PCRs:", error);
      }
    };

    fetchPCRs();
  }, []);

  const processUrlAndMint = async (twitterUrl: string) => {
    try {
      console.log("processing url", twitterUrl);
      console.log("processing API_URL", API_URL);

      const res = await fetch(`${API_URL}/process_data`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          payload: {
            user_url: twitterUrl.trim(),
          },
        }),
      });
      if (!res.ok) {
        console.error("Error:", res.statusText);
        setError("Invalid URL. Please try again.");
        return;
      }

      const data = await res.json();
      console.log("data", data);
      const { response, signature } = data;
      const { twitter_name, sui_address } = response.data;

      console.log("twitter_name", twitter_name);
      console.log("sui_address", sui_address);
      console.log("timestamp_ms", response.timestamp_ms);
      console.log("Signature before fromHEX:", signature);

      const tx = new Transaction();
      const twitter = tx.moveCall({
        target: `${EXAMPLE_PACKAGE_ID}::twitter::mint_nft`,
        arguments: [
          tx.pure.vector("u8", twitter_name),
          tx.pure.u64(response.timestamp_ms),
          tx.pure.vector("u8", fromHex(signature)),
          tx.object(ENCLAVE_OBJ_ID),
        ],
        typeArguments: [`${EXAMPLE_PACKAGE_ID}::twitter::TWITTER`],
      });
      tx.transferObjects([twitter], currentAccount?.address!);
      tx.setGasBudget(10000000);

      await signAndExecute(
        {
          transaction: tx,
        },
        {
          onSuccess: async (result) => {
            console.log("res", result);
            if (
              !result.effects ||
              !result.effects.created ||
              result.effects.created.length === 0
            ) {
              console.error("object created but no nft minted");
              setError(
                "Failed to mint NFT. Please check your input and try again.",
              );
              return;
            }
            setObjectUrl(result.effects!.created![0].reference.objectId);
          },
        },
      );
    } catch (error) {
      console.error("Error:", error);
      setError("Unknown error. Please try again.");
    }
  };

  return (
    <Container>
      {/* Top bar with connect button */}
      <Flex
        position="sticky"
        px="4"
        py="2"
        justify="end" // Align to the right
      >
        <Box>
          <ConnectButton />
        </Box>
      </Flex>

      {/* Centered title */}
      <Flex
        justify="center"
        align="center"
        my="8" // Add margin top/bottom
      >
        <h1 className="text-4xl font-bold m-4 mb-8">
          Mint Your Twitter Identity Onchain
        </h1>
      </Flex>
      <Card style={{ marginBottom: "2rem" }}>
        <p>
          1. Code is available{" "}
          <a href="https://github.com/MystenLabs/nautilus-twitter">here</a>.
        </p>
        <p>
          2. This is an example app for{" "}
          <a href="https://github.com/MystenLabs/nautilus-twitter">Nautilus</a>{" "}
          on Sui Testnet, and there are no incentives or rewards associated with
          it.
        </p>
        <p>
          3. This example is for Testnet only. Make sure you wallet is set to
          Testnet and has some balance (can request from{" "}
          <a href="https://faucet.sui.io/">faucet.sui.io</a>).
        </p>
        <p>
          4. The address you tweeted or posted in profile is indeed the address
          connected to this website. <br />- Example Profile (In description:
          address #SUI):{" "}
          <a
            href="https://x.com/mystenintern"
            target="_blank"
            rel="noopener noreferrer"
          >
            https://x.com/mystenintern
          </a>{" "}
          <br />- Example Tweet (Tweet content: address #SUI):{" "}
          <a
            href="https://x.com/mystenintern/status/1853217979774718028"
            target="_blank"
            rel="noopener noreferrer"
          >
            https://x.com/mystenintern/status/1853217979774718028
          </a>
        </p>
      </Card>
      <Flex direction="column" gap="2" justify="start">
        {currentAccount ? (
          <Card className="max-w-xs">
            <Flex direction="row" gap="2">
              <input
                style={{ width: "400px", padding: "8px" }}
                placeholder="Share your tweet or profile link!"
                onChange={(e) => setUserUrl(e.target.value)}
              />
              <Button
                size="3"
                onClick={() => {
                  processUrlAndMint(userUrl);
                }}
              >
                Mint
              </Button>
            </Flex>
            <Flex direction="column" gap="2">
              {objectUrl ? (
                <h1>
                  Twitter Identity Object:
                  <a
                    href={`https://testnet.suivision.xyz/object/${objectUrl}`}
                    target="_blank"
                    rel="noopener noreferrer"
                  >
                    {objectUrl}
                  </a>
                </h1>
              ) : null}
              {error ? <h1 className="text-red-500">Error: {error}</h1> : null}
            </Flex>
          </Card>
        ) : (
          <Card className="max-w-xs">
            <Flex direction="row" gap="2">
              <p className="m-4">Please connect your wallet on top right.</p>
            </Flex>
          </Card>
        )}

        <Card className="max-w-xs">
          <h2>Dont' trust, verify!</h2>
          <p>
            Build the software locally to compute the{" "}
            <a href="https://aws.amazon.com/ec2/nitro/nitro-enclaves/">
              AWS Nitro Enclave
            </a>{" "}
            <a
              href="https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-pcrs.html"
              target="_blank"
              rel="noopener noreferrer"
            >
              PCR values
            </a>
            . These values should match exactly with the{" "}
            <a
              href={`https://testnet.suivision.xyz/object/${ENCLAVE_CONFIG_OBJ_ID}`}
              target="_blank"
              rel="noopener noreferrer"
            >
              enclave config object
            </a>{" "}
            below, as they were registered onchain by the enclave administrator.
            This is an optional step allowing you to audit the enclave's
            integrity.
          </p>

          <p>
            <br />
            <code>
              git clone https://github.com/MystenLabs/nautilus-twitter <br />
              cd nautilus-twitter <br />
              git checkout example-configuration <br />
              make <br />
              cat out/nitro.pcrs
            </code>
          </p>
          <br />
          <h2>Enclave config object</h2>
          <p>
            <a
              href={`https://testnet.suivision.xyz/object/${ENCLAVE_CONFIG_OBJ_ID}`}
              target="_blank"
              rel="noopener noreferrer"
            >
              {ENCLAVE_CONFIG_OBJ_ID}
            </a>
            <br />
            <br />
            <b>PCR0:</b> {pcr0}
            <br />
            <b>PCR1:</b> {pcr1}
            <br />
            <b>PCR2:</b> {pcr2}
          </p>
        </Card>

        <Card className="max-w-xs">
          <h2>Why does this work?</h2> <br />
          <p>
            By posting a tweet or updating your profile, you prove ownership of
            your Twitter account. When you send the tweet or profile link to the
            enclave, it fetches the content and generates an attestation that
            binds your Twitter handle to your Wallet address. A Move smart
            contract then verifies the attestation and confirms that the
            transaction sender matches the address referenced in the
            attestation.
            <br />
            <br />
            <b>What if I tweeted someone else's address?</b> <br />
            <br />
            You cannot mint your Twitter handle to someone else’s address. The
            transaction will fail because the sender does not match the address
            specified in the attestation.
            <br />
            <b>
              What if someone else takes my Twitter profile URL and gets an
              attestation, then tries to mint that identity to their address?
            </b>{" "}
            <br />
            <br />
            For the same reason as above, only you - the wallet owner - can mint
            your Twitter handle, since no one else has access to your wallet.
          </p>
        </Card>
      </Flex>
    </Container>
  );
}

export default App;
