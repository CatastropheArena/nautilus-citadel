# make
PCR0=9a2908930a9e7a899f3d8184082d4329cbfcf4835a4778fce551076ac3f115b8fd151600b3c05cf78c5a15c04fea7e1b
PCR1=9a2908930a9e7a899f3d8184082d4329cbfcf4835a4778fce551076ac3f115b8fd151600b3c05cf78c5a15c04fea7e1b
PCR2=21b9efbc184807662e966d34f390821309eeac6802309798826296bf3e8bec7c10edb30948c90ba67310f7b964fc500a

# # optionally
# sui client switch --env testnet # or appropriate network
# sui client faucet
# sui client gas

# # deploy the enclave package
# cd move/enclave
# sui move build
# sui client publish

# record ENCLAVE_PACKAGE_ID as env var from publish output
ENCLAVE_PACKAGE_ID=0x26d2510011bfc8801cfd5012f91c839aa59287915cff1553f78287acd4f0f571

# # deploy your dapp logic
# cd ../app
# sui move build
# sui client publish

# record CAP_OBJECT_ID (owned object of type Cap), ENCLAVE_CONFIG_OBJECT_ID (shared object), EXAMPLES_PACKAGE_ID (package containing weather module) as env var from publish output

CAP_OBJECT_ID=0x36dfd0cc9283c80dcc53ecc1738b0c2d4a54e2672dd68c25d6cc3ee0be29dce3
ENCLAVE_CONFIG_OBJECT_ID=0xa2660be2a193646fae16c8e337d584342034d44a2288d53c99644012efc01123
EXAMPLES_PACKAGE_ID=0xac5e532633c4254435242a2e64a0e92e7f9c1331d142a6d2c02330a1a9042c23

# record the deployed enclave url, e.g. http://<PUBLIC_IP>:3000
ENCLAVE_URL=http://54.92.134.161:3000

# the module name and otw name used to create the dapp, defined in your Move code `fun init`
MODULE_NAME=twitter
OTW_NAME=TWITTER

# make sure all env vars are populated
echo $EXAMPLES_PACKAGE_ID
echo $ENCLAVE_PACKAGE_ID
echo $CAP_OBJECT_ID
echo $ENCLAVE_CONFIG_OBJECT_ID
echo 0x$PCR0
echo 0x$PCR1
echo 0x$PCR2
echo $MODULE_NAME
echo $OTW_NAME
echo $ENCLAVE_URL

# =======
# the two steps below (update pcrs, register enclave) can be reused if enclave server is updated
# =======

# this calls the update_pcrs onchain with the enclave cap and built PCRs, this can be reused to update PCRs if Rust server code is updated
sui client call --function update_pcrs --module enclave --package $ENCLAVE_PACKAGE_ID --type-args "$EXAMPLES_PACKAGE_ID::$MODULE_NAME::$OTW_NAME" --args $ENCLAVE_CONFIG_OBJECT_ID $CAP_OBJECT_ID 0x$PCR0 0x$PCR1 0x$PCR2

# optional, give it a name you like
sui client call --function update_name --module enclave --package $ENCLAVE_PACKAGE_ID --type-args "$EXAMPLES_PACKAGE_ID::$MODULE_NAME::$OTW_NAME" --args $ENCLAVE_CONFIG_OBJECT_ID $CAP_OBJECT_ID "twitter enclave, updated 2025-04-29"

# this script calls the get_attestation endpoint from your enclave url and use it to calls register_enclave onchain to register the public key, results in the created enclave object
sh ../register_enclave.sh $ENCLAVE_PACKAGE_ID $EXAMPLES_PACKAGE_ID $ENCLAVE_CONFIG_OBJECT_ID $ENCLAVE_URL $MODULE_NAME $OTW_NAME

# record the created shared object ENCLAVE_OBJECT_ID as env var from register output
ENCLAVE_OBJECT_ID=0xeba18ee5924e82709fd03bad1298e38f879ede03954ed0db9ad88ec8628261c7


sui client call --function mint_nft --module twitter \
--args "luo_eurax" 1745918301276 "0x005c14d78096010000096c756f5f657572617820540ba39b0328acd14e100a8af76b7880e336abe08f806ada5643085794bd8aab" 0xeba18ee5924e82709fd03bad1298e38f879ede03954ed0db9ad88ec8628261c7 \
--package $EXAMPLES_PACKAGE_ID \
--type-args "$EXAMPLES_PACKAGE_ID::$MODULE_NAME::$OTW_NAME" \
--gas-budget 100000000
