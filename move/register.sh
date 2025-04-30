# make
PCR0=3fc152fc3e3e7c4783a969478fb147ceec64d54cb27c5a363b02be7a7e73a4011cb878d3cd16dde32b14f772ef3c729c
PCR1=3fc152fc3e3e7c4783a969478fb147ceec64d54cb27c5a363b02be7a7e73a4011cb878d3cd16dde32b14f772ef3c729c
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
ENCLAVE_URL=http://13.217.113.41:3000

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
# sui client call --function update_pcrs --module enclave --package $ENCLAVE_PACKAGE_ID --type-args "$EXAMPLES_PACKAGE_ID::$MODULE_NAME::$OTW_NAME" --args $ENCLAVE_CONFIG_OBJECT_ID $CAP_OBJECT_ID 0x$PCR0 0x$PCR1 0x$PCR2

# optional, give it a name you like
# sui client call --function update_name --module enclave --package $ENCLAVE_PACKAGE_ID --type-args "$EXAMPLES_PACKAGE_ID::$MODULE_NAME::$OTW_NAME" --args $ENCLAVE_CONFIG_OBJECT_ID $CAP_OBJECT_ID "twitter enclave, updated 2025-04-29"

# this script calls the get_attestation endpoint from your enclave url and use it to calls register_enclave onchain to register the public key, results in the created enclave object
# sh ../register_enclave.sh $ENCLAVE_PACKAGE_ID $EXAMPLES_PACKAGE_ID $ENCLAVE_CONFIG_OBJECT_ID $ENCLAVE_URL $MODULE_NAME $OTW_NAME

# # record the created shared object ENCLAVE_OBJECT_ID as env var from register output
ENCLAVE_OBJECT_ID=0x7bd92db51df9730c8887445d22109e3d200b0ba19bd92c461da77d0aad7b4e79


sui client call --function mint_nft --module twitter \
--package $EXAMPLES_PACKAGE_ID \
--type-args "$EXAMPLES_PACKAGE_ID::$MODULE_NAME::$OTW_NAME" \
--args "luo_eurax" 1745937093978 "44016c80cc30a04ec1e71377de74c186fbd82cf9c205c8c7ba945180c5703df11c793604f15e782c638fbbc47069def331d2da2d4acc1ddb05dcbccd06c5e20e" 0x7bd92db51df9730c8887445d22109e3d200b0ba19bd92c461da77d0aad7b4e79 \
--gas-budget 100000000