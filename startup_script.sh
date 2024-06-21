# Check if Pulumi configuration files exist
if [ -f ./id_rsa_github_jwt.pem ]; then
    echo "private keys already generated."
    # pulumi login s3://pulumi-iac-state-storage
else
    echo "Did not find private key. generating new private key."

    # generate private key
    openssl genpkey -algorithm RSA -out private.pem -pkeyopt rsa_keygen_bits:2048
    # extatract public key from it
    openssl rsa -pubout -in private.pem -out public.pem
fi

