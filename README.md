
# JSD's GoDaddy+Lets encrypt wildcard cert page (+ le-godaddy-dns & dehydrated)

Please note this code is a fork of le-godaddy-dns and contains my rough nodes on how to get wildcard certs using GoDaddy's DNS. 

Please start off by reading through the original le-godaddy-dns notes. They are a great read with excellent information. I will only cover my steps below.

There is a side effect of using the patch api in which extra entries will be left in GoDaddy. This should not be a problem for GoDaddy and they can be cleaned up by hand later.

## Features added to le-godaddy-dns
 * Read dehydrated config file to pull in settings (le-godaddy-dns has no provision for configurable settings)
 * Switch to using godaddy's 'patch' api so we can add multiple records needed for wildcard cert validation (optional)
 * PFX Creation for windows environments (optional)


## Usage
### Register with lets encrypt
````
dehydrated --register --accept-terms
````
### Set Global's from Godaddy Key and Secret
````
export GD_KEY=_godaddy_api_key_
export GD_SECRET=_godaddy_api_secret_
# Required for PFX creation
export PKCS_PASSWORD=_your_pfx_password_
````
### Settings to add to dehydrated config
````
# Enable Hook chain setting
HOOK_CHAIN="yes"
# Define hook script
HOOK=_path_to_godaddy.py_
# Generate PFX file for windohs ;) (yes/no)
gdpy_gen_pfx=yes
# Use GoDaddy Patch APY (set to yes for wildcards) (yes/no)
gdpy_use_patch_api=yes
````

### Execute Dehydrated
````
cd _PATH_WITH_dehydrated_config_
dehydrated --challenge dns-01 -c --accept-terms

# For unit testing, changes, run the following to clear data
cd _PATH_WITH_dehydrated_config_
rm -rf ./accounts; rm -rf ./certs; rm -rf ./chains
````

## TODO
* Add tweak to dehydrated to pull in settings from command line such that will be set as if in config

## Other Notes

## testing GoDaddy using curl
### Deploy Challenge
````
curl -X PUT https://api.godaddy.com/v1/domains/${DOMAIN}/records/TXT -H "Authorization: sso-key ${GD_KEY}:${GD_SECRET}" -H "Content-Type: application/json" -d "[{\"name\": \"_acme-challenge.${DOMAIN}\", \"ttl\": 600, \"data\": \"VAL1\"}]"````
### Clean Challenge
````
curl -X PUT https://api.godaddy.com/v1/domains/${DOMAIN}/records/TXT -H "Authorization: sso-key ${GD_KEY}:${GD_SECRET}" -H "Content-Type: application/json" -d "[{\"name\": \"_acme-challenge.${DOMAIN}\", \"ttl\": 600, \"data\": \"--removed--\"}]"
````

## lexicon Notes
 * Lexicon is not usable for creating multiple keys. Ergo not suitible for wildcard registrations
### Lexicon calls
#### Create Key
````
% lexicon ${PROVIDER} create ${DOMAIN} TXT --name="_acme-challenge.${DOMAIN}." --content="${TOKEN_VAL}" --auth-key ${GD_KEY} --auth-secret ${GD_SECRET}
````
#### Delete Key
````
% lexicon ${PROVIDER} delete ${DOMAIN} TXT --name="_acme-challenge.${DOMAIN}." --content="${TOKEN_VAL}" --auth-key ${GD_KEY} --auth-secret ${GD_SECRET}
````
