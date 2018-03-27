#!/usr/bin/env python3
# fork of https://github.com/josteink/le-godaddy-dns

import os
import sys
import logging
from tld import get_tld
import time
import godaddypy
from OpenSSL import crypto
import configparser

if "GD_KEY" not in os.environ:
    raise Exception("Missing Godaddy API-key in GD_KEY environment variable! Please register one at https://developer.godaddy.com/keys/")

if "GD_SECRET" not in os.environ:
    raise Exception("Missing Godaddy API-secret in GD_SECRET environment variable! Please register one at https://developer.godaddy.com/keys/")

my_acct = godaddypy.Account(
    api_key=os.environ["GD_KEY"], 
    api_secret=os.environ["GD_SECRET"]
)
client = godaddypy.Client(my_acct)

logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler())
logger.setLevel(logging.INFO)

def _get_zone(domain):
    d = get_tld(domain,as_object=True,fix_protocol=True)
    return d.tld


def _get_subdomain_for(domain, zone):
    subdomain = domain[0:(-len(zone)-1)]
    return subdomain

def _add_dns_rec(domain, token):
    challengedomain = "_acme-challenge." + domain
    logger.info(" + Adding TXT record for {0} to '{1}'.".format(challengedomain, token))
    zone = _get_zone(challengedomain)
    # logger.info("Zone to update: {0}".format(zone))
    subdomain = _get_subdomain_for(challengedomain, zone)
    # logger.info("Subdomain name: {0}".format(subdomain))

    record = {
        'name': subdomain,
        'data': token,
        'ttl': 600,
        'type': 'TXT'
    }
    result=None
    try:
        result = client.add_record(zone, record)
    except godaddypy.client.BadResponse as err:
        msg=str(err)
        if msg.find('DUPLICATE_RECORD') > -1:
            logger.info(" + . Duplicate record found. Skipping.")
            return
        logger.warn("Error returned {0}.".format(err))
    if result is not True:
        logger.warn("Error updating record for domain {0}.".format(domain))
    else:
        logger.info(" + . Record added")

def _update_dns(domain, token):
    challengedomain = "_acme-challenge." + domain
    logger.info(" + Updating TXT record for {0} to '{1}'.".format(challengedomain, token))
    zone = _get_zone(challengedomain)
    # logger.info("Zone to update: {0}".format(zone))
    subdomain = _get_subdomain_for(challengedomain, zone)
    # logger.info("Subdomain name: {0}".format(subdomain))

    record = {
        'name': subdomain,
        'data': token,
        'ttl': 600,
        'type': 'TXT'
    }
    result = client.update_record(zone, record)
    if result is not True:
        logger.warn("Error updating record for domain {0}.".format(domain))


def create_txt_record(args):

    dehyd_config=loadDehydratedConfig()    
    gdpy_use_patch_api = True if dehyd_config is not None \
        and "gdpy_use_patch_api" in dehyd_config \
        and dehyd_config['gdpy_use_patch_api'] == 'yes' else False
    logger.info("gdpy_use_patch_api: {0}".format(gdpy_use_patch_api))

    for i in range(0, len(args), 3):
        domain, token = args[i], args[i+2]
        if gdpy_use_patch_api:
            _add_dns_rec(domain, token)
        else:
            _update_dns(domain, token)
        time.sleep(2)
    # a sleep is needed to allow DNS propagation
    logger.info(" + Sleeping to wait for DNS propagation")
    time.sleep(30)


def delete_txt_record(args):
    for i in range(0, len(args), 3):
        domain = args[i]
        # using client.delete_record() is dangerous. null it instead!
        # https://github.com/eXamadeus/godaddypy/issues/13

        if domain == "":
            logger.warn("Error deleting record, the domain argument is empty")
        else:
            _update_dns(domain, "_dehydrated-was-here_")


def deploy_cert(args):
    domain, privkey_pem, cert_pem, fullchain_pem, chain_pem, timestamp = args
    logger.info(' + ssl_certificate: {0}'.format(fullchain_pem))
    logger.info(' + ssl_certificate_key: {0}'.format(privkey_pem))

    dehyd_config=loadDehydratedConfig()    
    gdpy_gen_pfx = True if dehyd_config is not None \
        and "gdpy_gen_pfx" in dehyd_config \
        and dehyd_config['gdpy_gen_pfx'] == 'yes' else False
    logger.info("gdpy_gen_pfx: {0}".format(gdpy_gen_pfx))

    if gdpy_gen_pfx is True:
        if "PKCS_PASSWORD" not in os.environ:
            raise Exception("Missing PKCS Password in PKCS_PASSWORD environment variable!")
        # Create PFX for IIS
        pfx_pem = generate_pfx(args)
    
    return

def generate_pfx(args):
    domain, privkey_pem, cert_pem, fullchain_pem, chain_pem, timestamp = args

    logger.info("args: {0}".format(args))
    pfx_pem=cert_pem.replace("cert.pem", "cert.pfx")

    # Read in cert
    cert = crypto.load_certificate(
        crypto.FILETYPE_PEM, open(cert_pem, 'rt').read()
    )

    # Read in private key
    privkey = crypto.load_privatekey(
        crypto.FILETYPE_PEM, open(privkey_pem, 'rt').read()
    )

    # Generate PFX
    pfx = crypto.PKCS12Type()
    pfx.set_privatekey(privkey)
    pfx.set_certificate(cert)
    pfxdata = pfx.export(os.environ["PKCS_PASSWORD"])

    # Write PFX to file
    with open(pfx_pem, 'wb') as f:
        f.write(pfxdata)
    
    logger.info(' + PFX File Created: {0}'.format(pfx_pem))
    return pfx_pem

def loadDehydratedConfig():
    
    dehyConfigPath=os.environ["CONFIG"]

    if os.path.isfile(dehyConfigPath) is False:
        logger.info(" + godaddy.py: dehydrated config not found in env var CONFIG. Ignoring.")
        return None
    else:
        config_string=None
        with open(dehyConfigPath, 'r') as f:
            config_string = '[dummy]\n' + f.read()
        cp = configparser.ConfigParser()
        cp.read_string(config_string)
        dehyd_config=cp._sections['dummy']
        # logger.info("dehyd_config: {0}".format(dehyd_config))
    return dehyd_config


def invalid_challenge(args):
    [domain, response] = args
    logger.warn(" + invalid challenge for domain {0}: {1}".format(domain, response))
    return


def request_failure(args):
    [status_code, err_txt, req_type] = args
    logger.warn(" + Request failed with status code: {0}, {1}, type: {2}".format(status_code, err_txt, req_type))
    return


def main(argv):
    
    ops = {
        'deploy_challenge': create_txt_record,
        'clean_challenge' : delete_txt_record,
        'deploy_cert'     : deploy_cert,
        'invalid_challenge': invalid_challenge,
        'request_failure' : request_failure
    }

    opname = argv[0]
    if opname not in ops:
        return
    else:
        logger.info(" + Godaddy hook executing: {0}".format(opname))
        ops[opname](argv[1:])


if __name__ == '__main__':
    main(sys.argv[1:])
