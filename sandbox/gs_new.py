import time

from indy import anoncreds, crypto, did, ledger, pool, wallet, blob_storage

import json
import logging

import argparse
import sys
from ctypes import *
from os.path import dirname

from indy.error import ErrorCode, IndyError

from src.utils import get_pool_genesis_txn_path, run_coroutine, PROTOCOL_VERSION

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

parser = argparse.ArgumentParser(description='Run python getting-started scenario (michael/Faber)')
parser.add_argument('-t', '--storage_type', help='load custom wallet storage plug-in')
parser.add_argument('-l', '--library', help='dynamic library to load for plug-in')
parser.add_argument('-e', '--entrypoint', help='entry point for dynamic library')
parser.add_argument('-c', '--config', help='entry point for dynamic library')
parser.add_argument('-s', '--creds', help='entry point for dynamic library')

args = parser.parse_args()


# check if we need to dyna-load a custom wallet storage plug-in
if args.storage_type:
    if not (args.library and args.entrypoint):
        parser.print_help()
        sys.exit(0)
    stg_lib = CDLL(args.library)
    result = stg_lib[args.entrypoint]()
    if result != 0:
        print("Error unable to load wallet storage", result)
        parser.print_help()
        sys.exit(0)

    print("Success, loaded wallet storage", args.storage_type)

async def get_facial_scan_data():
    return "guid"

async def run():
    print("Getting started -> started")

    pool_ = {
        'name': 'pool1'
    }
    print("Open Pool Ledger: {}".format(pool_['name']))
    pool_['genesis_txn_path'] = get_pool_genesis_txn_path(pool_['name'])
    pool_['config'] = json.dumps({"genesis_txn": str(pool_['genesis_txn_path'])})

    # Set protocol version 2 to work with Indy Node 1.4
    await pool.set_protocol_version(PROTOCOL_VERSION)

    try:
        await pool.create_pool_ledger_config(pool_['name'], pool_['config'])
    except IndyError as ex:
        if ex.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
            pass
    pool_['handle'] = await pool.open_pool_ledger(pool_['name'], None)

    print("\n==============================")
    print("=== Getting Trust Anchor credentials for Faber, sovrin, door_access and Government  ==")
    print("------------------------------")

    print("\"Sovrin Steward\" -> Create wallet")
    steward = {
        'name': "Sovrin Steward",
        'wallet_config': json.dumps({'id': 'sovrin_steward_wallet'}),
        'wallet_credentials': json.dumps({'key': 'steward_wallet_key'}),
        'pool': pool_['handle'],
        'seed': '000000000000000000000000Steward1'
    }

    try:
        await wallet.create_wallet(steward['wallet_config'], steward['wallet_credentials'])
    except IndyError as ex:
        if ex.error_code == ErrorCode.WalletAlreadyExistsError:
            pass

    steward['wallet'] = await wallet.open_wallet(steward['wallet_config'], steward['wallet_credentials'])

    print("\"Sovrin Steward\" -> Create and store in Wallet DID from seed")
    steward['did_info'] = json.dumps({'seed': steward['seed']})
    steward['did'], steward['key'] = await did.create_and_store_my_did(steward['wallet'], steward['did_info'])

    print("\n==============================")
    print("== Getting Trust Anchor credentials - Government Onboarding  ==")
    print("------------------------------")

    government = {
        'name': 'Government',
        'wallet_config': json.dumps({'id': 'government_wallet'}),
        'wallet_credentials': json.dumps({'key': 'government_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'TRUST_ANCHOR'
    }
    steward['did_for_government'], steward['key_for_government'], government['did_for_steward'], \
    government['key_for_steward'], _ = await onboarding(steward, government)

    print("\n==============================")
    print("== Getting Trust Anchor credentials - Government getting Verinym  ==")
    print("------------------------------")

    government['did'] = await get_verinym(steward, steward['did_for_government'], steward['key_for_government'],
                                          government, government['did_for_steward'], government['key_for_steward'])

    print("\n==============================")
    print("== Getting Trust Anchor credentials - Faber Onboarding  ==")
    print("------------------------------")

    faber = {
        'name': 'Faber',
        'wallet_config': json.dumps({'id': 'faber_wallet'}),
        'wallet_credentials': json.dumps({'key': 'faber_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'TRUST_ANCHOR'
    }
    steward['did_for_faber'], steward['key_for_faber'], faber['did_for_steward'], faber['key_for_steward'], _ = \
        await onboarding(steward, faber)

    print("\n==============================")
    print("== Getting Trust Anchor credentials - Faber getting Verinym  ==")
    print("------------------------------")

    faber['did'] = \
        await get_verinym(steward, steward['did_for_faber'], steward['key_for_faber'],
                          faber, faber['did_for_steward'], faber['key_for_steward'])

    print("\n==============================")
    print("== Getting Trust Anchor credentials - sovrin Onboarding  ==")
    print("------------------------------")

    sovrin = {
        'name': 'sovrin',
        'wallet_config': json.dumps({'id': 'sovrin_wallet'}),
        'wallet_credentials': json.dumps({'key': 'sovrin_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'TRUST_ANCHOR'
    }
    steward['did_for_sovrin'], steward['key_for_sovrin'], sovrin['did_for_steward'], sovrin['key_for_steward'], _ = \
        await onboarding(steward, sovrin)

    print("\n==============================")
    print("== Getting Trust Anchor credentials - sovrin getting Verinym  ==")
    print("------------------------------")

    sovrin['did'] = await get_verinym(steward, steward['did_for_sovrin'], steward['key_for_sovrin'],
                                    sovrin, sovrin['did_for_steward'], sovrin['key_for_steward'])

    print("\n==============================")
    print("== Getting Trust Anchor credentials - door_access Onboarding  ==")
    print("------------------------------")

    door_access = {
        'name': 'door_access',
        'wallet_config': json.dumps({'id': 'door_access_wallet'}),
        'wallet_credentials': json.dumps({'key': 'door_access_wallet_key'}),
        'pool': pool_['handle'],
        'role': 'TRUST_ANCHOR'
    }
    steward['did_for_door_access'], steward['key_for_door_access'], door_access['did_for_steward'], door_access['key_for_steward'], _ = \
        await onboarding(steward, door_access)

    print("==============================")
    print("== Getting Trust Anchor credentials - door_access getting Verinym  ==")
    print("------------------------------")

    door_access['did'] = await get_verinym(steward, steward['did_for_door_access'], steward['key_for_door_access'],
                                      door_access, door_access['did_for_steward'], door_access['key_for_steward'])

    print("\n==============================")
    print("=== Credential Schemas Setup ==")
    print("------------------------------")

    print("\"Government\" -> Create \"Id-Card\" Schema")
    id_card = {
        'name': 'Id-Card',
        'version': '0.2',
        'attributes': ['first_name', 'last_name', 'birth_date', 'facial_scan']
    }
    (government['id_card_schema_id'], government['id_card_schema']) = \
        await anoncreds.issuer_create_schema(government['did'], id_card['name'], id_card['version'],
                                             json.dumps(id_card['attributes']))
    id_card_schema_id = government['id_card_schema_id']

    print("\"Government\" -> Send \"Id-Card\" Schema to Ledger")
    await send_schema(government['pool'], government['wallet'], government['did'], government['id_card_schema'])

######
    print("\"Government\" -> Create \"Job-Certificate\" Schema")
    job_certificate = {
        'name': 'Job-Certificate',
        'version': '0.2',
        'attributes': ['first_name', 'last_name', 'employee_status', 'start_date', 'salary']
    }
    (government['job_certificate_schema_id'], government['job_certificate_schema']) = \
        await anoncreds.issuer_create_schema(government['did'], job_certificate['name'], job_certificate['version'],
                                             json.dumps(job_certificate['attributes']))
    job_certificate_schema_id = government['job_certificate_schema_id']

    print("\"Government\" -> Send \"Job-Certificate\" Schema to Ledger")
    await send_schema(government['pool'], government['wallet'], government['did'], government['job_certificate_schema'])

#####
    print("\"Government\" -> Create \"Transcript\" Schema")
    transcript = {
        'name': 'Transcript',
        'version': '1.2',
        'attributes': ['first_name', 'last_name', 'degree', 'status', 'year', 'average', 'ssn']
    }
    (government['transcript_schema_id'], government['transcript_schema']) = \
        await anoncreds.issuer_create_schema(government['did'], transcript['name'], transcript['version'],
                                             json.dumps(transcript['attributes']))
    transcript_schema_id = government['transcript_schema_id']

    print("\"Government\" -> Send \"Transcript\" Schema to Ledger")
    await send_schema(government['pool'], government['wallet'], government['did'], government['transcript_schema'])

    time.sleep(1)  # sleep 1 second before getting schema




    print("\n==============================")
    print("=== Government Credential Definition Setup ==")
    print("------------------------------")

    print("\"Government\" -> Get \"id_card\" Schema from Ledger")
    (government['id_card_schema_id'], government['id_card_schema']) = \
        await get_schema(government['pool'], government['did'], id_card_schema_id)

    print("\"government\" -> Create and store in Wallet \"government id_card\" Credential Definition")
    id_card_cred_def = {
        'tag': 'TAG1',
        'type': 'CL',
        'config': {"support_revocation": False}
    }
    (government['id_card_cred_def_id'], government['id_card_cred_def']) = \
        await anoncreds.issuer_create_and_store_credential_def(government['wallet'], government['did'],
                                                               government['id_card_schema'], id_card_cred_def['tag'],
                                                               id_card_cred_def['type'],
                                                               json.dumps(id_card_cred_def['config']))


    print("\"government\" -> Send  \"government id_card\" Credential Definition to Ledger")
    await send_cred_def(government['pool'], government['wallet'], government['did'], government['id_card_cred_def'])
    ######
    
    print("\n==============================")
    print("=== Faber Credential Definition Setup ==")
    print("------------------------------")
    print("\"Faber\" -> Get \"Transcript\" Schema from Ledger")
    (faber['transcript_schema_id'], faber['transcript_schema']) = \
        await get_schema(faber['pool'], faber['did'], transcript_schema_id)

    print("\"Faber\" -> Create and store in Wallet \"Faber Transcript\" Credential Definition")
    transcript_cred_def = {
        'tag': 'TAG1',
        'type': 'CL',
        'config': {"support_revocation": False}
    }
    (faber['transcript_cred_def_id'], faber['transcript_cred_def']) = \
        await anoncreds.issuer_create_and_store_credential_def(faber['wallet'], faber['did'],
                                                               faber['transcript_schema'], transcript_cred_def['tag'],
                                                               transcript_cred_def['type'],
                                                               json.dumps(transcript_cred_def['config']))

    print("\"Faber\" -> Send  \"Faber Transcript\" Credential Definition to Ledger")
    await send_cred_def(faber['pool'], faber['wallet'], faber['did'], faber['transcript_cred_def'])

    print("\n==============================")
    print("=== Sovrin Credential Definition Setup ==")
    print("------------------------------")

    print("\"sovrin\" -> Get from Ledger \"Job-Certificate\" Schema")
    (sovrin['job_certificate_schema_id'], sovrin['job_certificate_schema']) = \
        await get_schema(sovrin['pool'], sovrin['did'], job_certificate_schema_id)

    print("\"sovrin\" -> Create and store in Wallet \"sovrin Job-Certificate\" Credential Definition")
    job_certificate_cred_def = {
        'tag': 'TAG1',
        'type': 'CL',
        'config': {"support_revocation": True}
    }
    (sovrin['job_certificate_cred_def_id'], sovrin['job_certificate_cred_def']) = \
        await anoncreds.issuer_create_and_store_credential_def(sovrin['wallet'], sovrin['did'],
                                                               sovrin['job_certificate_schema'],
                                                               job_certificate_cred_def['tag'],
                                                               job_certificate_cred_def['type'],
                                                               json.dumps(job_certificate_cred_def['config']))

    print("\"sovrin\" -> Send \"sovrin Job-Certificate\" Credential Definition to Ledger")
    await send_cred_def(sovrin['pool'], sovrin['wallet'], sovrin['did'], sovrin['job_certificate_cred_def'])

    print("\"sovrin\" -> Creates Revocation Registry")
    sovrin['tails_writer_config'] = json.dumps({'base_dir': "/tmp/indy_sovrin_tails", 'uri_pattern': ''})
    tails_writer = await blob_storage.open_writer('default', sovrin['tails_writer_config'])
    (sovrin['revoc_reg_id'], sovrin['revoc_reg_def'], sovrin['revoc_reg_entry']) = \
        await anoncreds.issuer_create_and_store_revoc_reg(sovrin['wallet'], sovrin['did'], 'CL_ACCUM', 'TAG1',
                                                          sovrin['job_certificate_cred_def_id'],
                                                          json.dumps({'max_cred_num': 5,
                                                                      'issuance_type': 'ISSUANCE_ON_DEMAND'}),
                                                          tails_writer)

    print("\"sovrin\" -> Post Revocation Registry Definition to Ledger")
    sovrin['revoc_reg_def_request'] = await ledger.build_revoc_reg_def_request(sovrin['did'], sovrin['revoc_reg_def'])
    await ledger.sign_and_submit_request(sovrin['pool'], sovrin['wallet'], sovrin['did'], sovrin['revoc_reg_def_request'])

    print("\"sovrin\" -> Post Revocation Registry Entry to Ledger")
    sovrin['revoc_reg_entry_request'] = \
        await ledger.build_revoc_reg_entry_request(sovrin['did'], sovrin['revoc_reg_id'], 'CL_ACCUM',
                                                   sovrin['revoc_reg_entry'])
    await ledger.sign_and_submit_request(sovrin['pool'], sovrin['wallet'], sovrin['did'], sovrin['revoc_reg_entry_request'])
    print("\n==============================")
    print("=== All Schema, Credentials, and Definitions have been created. ===")
    print("==============================")
    input("=== Press Enter To Continue... ===")
    
    
    
    ###############
    ###############
    ###############



    print("==============================")
    print("=== Now Getting id_card with government ==")
    print("==============================")
    print("== Getting id_card with government - Onboarding ==")
    print("------------------------------")

    michael = {
        'name': 'michael',
        'wallet_config': json.dumps({'id': 'michael_wallet'}),
        'wallet_credentials': json.dumps({'key': 'michael_wallet_key'}),
        'pool': pool_['handle'],
    }
    government['did_for_michael'], government['key_for_michael'], michael['did_for_government'], michael['key_for_government'], \
    government['michael_connection_response'] = await onboarding(government, michael)

    print("\n==============================")
    print("== Getting id_card with government - Getting id_card Credential ==")
    input("=== Press Enter To Continue... ===\n------------------------------")

    print("\"government\" -> Create \"id_card\" Credential Offer for michael")
    government['id_card_cred_offer'] = \
        await anoncreds.issuer_create_credential_offer(government['wallet'], government['id_card_cred_def_id'])

    print("\"government\" -> Get key for michael did")
    government['michael_key_for_government'] = \
        await did.key_for_did(government['pool'], government['wallet'], government['michael_connection_response']['did'])

    print("\"government\" -> Authcrypt \"id_card\" Credential Offer for michael")
    government['authcrypted_id_card_cred_offer'] = \
        await crypto.auth_crypt(government['wallet'], government['key_for_michael'], government['michael_key_for_government'],
                                government['id_card_cred_offer'].encode('utf-8'))

    print("\"government\" -> Send authcrypted \"id_card\" Credential Offer to michael")
    michael['authcrypted_id_card_cred_offer'] = government['authcrypted_id_card_cred_offer']

    print("\"michael\" -> Authdecrypted \"id_card\" Credential Offer from government")
    michael['government_key_for_michael'], michael['id_card_cred_offer'], authdecrypted_id_card_cred_offer = \
        await auth_decrypt(michael['wallet'], michael['key_for_government'], michael['authcrypted_id_card_cred_offer'])
    michael['id_card_schema_id'] = authdecrypted_id_card_cred_offer['schema_id']
    michael['id_card_cred_def_id'] = authdecrypted_id_card_cred_offer['cred_def_id']

    print("\"michael\" -> Create and store \"michael\" Master Secret in Wallet")
    michael['master_secret_id'] = await anoncreds.prover_create_master_secret(michael['wallet'], None)

    print("\"michael\" -> Get \"government id_card\" Credential Definition from Ledger")
    (michael['government_id_card_cred_def_id'], michael['government_id_card_cred_def']) = \
        await get_cred_def(michael['pool'], michael['did_for_government'], michael['id_card_cred_def_id'])

    print("\"michael\" -> Create \"id_card\" Credential Request for government")
    (michael['id_card_cred_request'], michael['id_card_cred_request_metadata']) = \
        await anoncreds.prover_create_credential_req(michael['wallet'], michael['did_for_government'],
                                                     michael['id_card_cred_offer'], michael['government_id_card_cred_def'],
                                                     michael['master_secret_id'])

    print("\"michael\" -> Authcrypt \"id_card\" Credential Request for government")
    michael['authcrypted_id_card_cred_request'] = \
        await crypto.auth_crypt(michael['wallet'], michael['key_for_government'], michael['government_key_for_michael'],
                                michael['id_card_cred_request'].encode('utf-8'))

    print("\"michael\" -> Send authcrypted \"id_card\" Credential Request to government")
    government['authcrypted_id_card_cred_request'] = michael['authcrypted_id_card_cred_request']

    print("\"government\" -> Authdecrypt \"id_card\" Credential Request from michael")
    government['michael_key_for_government'], government['id_card_cred_request'], _ = \
        await auth_decrypt(government['wallet'], government['key_for_michael'], government['authcrypted_id_card_cred_request'])

    print("\"government\" -> Create \"id_card\" Credential for michael")
    government['michael_id_card_cred_values'] = json.dumps({
        "first_name": {"raw": "michael", "encoded": "1139481716457488690172217916278103335"},
        "last_name": {"raw": "Garcia", "encoded": "5321642780241790123587902456789123452"},
        "birth_date": {"raw": "Bachelor of Science, Marketing", "encoded": "12434523576212321"},
        "facial_scan": {"raw": "graduated", "encoded": "2213454313412354"}
    })
    
    government['id_card_cred'], _, _ = \
        await anoncreds.issuer_create_credential(government['wallet'], government['id_card_cred_offer'],
                                                 government['id_card_cred_request'],
                                                 government['michael_id_card_cred_values'], None, None)

    print("\"government\" -> Authcrypt \"id_card\" Credential for michael")
    government['authcrypted_id_card_cred'] = \
        await crypto.auth_crypt(government['wallet'], government['key_for_michael'], government['michael_key_for_government'],
                                government['id_card_cred'].encode('utf-8'))

    print("\"government\" -> Send authcrypted \"id_card\" Credential to michael")
    michael['authcrypted_id_card_cred'] = government['authcrypted_id_card_cred']

    print("\"michael\" -> Authdecrypted \"id_card\" Credential from government")
    _, michael['id_card_cred'], _ = \
        await auth_decrypt(michael['wallet'], michael['key_for_government'], michael['authcrypted_id_card_cred'])

    print("\"michael\" -> Store \"id_card\" Credential from government")
    _, michael['id_card_cred_def'] = await get_cred_def(michael['pool'], michael['did_for_government'],
                                                         michael['id_card_cred_def_id'])

    await anoncreds.prover_store_credential(michael['wallet'], None, michael['id_card_cred_request_metadata'],
                                            michael['id_card_cred'], michael['id_card_cred_def'], None)

    
    ###############
    ###############
    ###############


    print("==============================")
    print("=== Now Getting Transcript with Faber College ==")
    print("==============================")
    print("== Getting Transcript with Faber - Onboarding ==")
    print("------------------------------")

    # michael = {
    #     'name': 'michael',
    #     'wallet_config': json.dumps({'id': 'michael_wallet'}),
    #     'wallet_credentials': json.dumps({'key': 'michael_wallet_key'}),
    #     'pool': pool_['handle'],
    # }
    faber['did_for_michael'], faber['key_for_michael'], michael['did_for_faber'], michael['key_for_faber'], \
    faber['michael_connection_response'] = await onboarding(faber, michael)

    print("\n==============================")
    print("== Getting Transcript with Faber - Getting Transcript Credential ==")
    input("=== Press Enter To Continue... ===\n------------------------------")

    print("\"Faber\" -> Create \"Transcript\" Credential Offer for michael")
    faber['transcript_cred_offer'] = \
        await anoncreds.issuer_create_credential_offer(faber['wallet'], faber['transcript_cred_def_id'])

    print("\"Faber\" -> Get key for michael did")
    faber['michael_key_for_faber'] = \
        await did.key_for_did(faber['pool'], faber['wallet'], faber['michael_connection_response']['did'])

    print("\"Faber\" -> Authcrypt \"Transcript\" Credential Offer for michael")
    faber['authcrypted_transcript_cred_offer'] = \
        await crypto.auth_crypt(faber['wallet'], faber['key_for_michael'], faber['michael_key_for_faber'],
                                faber['transcript_cred_offer'].encode('utf-8'))

    print("\"Faber\" -> Send authcrypted \"Transcript\" Credential Offer to michael")
    michael['authcrypted_transcript_cred_offer'] = faber['authcrypted_transcript_cred_offer']

    print("\"michael\" -> Authdecrypted \"Transcript\" Credential Offer from Faber")
    michael['faber_key_for_michael'], michael['transcript_cred_offer'], authdecrypted_transcript_cred_offer = \
        await auth_decrypt(michael['wallet'], michael['key_for_faber'], michael['authcrypted_transcript_cred_offer'])
    michael['transcript_schema_id'] = authdecrypted_transcript_cred_offer['schema_id']
    michael['transcript_cred_def_id'] = authdecrypted_transcript_cred_offer['cred_def_id']

    print("\"michael\" -> Create and store \"michael\" Master Secret in Wallet")
    michael['master_secret_id'] = await anoncreds.prover_create_master_secret(michael['wallet'], None)

    print("\"michael\" -> Get \"Faber Transcript\" Credential Definition from Ledger")
    (michael['faber_transcript_cred_def_id'], michael['faber_transcript_cred_def']) = \
        await get_cred_def(michael['pool'], michael['did_for_faber'], michael['transcript_cred_def_id'])

    print("\"michael\" -> Create \"Transcript\" Credential Request for Faber")
    (michael['transcript_cred_request'], michael['transcript_cred_request_metadata']) = \
        await anoncreds.prover_create_credential_req(michael['wallet'], michael['did_for_faber'],
                                                     michael['transcript_cred_offer'], michael['faber_transcript_cred_def'],
                                                     michael['master_secret_id'])

    print("\"michael\" -> Authcrypt \"Transcript\" Credential Request for Faber")
    michael['authcrypted_transcript_cred_request'] = \
        await crypto.auth_crypt(michael['wallet'], michael['key_for_faber'], michael['faber_key_for_michael'],
                                michael['transcript_cred_request'].encode('utf-8'))

    print("\"michael\" -> Send authcrypted \"Transcript\" Credential Request to Faber")
    faber['authcrypted_transcript_cred_request'] = michael['authcrypted_transcript_cred_request']

    print("\"Faber\" -> Authdecrypt \"Transcript\" Credential Request from michael")
    faber['michael_key_for_faber'], faber['transcript_cred_request'], _ = \
        await auth_decrypt(faber['wallet'], faber['key_for_michael'], faber['authcrypted_transcript_cred_request'])

    print("\"Faber\" -> Create \"Transcript\" Credential for michael")
    faber['michael_transcript_cred_values'] = json.dumps({
        "first_name": {"raw": "michael", "encoded": "1139481716457488690172217916278103335"},
        "last_name": {"raw": "Garcia", "encoded": "5321642780241790123587902456789123452"},
        "degree": {"raw": "Bachelor of Science, Marketing", "encoded": "12434523576212321"},
        "status": {"raw": "graduated", "encoded": "2213454313412354"},
        "ssn": {"raw": "123-45-6789", "encoded": "3124141231422543541"},
        "year": {"raw": "2015", "encoded": "2015"},
        "average": {"raw": "5", "encoded": "5"}
    })
    faber['transcript_cred'], _, _ = \
        await anoncreds.issuer_create_credential(faber['wallet'], faber['transcript_cred_offer'],
                                                 faber['transcript_cred_request'],
                                                 faber['michael_transcript_cred_values'], None, None)

    print("\"Faber\" -> Authcrypt \"Transcript\" Credential for michael")
    faber['authcrypted_transcript_cred'] = \
        await crypto.auth_crypt(faber['wallet'], faber['key_for_michael'], faber['michael_key_for_faber'],
                                faber['transcript_cred'].encode('utf-8'))

    print("\"Faber\" -> Send authcrypted \"Transcript\" Credential to michael")
    michael['authcrypted_transcript_cred'] = faber['authcrypted_transcript_cred']

    print("\"michael\" -> Authdecrypted \"Transcript\" Credential from Faber")
    _, michael['transcript_cred'], _ = \
        await auth_decrypt(michael['wallet'], michael['key_for_faber'], michael['authcrypted_transcript_cred'])

    print("\"michael\" -> Store \"Transcript\" Credential from Faber")
    _, michael['transcript_cred_def'] = await get_cred_def(michael['pool'], michael['did_for_faber'],
                                                         michael['transcript_cred_def_id'])

    await anoncreds.prover_store_credential(michael['wallet'], None, michael['transcript_cred_request_metadata'],
                                            michael['transcript_cred'], michael['transcript_cred_def'], None)

    print("\n==============================")
    print("=== Apply for the job with sovrin ==")
    print("==============================")
    print("== Apply for the job with sovrin - Onboarding ==")
    print("------------------------------")

    sovrin['did_for_michael'], sovrin['key_for_michael'], michael['did_for_sovrin'], michael['key_for_sovrin'], \
    sovrin['michael_connection_response'] = await onboarding(sovrin, michael)

    print("\n==============================")
    print("== Apply for the job with sovrin - Transcript proving ==")
    print("------------------------------")

    print("\"sovrin\" -> Create \"Job-Application\" Proof Request")
    sovrin['job_application_proof_request'] = json.dumps({
        'nonce': '1432422343242122312411212',
        'name': 'Job-Application',
        'version': '0.1',
        'requested_attributes': {
            'attr1_referent': {
                'name': 'first_name'
            },
            'attr2_referent': {
                'name': 'last_name'
            },
            'attr3_referent': {
                'name': 'degree',
                'restrictions': [{'cred_def_id': faber['transcript_cred_def_id']}]
            },
            'attr4_referent': {
                'name': 'status',
                'restrictions': [{'cred_def_id': faber['transcript_cred_def_id']}]
            },
            'attr5_referent': {
                'name': 'ssn',
                'restrictions': [{'cred_def_id': faber['transcript_cred_def_id']}]
            },
            'attr6_referent': {
                'name': 'phone_number'
            }
        },
        'requested_predicates': {
            'predicate1_referent': {
                'name': 'average',
                'p_type': '>=',
                'p_value': 4,
                'restrictions': [{'cred_def_id': faber['transcript_cred_def_id']}]
            }
        }
    })

    print("\"sovrin\" -> Get key for michael did")
    sovrin['michael_key_for_sovrin'] = \
        await did.key_for_did(sovrin['pool'], sovrin['wallet'], sovrin['michael_connection_response']['did'])

    print("\"sovrin\" -> Authcrypt \"Job-Application\" Proof Request for michael")
    sovrin['authcrypted_job_application_proof_request'] = \
        await crypto.auth_crypt(sovrin['wallet'], sovrin['key_for_michael'], sovrin['michael_key_for_sovrin'],
                                sovrin['job_application_proof_request'].encode('utf-8'))

    print("\"sovrin\" -> Send authcrypted \"Job-Application\" Proof Request to michael")
    michael['authcrypted_job_application_proof_request'] = sovrin['authcrypted_job_application_proof_request']

    print("\"michael\" -> Authdecrypt \"Job-Application\" Proof Request from sovrin")
    michael['sovrin_key_for_michael'], michael['job_application_proof_request'], _ = \
        await auth_decrypt(michael['wallet'], michael['key_for_sovrin'], michael['authcrypted_job_application_proof_request'])

    print("\"michael\" -> Get credentials for \"Job-Application\" Proof Request")

    search_for_job_application_proof_request = \
        await anoncreds.prover_search_credentials_for_proof_req(michael['wallet'],
                                                                michael['job_application_proof_request'], None)

    cred_for_attr1 = await get_credential_for_referent(search_for_job_application_proof_request, 'attr1_referent')
    cred_for_attr2 = await get_credential_for_referent(search_for_job_application_proof_request, 'attr2_referent')
    cred_for_attr3 = await get_credential_for_referent(search_for_job_application_proof_request, 'attr3_referent')
    cred_for_attr4 = await get_credential_for_referent(search_for_job_application_proof_request, 'attr4_referent')
    cred_for_attr5 = await get_credential_for_referent(search_for_job_application_proof_request, 'attr5_referent')
    cred_for_predicate1 = \
        await get_credential_for_referent(search_for_job_application_proof_request, 'predicate1_referent')

    await anoncreds.prover_close_credentials_search_for_proof_req(search_for_job_application_proof_request)

    michael['creds_for_job_application_proof'] = {cred_for_attr1['referent']: cred_for_attr1,
                                                cred_for_attr2['referent']: cred_for_attr2,
                                                cred_for_attr3['referent']: cred_for_attr3,
                                                cred_for_attr4['referent']: cred_for_attr4,
                                                cred_for_attr5['referent']: cred_for_attr5,
                                                cred_for_predicate1['referent']: cred_for_predicate1}

    michael['schemas_for_job_application'], michael['cred_defs_for_job_application'], \
    michael['revoc_states_for_job_application'] = \
        await prover_get_entities_from_ledger(michael['pool'], michael['did_for_sovrin'],
                                              michael['creds_for_job_application_proof'], michael['name'])

    print("\"michael\" -> Create \"Job-Application\" Proof")
    michael['job_application_requested_creds'] = json.dumps({
        'self_attested_attributes': {
            'attr1_referent': 'michael',
            'attr2_referent': 'Garcia',
            'attr6_referent': '123-45-6789'
        },
        'requested_attributes': {
            'attr3_referent': {'cred_id': cred_for_attr3['referent'], 'revealed': True},
            'attr4_referent': {'cred_id': cred_for_attr4['referent'], 'revealed': True},
            'attr5_referent': {'cred_id': cred_for_attr5['referent'], 'revealed': True},
        },
        'requested_predicates': {'predicate1_referent': {'cred_id': cred_for_predicate1['referent']}}
    })

    michael['job_application_proof'] = \
        await anoncreds.prover_create_proof(michael['wallet'], michael['job_application_proof_request'],
                                            michael['job_application_requested_creds'], michael['master_secret_id'],
                                            michael['schemas_for_job_application'],
                                            michael['cred_defs_for_job_application'],
                                            michael['revoc_states_for_job_application'])

    print("\"michael\" -> Authcrypt \"Job-Application\" Proof for sovrin")
    michael['authcrypted_job_application_proof'] = \
        await crypto.auth_crypt(michael['wallet'], michael['key_for_sovrin'], michael['sovrin_key_for_michael'],
                                michael['job_application_proof'].encode('utf-8'))

    print("\"michael\" -> Send authcrypted \"Job-Application\" Proof to sovrin")
    sovrin['authcrypted_job_application_proof'] = michael['authcrypted_job_application_proof']

    print("\"sovrin\" -> Authdecrypted \"Job-Application\" Proof from michael")
    _, sovrin['job_application_proof'], decrypted_job_application_proof = \
        await auth_decrypt(sovrin['wallet'], sovrin['key_for_michael'], sovrin['authcrypted_job_application_proof'])

    sovrin['schemas_for_job_application'], sovrin['cred_defs_for_job_application'], \
    sovrin['revoc_ref_defs_for_job_application'], sovrin['revoc_regs_for_job_application'] = \
        await verifier_get_entities_from_ledger(sovrin['pool'], sovrin['did'],
                                                decrypted_job_application_proof['identifiers'], sovrin['name'])

    print("\"sovrin\" -> Verify \"Job-Application\" Proof from michael")
    assert 'Bachelor of Science, Marketing' == \
           decrypted_job_application_proof['requested_proof']['revealed_attrs']['attr3_referent']['raw']
    assert 'graduated' == \
           decrypted_job_application_proof['requested_proof']['revealed_attrs']['attr4_referent']['raw']
    assert '123-45-6789' == \
           decrypted_job_application_proof['requested_proof']['revealed_attrs']['attr5_referent']['raw']

    assert 'michael' == decrypted_job_application_proof['requested_proof']['self_attested_attrs']['attr1_referent']
    assert 'Garcia' == decrypted_job_application_proof['requested_proof']['self_attested_attrs']['attr2_referent']
    assert '123-45-6789' == decrypted_job_application_proof['requested_proof']['self_attested_attrs']['attr6_referent']

    assert await anoncreds.verifier_verify_proof(sovrin['job_application_proof_request'], sovrin['job_application_proof'],
                                                 sovrin['schemas_for_job_application'],
                                                 sovrin['cred_defs_for_job_application'],
                                                 sovrin['revoc_ref_defs_for_job_application'],
                                                 sovrin['revoc_regs_for_job_application'])

    print("\n==============================")
    print("== Apply for the job with sovrin - Getting Job-Certificate Credential ==")
    input("=== Press Enter To Continue... ===\n------------------------------")

    print("\"sovrin\" -> Create \"Job-Certificate\" Credential Offer for michael")
    sovrin['job_certificate_cred_offer'] = \
        await anoncreds.issuer_create_credential_offer(sovrin['wallet'], sovrin['job_certificate_cred_def_id'])

    print("\"sovrin\" -> Get key for michael did")
    sovrin['michael_key_for_sovrin'] = \
        await did.key_for_did(sovrin['pool'], sovrin['wallet'], sovrin['michael_connection_response']['did'])

    print("\"sovrin\" -> Authcrypt \"Job-Certificate\" Credential Offer for michael")
    sovrin['authcrypted_job_certificate_cred_offer'] = \
        await crypto.auth_crypt(sovrin['wallet'], sovrin['key_for_michael'], sovrin['michael_key_for_sovrin'],
                                sovrin['job_certificate_cred_offer'].encode('utf-8'))

    print("\"sovrin\" -> Send authcrypted \"Job-Certificate\" Credential Offer to michael")
    michael['authcrypted_job_certificate_cred_offer'] = sovrin['authcrypted_job_certificate_cred_offer']

    print("\"michael\" -> Authdecrypted \"Job-Certificate\" Credential Offer from sovrin")
    michael['sovrin_key_for_michael_michael'], michael['job_certificate_cred_offer'], job_certificate_cred_offer = \
        await auth_decrypt(michael['wallet'], michael['key_for_sovrin'], michael['authcrypted_job_certificate_cred_offer'])

    print("\"michael\" -> Get \"sovrin Job-Certificate\" Credential Definition from Ledger")
    (michael['sovrin_job_certificate_cred_def_id'], michael['sovrin_job_certificate_cred_def']) = \
        await get_cred_def(michael['pool'], michael['did_for_sovrin'], job_certificate_cred_offer['cred_def_id'])

    print("\"michael\" -> Create and store in Wallet \"Job-Certificate\" Credential Request for sovrin")
    (michael['job_certificate_cred_request'], michael['job_certificate_cred_request_metadata']) = \
        await anoncreds.prover_create_credential_req(michael['wallet'], michael['did_for_sovrin'],
                                                     michael['job_certificate_cred_offer'],
                                                     michael['sovrin_job_certificate_cred_def'], michael['master_secret_id'])

    print("\"michael\" -> Authcrypt \"Job-Certificate\" Credential Request for sovrin")
    michael['authcrypted_job_certificate_cred_request'] = \
        await crypto.auth_crypt(michael['wallet'], michael['key_for_sovrin'], michael['sovrin_key_for_michael'],
                                michael['job_certificate_cred_request'].encode('utf-8'))

    print("\"michael\" -> Send authcrypted \"Job-Certificate\" Credential Request to sovrin")
    michael['job_certificate_cred_values'] = json.dumps({
        "first_name": {"raw": "michael", "encoded": "245712572474217942457235975012103335"},
        "last_name": {"raw": "Garcia", "encoded": "312643218496194691632153761283356127"},
        "employee_status": {"raw": "Permanent", "encoded": "2143135425425143112321314321"},
        "salary": {"raw": "2400", "encoded": "2400"},
        "start_date": {"raw": "10", "encoded": "10"}
    })
    sovrin['authcrypted_job_certificate_cred_request'] = michael['authcrypted_job_certificate_cred_request']
    sovrin['job_certificate_cred_values'] = michael['job_certificate_cred_values']

    print("\"sovrin\" -> Authdecrypt \"Job-Certificate\" Credential Request from michael")
    sovrin['michael_key_for_sovrin'], sovrin['job_certificate_cred_request'], _ = \
        await auth_decrypt(sovrin['wallet'], sovrin['key_for_michael'], sovrin['authcrypted_job_certificate_cred_request'])

    print("\"sovrin\" -> Create \"Job-Certificate\" Credential for michael")
    sovrin['blob_storage_reader_cfg_handle'] = await blob_storage.open_reader('default', sovrin['tails_writer_config'])
    sovrin['job_certificate_cred'], sovrin['job_certificate_cred_rev_id'], sovrin['michael_cert_rev_reg_delta'] = \
        await anoncreds.issuer_create_credential(sovrin['wallet'], sovrin['job_certificate_cred_offer'],
                                                 sovrin['job_certificate_cred_request'],
                                                 sovrin['job_certificate_cred_values'],
                                                 sovrin['revoc_reg_id'],
                                                 sovrin['blob_storage_reader_cfg_handle'])

    print("\"sovrin\" -> Post Revocation Registry Delta to Ledger")
    sovrin['revoc_reg_entry_req'] = \
        await ledger.build_revoc_reg_entry_request(sovrin['did'], sovrin['revoc_reg_id'], 'CL_ACCUM',
                                                   sovrin['michael_cert_rev_reg_delta'])
    await ledger.sign_and_submit_request(sovrin['pool'], sovrin['wallet'], sovrin['did'], sovrin['revoc_reg_entry_req'])

    print("\"sovrin\" -> Authcrypt \"Job-Certificate\" Credential for michael")
    sovrin['authcrypted_job_certificate_cred'] = \
        await crypto.auth_crypt(sovrin['wallet'], sovrin['key_for_michael'], sovrin['michael_key_for_sovrin'],
                                sovrin['job_certificate_cred'].encode('utf-8'))

    print("\"sovrin\" -> Send authcrypted \"Job-Certificate\" Credential to michael")
    michael['authcrypted_job_certificate_cred'] = sovrin['authcrypted_job_certificate_cred']

    print("\"michael\" -> Authdecrypted \"Job-Certificate\" Credential from sovrin")
    _, michael['job_certificate_cred'], michael_job_certificate_cred = \
        await auth_decrypt(michael['wallet'], michael['key_for_sovrin'], michael['authcrypted_job_certificate_cred'])

    print("\"michael\" -> Gets RevocationRegistryDefinition for \"Job-Certificate\" Credential from sovrin")
    michael['sovrin_revoc_reg_des_req'] = \
        await ledger.build_get_revoc_reg_def_request(michael['did_for_sovrin'],
                                                     michael_job_certificate_cred['rev_reg_id'])
    michael['sovrin_revoc_reg_des_resp'] = await ledger.submit_request(michael['pool'], michael['sovrin_revoc_reg_des_req'])
    (michael['sovrin_revoc_reg_def_id'], michael['sovrin_revoc_reg_def_json']) = \
        await ledger.parse_get_revoc_reg_def_response(michael['sovrin_revoc_reg_des_resp'])

    print("\"michael\" -> Store \"Job-Certificate\" Credential")
    await anoncreds.prover_store_credential(michael['wallet'], None, michael['job_certificate_cred_request_metadata'],
                                            michael['job_certificate_cred'],
                                            michael['sovrin_job_certificate_cred_def'], michael['sovrin_revoc_reg_def_json'])

    print("\n==============================")
    print("=== Apply for the login with door_access ==")
    print("==============================")
    print("== Apply for the login with door_access - Connecting Via Bluetooth ==")
    input("=== Press any key to continue... ===\n------------------------------")

    door_access['did_for_michael'], door_access['key_for_michael'], michael['did_for_door_access'], michael['key_for_door_access'], \
    door_access['michael_connection_response'] = await onboarding(door_access, michael)

    async def apply_login_basic():
        # This method will be called twice: once with a valid Job-Certificate and
        # the second time after the Job-Certificate has been revoked.
        
        print("\n==============================")
        print("== Connecting to Sovrin Door ==")
        print("------------------------------")

        print("\"door_access\" -> Create \"Door Login\" Proof Request")
        door_access['apply_login_proof_request'] = json.dumps({
            'nonce': '123432421212',
            'name': 'login-Application-Basic',
            'version': '0.1',
            'requested_attributes': {
                'attr1_referent': {
                    'name': 'employee_status',
                    'restrictions': [{'cred_def_id': sovrin['job_certificate_cred_def_id']}]
                }, 
                'attr2_referent': {
                    'name': 'ssn'
                    # 'restrictions': [{'cred_def_id': government['id_card_cred_def_id']}]
                }
            },
            'requested_predicates': {
                'predicate1_referent': {
                    'name': 'start_date',
                    'p_type': '>=',
                    'p_value': 10,
                    'restrictions': [{'cred_def_id': sovrin['job_certificate_cred_def_id']}]
                }
            },
            'non_revoked': {'to': int(time.time())}
        })

        print("\"door_access\" -> Get key for michael did")
        door_access['michael_key_for_door_access'] = \
            await did.key_for_did(door_access['pool'], door_access['wallet'], door_access['michael_connection_response']['did'])

        print("\"door_access\" -> Authcrypt \"Door Login\" Proof Request for michael")
        door_access['authcrypted_apply_login_proof_request'] = \
            await crypto.auth_crypt(door_access['wallet'], door_access['key_for_michael'], door_access['michael_key_for_door_access'],
                                    door_access['apply_login_proof_request'].encode('utf-8'))

        print("\"door_access\" -> Send authcrypted \"Door Login\" Proof Request to michael")
        michael['authcrypted_apply_login_proof_request'] = door_access['authcrypted_apply_login_proof_request']

        print("\"michael\" -> Authdecrypt \"Door Login\" Proof Request from door_access")
        michael['door_access_key_for_michael'], michael['apply_login_proof_request'], _ = \
            await auth_decrypt(michael['wallet'], michael['key_for_door_access'], michael['authcrypted_apply_login_proof_request'])

        print("\"michael\" -> Get credentials for \"Door Login\" Proof Request")

        search_for_apply_login_proof_request = \
            await anoncreds.prover_search_credentials_for_proof_req(michael['wallet'],
                                                                    michael['apply_login_proof_request'], None)

        cred_for_attr1 = await get_credential_for_referent(search_for_apply_login_proof_request, 'attr1_referent')
        cred_for_attr2 = await get_credential_for_referent(search_for_apply_login_proof_request, 'attr2_referent')
        cred_for_predicate1 = await get_credential_for_referent(search_for_apply_login_proof_request, 'predicate1_referent')
        
        await anoncreds.prover_close_credentials_search_for_proof_req(search_for_apply_login_proof_request)

        michael['creds_for_apply_login_proof'] = {cred_for_attr1['referent']: cred_for_attr1,
                                                  cred_for_attr2['referent']: cred_for_attr2,
                                                  cred_for_predicate1['referent']: cred_for_predicate1}

        requested_timestamp = int(json.loads(door_access['apply_login_proof_request'])['non_revoked']['to'])
        michael['schemas_for_login_app'], michael['cred_defs_for_login_app'], michael['revoc_states_for_login_app'] = \
            await prover_get_entities_from_ledger(michael['pool'], michael['did_for_door_access'],
                                                  michael['creds_for_apply_login_proof'],
                                                  michael['name'], None, requested_timestamp)

        print("\"michael\" -> Create \"Door Login\" Proof")
        revoc_states_for_login_app = json.loads(michael['revoc_states_for_login_app'])
        timestamp_for_attr1 = get_timestamp_for_attribute(cred_for_attr1, revoc_states_for_login_app)
        timestamp_for_attr2 = get_timestamp_for_attribute(cred_for_attr2, revoc_states_for_login_app)
        timestamp_for_predicate1 = get_timestamp_for_attribute(cred_for_predicate1, revoc_states_for_login_app)
        michael['apply_login_requested_creds'] = json.dumps({
            'self_attested_attributes': {},
            'requested_attributes': {
                'attr1_referent': {'cred_id': cred_for_attr1['referent'], 'revealed': True, 'timestamp': timestamp_for_attr1},
                'attr2_referent': {'cred_id': cred_for_attr2['referent'], 'revealed': True, 'timestamp': timestamp_for_attr2}
            },
            'requested_predicates': {
                'predicate1_referent': {'cred_id': cred_for_predicate1['referent'], 'timestamp': timestamp_for_predicate1}
            }
        })
        michael['apply_login_proof'] = \
            await anoncreds.prover_create_proof(michael['wallet'], michael['apply_login_proof_request'],
                                                michael['apply_login_requested_creds'], michael['master_secret_id'],
                                                michael['schemas_for_login_app'], michael['cred_defs_for_login_app'],
                                                michael['revoc_states_for_login_app'])

        print("\"michael\" -> Authcrypt \"Door Login\" Proof for door_access")
        michael['authcrypted_michael_apply_login_proof'] = \
            await crypto.auth_crypt(michael['wallet'], michael['key_for_door_access'], michael['door_access_key_for_michael'],
                                    michael['apply_login_proof'].encode('utf-8'))

        print("\"michael\" -> Send authcrypted \"Door Login\" Proof to door_access")
        door_access['authcrypted_michael_apply_login_proof'] = michael['authcrypted_michael_apply_login_proof']

        print("\"door_access\" -> Authdecrypted \"Door Login\" Proof from michael")
        _, door_access['michael_apply_login_proof'], authdecrypted_michael_apply_login_proof = \
            await auth_decrypt(door_access['wallet'], door_access['key_for_michael'], door_access['authcrypted_michael_apply_login_proof'])

        print("\"door_access\" -> Get Schemas, Credential Definitions and Revocation Registries from Ledger"
                    " required for Proof verifying")

        door_access['schemas_for_login_app'], door_access['cred_defs_for_login_app'], door_access['revoc_defs_for_login_app'], \
        door_access['revoc_regs_for_login_app'] = \
            await verifier_get_entities_from_ledger(door_access['pool'], door_access['did'],
                                                    authdecrypted_michael_apply_login_proof['identifiers'],
                                                    door_access['name'], requested_timestamp)

        print("\"door_access\" -> Verify \"Door Login\" Proof from michael")
        assert 'Permanent' == \
               authdecrypted_michael_apply_login_proof['requested_proof']['revealed_attrs']['attr1_referent']['raw']

    await apply_login_basic()

    assert await anoncreds.verifier_verify_proof(door_access['apply_login_proof_request'],
                                                 door_access['michael_apply_login_proof'],
                                                 door_access['schemas_for_login_app'],
                                                 door_access['cred_defs_for_login_app'],
                                                 door_access['revoc_defs_for_login_app'],
                                                 door_access['revoc_regs_for_login_app'])
    print("\n==============================")
    print("== Credential revocation - sovrin revokes michael's door door_access  ==")
    print("------------------------------")

    print("\"sovrin\" - Revoke  credential")
    sovrin['michael_cert_rev_reg_delta'] = \
        await anoncreds.issuer_revoke_credential(sovrin['wallet'],
                                                 sovrin['blob_storage_reader_cfg_handle'],
                                                 sovrin['revoc_reg_id'],
                                                 sovrin['job_certificate_cred_rev_id'])

    print("\"sovrin\" - Post RevocationRegistryDelta to Ledger")
    sovrin['revoc_reg_entry_req'] = \
        await ledger.build_revoc_reg_entry_request(sovrin['did'], sovrin['revoc_reg_id'], 'CL_ACCUM',
                                                   sovrin['michael_cert_rev_reg_delta'])
    await ledger.sign_and_submit_request(sovrin['pool'], sovrin['wallet'], sovrin['did'], sovrin['revoc_reg_entry_req'])

    print("\n==============================")

    print("\n==============================")
    print("== Apply for the login with door_access again - Job-Certificate proving after revocation  ==")
    input("=== Press any key to continue... ===\n------------------------------")

    await apply_login_basic()

    assert not await anoncreds.verifier_verify_proof(door_access['apply_login_proof_request'],
                                                     door_access['michael_apply_login_proof'],
                                                     door_access['schemas_for_login_app'],
                                                     door_access['cred_defs_for_login_app'],
                                                     door_access['revoc_defs_for_login_app'],
                                                     door_access['revoc_regs_for_login_app'])

    print("==============================")
    print("=== Door Access Denied, Credential has been revoked")
    print("==============================")


    print(" \"Sovrin Steward\" -> Close and Delete wallet")
    await wallet.close_wallet(steward['wallet'])
    await wallet.delete_wallet(steward['wallet_config'], steward['wallet_credentials'])

    print("\"Government\" -> Close and Delete wallet")
    await wallet.close_wallet(government['wallet'])
    await wallet.delete_wallet(wallet_config("delete", government['wallet_config']), wallet_credentials("delete", government['wallet_credentials']))

    print("\"Faber\" -> Close and Delete wallet")
    await wallet.close_wallet(faber['wallet'])
    await wallet.delete_wallet(wallet_config("delete", faber['wallet_config']), wallet_credentials("delete", faber['wallet_credentials']))

    print("\"sovrin\" -> Close and Delete wallet")
    await wallet.close_wallet(sovrin['wallet'])
    await wallet.delete_wallet(wallet_config("delete", sovrin['wallet_config']), wallet_credentials("delete", sovrin['wallet_credentials']))

    print("\"door_access\" -> Close and Delete wallet")
    await wallet.close_wallet(door_access['wallet'])
    await wallet.delete_wallet(wallet_config("delete", door_access['wallet_config']), wallet_credentials("delete", door_access['wallet_credentials']))

    print("\"michael\" -> Close and Delete wallet")
    await wallet.close_wallet(michael['wallet'])
    await wallet.delete_wallet(wallet_config("delete", michael['wallet_config']), wallet_credentials("delete", michael['wallet_credentials']))

    print("Close and Delete pool")
    await pool.close_pool_ledger(pool_['handle'])
    await pool.delete_pool_ledger_config(pool_['name'])

    print("Getting started -> done")

    print("==============================")
    print("=== Thank you for following along ===")
    print("==============================")

async def onboarding(_from, to):
    print("\"{}\" -> Create and store in Wallet \"{} {}\" DID".format(_from['name'], _from['name'], to['name']))
    (from_to_did, from_to_key) = await did.create_and_store_my_did(_from['wallet'], "{}")

    print("\"{}\" -> Send Nym to Ledger for \"{} {}\" DID".format(_from['name'], _from['name'], to['name']))
    await send_nym(_from['pool'], _from['wallet'], _from['did'], from_to_did, from_to_key, None)

    print("\"{}\" -> Send connection request to {} with \"{} {}\" DID and nonce"
                .format(_from['name'], to['name'], _from['name'], to['name']))
    connection_request = {
        'did': from_to_did,
        'nonce': 123456789
    }

    if 'wallet' not in to:
        print("\"{}\" -> Create wallet".format(to['name']))
        try:
            await wallet.create_wallet(wallet_config("create", to['wallet_config']), wallet_credentials("create", to['wallet_credentials']))
        except IndyError as ex:
            if ex.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
                pass
        to['wallet'] = await wallet.open_wallet(wallet_config("open", to['wallet_config']), wallet_credentials("open", to['wallet_credentials']))

    print("\"{}\" -> Create and store in Wallet \"{} {}\" DID".format(to['name'], to['name'], _from['name']))
    (to_from_did, to_from_key) = await did.create_and_store_my_did(to['wallet'], "{}")

    print("\"{}\" -> Get key for did from \"{}\" connection request".format(to['name'], _from['name']))
    from_to_verkey = await did.key_for_did(_from['pool'], to['wallet'], connection_request['did'])

    print("\"{}\" -> Anoncrypt connection response for \"{}\" with \"{} {}\" DID, verkey and nonce"
                .format(to['name'], _from['name'], to['name'], _from['name']))
    to['connection_response'] = json.dumps({
        'did': to_from_did,
        'verkey': to_from_key,
        'nonce': connection_request['nonce']
    })
    to['anoncrypted_connection_response'] = \
        await crypto.anon_crypt(from_to_verkey, to['connection_response'].encode('utf-8'))

    print("\"{}\" -> Send anoncrypted connection response to \"{}\"".format(to['name'], _from['name']))
    _from['anoncrypted_connection_response'] = to['anoncrypted_connection_response']

    print("\"{}\" -> Anondecrypt connection response from \"{}\"".format(_from['name'], to['name']))
    _from['connection_response'] = \
        json.loads((await crypto.anon_decrypt(_from['wallet'], from_to_key,
                                              _from['anoncrypted_connection_response'])).decode("utf-8"))

    print("\"{}\" -> Authenticates \"{}\" by comparision of Nonce".format(_from['name'], to['name']))
    assert connection_request['nonce'] == _from['connection_response']['nonce']

    print("\"{}\" -> Send Nym to Ledger for \"{} {}\" DID".format(_from['name'], to['name'], _from['name']))
    await send_nym(_from['pool'], _from['wallet'], _from['did'], to_from_did, to_from_key, None)

    return from_to_did, from_to_key, to_from_did, to_from_key, _from['connection_response']


def wallet_config(operation, wallet_config_str):
    if not args.storage_type:
        return wallet_config_str
    wallet_config_json = json.loads(wallet_config_str)
    wallet_config_json['storage_type'] = args.storage_type
    if args.config:
        wallet_config_json['storage_config'] = json.loads(args.config)
    #print(operation, json.dumps(wallet_config_json))
    return json.dumps(wallet_config_json)


def wallet_credentials(operation, wallet_credentials_str):
    if not args.storage_type:
        return wallet_credentials_str
    wallet_credentials_json = json.loads(wallet_credentials_str)
    if args.creds:
        wallet_credentials_json['storage_credentials'] = json.loads(args.creds)
    #print(operation, json.dumps(wallet_credentials_json))
    return json.dumps(wallet_credentials_json)


async def get_verinym(_from, from_to_did, from_to_key, to, to_from_did, to_from_key):
    print("\"{}\" -> Create and store in Wallet \"{}\" new DID".format(to['name'], to['name']))
    (to_did, to_key) = await did.create_and_store_my_did(to['wallet'], "{}")

    print("\"{}\" -> Authcrypt \"{} DID info\" for \"{}\"".format(to['name'], to['name'], _from['name']))
    to['did_info'] = json.dumps({
        'did': to_did,
        'verkey': to_key
    })
    to['authcrypted_did_info'] = \
        await crypto.auth_crypt(to['wallet'], to_from_key, from_to_key, to['did_info'].encode('utf-8'))

    print("\"{}\" -> Send authcrypted \"{} DID info\" to {}".format(to['name'], to['name'], _from['name']))

    print("\"{}\" -> Authdecrypted \"{} DID info\" from {}".format(_from['name'], to['name'], to['name']))
    sender_verkey, authdecrypted_did_info_json, authdecrypted_did_info = \
        await auth_decrypt(_from['wallet'], from_to_key, to['authcrypted_did_info'])

    print("\"{}\" -> Authenticate {} by comparision of Verkeys".format(_from['name'], to['name'], ))
    assert sender_verkey == await did.key_for_did(_from['pool'], _from['wallet'], to_from_did)

    print("\"{}\" -> Send Nym to Ledger for \"{} DID\" with {} Role"
                .format(_from['name'], to['name'], to['role']))
    await send_nym(_from['pool'], _from['wallet'], _from['did'], authdecrypted_did_info['did'],
                   authdecrypted_did_info['verkey'], to['role'])

    return to_did


async def send_nym(pool_handle, wallet_handle, _did, new_did, new_key, role):
    nym_request = await ledger.build_nym_request(_did, new_did, new_key, None, role)
    await ledger.sign_and_submit_request(pool_handle, wallet_handle, _did, nym_request)


async def send_schema(pool_handle, wallet_handle, _did, schema):
    schema_request = await ledger.build_schema_request(_did, schema)
    await ledger.sign_and_submit_request(pool_handle, wallet_handle, _did, schema_request)


async def send_cred_def(pool_handle, wallet_handle, _did, cred_def_json):
    cred_def_request = await ledger.build_cred_def_request(_did, cred_def_json)
    await ledger.sign_and_submit_request(pool_handle, wallet_handle, _did, cred_def_request)


async def get_schema(pool_handle, _did, schema_id):
    get_schema_request = await ledger.build_get_schema_request(_did, schema_id)
    get_schema_response = await ledger.submit_request(pool_handle, get_schema_request)
    return await ledger.parse_get_schema_response(get_schema_response)


async def get_cred_def(pool_handle, _did, cred_def_id):
    get_cred_def_request = await ledger.build_get_cred_def_request(_did, cred_def_id)
    get_cred_def_response = await ledger.submit_request(pool_handle, get_cred_def_request)
    return await ledger.parse_get_cred_def_response(get_cred_def_response)


async def get_credential_for_referent(search_handle, referent):
    credentials = json.loads(
        await anoncreds.prover_fetch_credentials_for_proof_req(search_handle, referent, 10))
    return credentials[0]['cred_info']


def get_timestamp_for_attribute(cred_for_attribute, revoc_states):
    if cred_for_attribute['rev_reg_id'] in revoc_states:
        return int(next(iter(revoc_states[cred_for_attribute['rev_reg_id']])))
    else:
        return None


async def prover_get_entities_from_ledger(pool_handle, _did, identifiers, actor, timestamp_from=None, timestamp_to=None):
    schemas = {}
    cred_defs = {}
    rev_states = {}
    for item in identifiers.values():
        print("\"{}\" -> Get Schema from Ledger".format(actor))
        (received_schema_id, received_schema) = await get_schema(pool_handle, _did, item['schema_id'])
        schemas[received_schema_id] = json.loads(received_schema)

        print("\"{}\" -> Get Claim Definition from Ledger".format(actor))
        (received_cred_def_id, received_cred_def) = await get_cred_def(pool_handle, _did, item['cred_def_id'])
        cred_defs[received_cred_def_id] = json.loads(received_cred_def)

        if 'rev_reg_id' in item and item['rev_reg_id'] is not None:
            # Create Revocations States
            print("\"{}\" -> Get Revocation Registry Definition from Ledger".format(actor))
            get_revoc_reg_def_request = await ledger.build_get_revoc_reg_def_request(_did, item['rev_reg_id'])

            get_revoc_reg_def_response = await ledger.submit_request(pool_handle, get_revoc_reg_def_request)
            (rev_reg_id, revoc_reg_def_json) = await ledger.parse_get_revoc_reg_def_response(get_revoc_reg_def_response)

            print("\"{}\" -> Get Revocation Registry Delta from Ledger".format(actor))
            if not timestamp_to: timestamp_to = int(time.time())
            get_revoc_reg_delta_request = \
                await ledger.build_get_revoc_reg_delta_request(_did, item['rev_reg_id'], timestamp_from, timestamp_to)
            get_revoc_reg_delta_response = \
                await ledger.submit_request(pool_handle, get_revoc_reg_delta_request)
            (rev_reg_id, revoc_reg_delta_json, t) = \
                await ledger.parse_get_revoc_reg_delta_response(get_revoc_reg_delta_response)

            tails_reader_config = json.dumps(
                {'base_dir': dirname(json.loads(revoc_reg_def_json)['value']['tailsLocation']),
                 'uri_pattern': ''})
            blob_storage_reader_cfg_handle = await blob_storage.open_reader('default', tails_reader_config)

            print('%s - Create Revocation State', actor)
            rev_state_json = \
                await anoncreds.create_revocation_state(blob_storage_reader_cfg_handle, revoc_reg_def_json,
                                                        revoc_reg_delta_json, t, item['cred_rev_id'])
            rev_states[rev_reg_id] = {t: json.loads(rev_state_json)}

    return json.dumps(schemas), json.dumps(cred_defs), json.dumps(rev_states)


async def verifier_get_entities_from_ledger(pool_handle, _did, identifiers, actor, timestamp=None):
    schemas = {}
    cred_defs = {}
    rev_reg_defs = {}
    rev_regs = {}
    for item in identifiers:
        print("\"{}\" -> Get Schema from Ledger".format(actor))
        (received_schema_id, received_schema) = await get_schema(pool_handle, _did, item['schema_id'])
        schemas[received_schema_id] = json.loads(received_schema)

        print("\"{}\" -> Get Claim Definition from Ledger".format(actor))
        (received_cred_def_id, received_cred_def) = await get_cred_def(pool_handle, _did, item['cred_def_id'])
        cred_defs[received_cred_def_id] = json.loads(received_cred_def)

        if 'rev_reg_id' in item and item['rev_reg_id'] is not None:
            # Get Revocation Definitions and Revocation Registries
            print("\"{}\" -> Get Revocation Definition from Ledger".format(actor))
            get_revoc_reg_def_request = await ledger.build_get_revoc_reg_def_request(_did, item['rev_reg_id'])

            get_revoc_reg_def_response = await ledger.submit_request(pool_handle, get_revoc_reg_def_request)
            (rev_reg_id, revoc_reg_def_json) = await ledger.parse_get_revoc_reg_def_response(get_revoc_reg_def_response)

            print("\"{}\" -> Get Revocation Registry from Ledger".format(actor))
            if not timestamp: timestamp = item['timestamp']
            get_revoc_reg_request = \
                await ledger.build_get_revoc_reg_request(_did, item['rev_reg_id'], timestamp)
            get_revoc_reg_response = await ledger.submit_request(pool_handle, get_revoc_reg_request)
            (rev_reg_id, rev_reg_json, timestamp2) = await ledger.parse_get_revoc_reg_response(get_revoc_reg_response)

            rev_regs[rev_reg_id] = {timestamp2: json.loads(rev_reg_json)}
            rev_reg_defs[rev_reg_id] = json.loads(revoc_reg_def_json)

    return json.dumps(schemas), json.dumps(cred_defs), json.dumps(rev_reg_defs), json.dumps(rev_regs)


async def auth_decrypt(wallet_handle, key, message):
    from_verkey, decrypted_message_json = await crypto.auth_decrypt(wallet_handle, key, message)
    decrypted_message_json = decrypted_message_json.decode("utf-8")
    decrypted_message = json.loads(decrypted_message_json)
    return from_verkey, decrypted_message_json, decrypted_message


if __name__ == '__main__':
    run_coroutine(run)
    time.sleep(1)  # FIXME waiting for libindy thread complete