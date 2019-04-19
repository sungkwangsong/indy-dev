import time

from indy import anoncreds, crypto, did, ledger, pool, wallet

import json
import logging
from typing import Optional

from indy.error import ErrorCode, IndyError

from src.utils import get_pool_genesis_txn_path, run_coroutine, PROTOCOL_VERSION
import subprocess
logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

async def run():
    bashCommand = "bash refresh.sh"
    process = subprocess.Popen(bashCommand.split(), stdout=subprocess.PIPE)
    output, error = process.communicate()

    logger.info("Getting started -> started")

    pool_name = 'pool1'
    logger.info("Open Pool Ledger: {}".format(pool_name))
    pool_genesis_txn_path = get_pool_genesis_txn_path(pool_name)
    pool_config = json.dumps({"genesis_txn": str(pool_genesis_txn_path)})
    print(pool_config)
    

    # Set protocol version 2 to work with Indy Node 1.4
    await pool.set_protocol_version(PROTOCOL_VERSION)

    try:
        await pool.create_pool_ledger_config(pool_name, pool_config)
    except IndyError as ex:
        if ex.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
            pass
    pool_handle = await pool.open_pool_ledger(pool_name, None)

    logger.info("==============================")
    logger.info("=== Getting Trust Anchor credentials for Faber, sovrin, access and Government  ==")
    logger.info("------------------------------")

    logger.info("\"Sovrin Steward\" -> Create wallet")
    steward_wallet_config = json.dumps({"id": "sovrin_steward_wallet"})
    steward_wallet_credentials = json.dumps({"key": "steward_wallet_key"})
    try:
        await wallet.create_wallet(steward_wallet_config, steward_wallet_credentials)
    except IndyError as ex:
        if ex.error_code == ErrorCode.WalletAlreadyExistsError:
            pass

    steward_wallet = await wallet.open_wallet(steward_wallet_config, steward_wallet_credentials)

    logger.info("\"Sovrin Steward\" -> Create and store in Wallet DID from seed")
    steward_did_info = {'seed': '000000000000000000000000Steward1'}
    (steward_did, steward_key) = await did.create_and_store_my_did(steward_wallet, json.dumps(steward_did_info))

    logger.info("==============================")
    logger.info("== Getting Trust Anchor credentials - Government Onboarding  ==")
    logger.info("------------------------------")

    government_wallet_config = json.dumps({"id": "government_wallet"})
    government_wallet_credentials = json.dumps({"key": "government_wallet_key"})
    government_wallet, steward_government_key, government_steward_did, government_steward_key, _ \
        = await onboarding(pool_handle, "Sovrin Steward", steward_wallet, steward_did, "Government", None,
                           government_wallet_config, government_wallet_credentials)

    logger.info("==============================")
    logger.info("== Getting Trust Anchor credentials - Government getting Verinym  ==")
    logger.info("------------------------------")

    government_did = await get_verinym(pool_handle, "Sovrin Steward", steward_wallet, steward_did,
                                       steward_government_key, "Government", government_wallet, government_steward_did,
                                       government_steward_key, 'TRUST_ANCHOR')

    logger.info("==============================")
    logger.info("== Getting Trust Anchor credentials - Faber Onboarding  ==")
    logger.info("------------------------------")

    faber_wallet_config = json.dumps({"id": "faber_wallet"})
    faber_wallet_credentials = json.dumps({"key": "faber_wallet_key"})
    faber_wallet, steward_faber_key, faber_steward_did, faber_steward_key, _ = \
        await onboarding(pool_handle, "Sovrin Steward", steward_wallet, steward_did, "Faber", None, faber_wallet_config,
                         faber_wallet_credentials)

    logger.info("==============================")
    logger.info("== Getting Trust Anchor credentials - Faber getting Verinym  ==")
    logger.info("------------------------------")

    faber_did = await get_verinym(pool_handle, "Sovrin Steward", steward_wallet, steward_did, steward_faber_key,
                                  "Faber", faber_wallet, faber_steward_did, faber_steward_key, 'TRUST_ANCHOR')

    logger.info("==============================")
    logger.info("== Getting Trust Anchor credentials - sovrin Onboarding  ==")
    logger.info("------------------------------")

    sovrin_wallet_config = json.dumps({"id": "sovrin_wallet"})
    sovrin_wallet_credentials = json.dumps({"key": "sovrin_wallet_key"})
    sovrin_wallet, steward_sovrin_key, sovrin_steward_did, sovrin_steward_key, _ = \
        await onboarding(pool_handle, "Sovrin Steward", steward_wallet, steward_did, "sovrin", None, sovrin_wallet_config,
                         sovrin_wallet_credentials)

    logger.info("==============================")
    logger.info("== Getting Trust Anchor credentials - sovrin getting Verinym  ==")
    logger.info("------------------------------")

    sovrin_did = await get_verinym(pool_handle, "Sovrin Steward", steward_wallet, steward_did, steward_sovrin_key,
                                 "sovrin", sovrin_wallet, sovrin_steward_did, sovrin_steward_key, 'TRUST_ANCHOR')

    logger.info("==============================")
    logger.info("== Getting Trust Anchor credentials - access Onboarding  ==")
    logger.info("------------------------------")

    access_wallet_config = json.dumps({"id": " access_wallet"})
    access_wallet_credentials = json.dumps({"key": "access_wallet_key"})
    access_wallet, steward_access_key, access_steward_did, access_steward_key, _ = \
        await onboarding(pool_handle, "Sovrin Steward", steward_wallet, steward_did, "access", None,
                         access_wallet_config, access_wallet_credentials)

    logger.info("==============================")
    logger.info("== Getting Trust Anchor credentials - access getting Verinym  ==")
    logger.info("------------------------------")

    access_did = await get_verinym(pool_handle, "Sovrin Steward", steward_wallet, steward_did, steward_access_key,
                                   "access", access_wallet, access_steward_did, access_steward_key, 'TRUST_ANCHOR')

    logger.info("==============================")
    logger.info("=== Credential Schemas Setup ==")
    logger.info("------------------------------")

    logger.info("\"Government\" -> Create \"Job-Certificate\" Schema")
    (job_certificate_schema_id, job_certificate_schema) = \
        await anoncreds.issuer_create_schema(government_did, 'Job-Certificate', '0.2',
                                             json.dumps(['first_name', 'last_name', 'start_date', 'employee_status',
                                                         'end_date']))

    logger.info("\"Government\" -> Send \"Job-Certificate\" Schema to Ledger")
    await send_schema(pool_handle, government_wallet, government_did, job_certificate_schema)

    logger.info("\"Government\" -> Create \"Transcript\" Schema")
    (transcript_schema_id, transcript_schema) = \
        await anoncreds.issuer_create_schema(government_did, 'Transcript', '1.2',
                                             json.dumps(['first_name', 'last_name', 'degree', 'status',
                                                         'year', 'average', 'ssn']))
    logger.info("\"Government\" -> Send \"Transcript\" Schema to Ledger")
    await send_schema(pool_handle, government_wallet, government_did, transcript_schema)

    time.sleep(1)  # sleep 1 second before getting schema

    logger.info("==============================")
    logger.info("=== Faber Credential Definition Setup ==")
    logger.info("------------------------------")

    logger.info("\"Faber\" -> Get \"Transcript\" Schema from Ledger")
    (_, transcript_schema) = await get_schema(pool_handle, faber_did, transcript_schema_id)

    logger.info("\"Faber\" -> Create and store in Wallet \"Faber Transcript\" Credential Definition")
    (faber_transcript_cred_def_id, faber_transcript_cred_def_json) = \
        await anoncreds.issuer_create_and_store_credential_def(faber_wallet, faber_did, transcript_schema,
                                                               'TAG1', 'CL', '{"support_revocation": false}')

    logger.info("\"Faber\" -> Send  \"Faber Transcript\" Credential Definition to Ledger")
    await send_cred_def(pool_handle, faber_wallet, faber_did, faber_transcript_cred_def_json)

    logger.info("==============================")
    logger.info("=== sovrin Credential Definition Setup ==")
    logger.info("------------------------------")

    logger.info("\"sovrin\" -> Get from Ledger \"Job-Certificate\" Schema")
    (_, job_certificate_schema) = await get_schema(pool_handle, sovrin_did, job_certificate_schema_id)

    logger.info("\"sovrin\" -> Create and store in Wallet \"sovrin Job-Certificate\" Credential Definition")
    (sovrin_job_certificate_cred_def_id, sovrin_job_certificate_cred_def_json) = \
        await anoncreds.issuer_create_and_store_credential_def(sovrin_wallet, sovrin_did, job_certificate_schema,
                                                               'TAG1', 'CL', '{"support_revocation": false}')

    logger.info("\"sovrin\" -> Send \"sovrin Job-Certificate\" Credential Definition to Ledger")
    await send_cred_def(pool_handle, sovrin_wallet, sovrin_did, sovrin_job_certificate_cred_def_json)

    logger.info("==============================")
    logger.info("=== Getting Transcript with Faber ==")
    logger.info("==============================")
    logger.info("== Getting Transcript with Faber - Onboarding ==")
    logger.info("------------------------------")

    michael_wallet_config = json.dumps({"id": " michael_wallet"})
    michael_wallet_credentials = json.dumps({"key": "michael_wallet_key"})
    michael_wallet, faber_michael_key, michael_faber_did, michael_faber_key, faber_michael_connection_response \
        = await onboarding(pool_handle, "Faber", faber_wallet, faber_did, "michael", None, michael_wallet_config,
                           michael_wallet_credentials)

    logger.info("==============================")
    logger.info("== Getting Transcript with Faber - Getting Transcript Credential ==")
    logger.info("------------------------------")

    logger.info("\"Faber\" -> Create \"Transcript\" Credential Offer for michael")
    transcript_cred_offer_json = \
        await anoncreds.issuer_create_credential_offer(faber_wallet, faber_transcript_cred_def_id)

    logger.info("\"Faber\" -> Get key for michael did")
    michael_faber_verkey = await did.key_for_did(pool_handle, michael_wallet, faber_michael_connection_response['did'])

    logger.info("\"Faber\" -> Authcrypt \"Transcript\" Credential Offer for michael")
    authcrypted_transcript_cred_offer = await crypto.auth_crypt(faber_wallet, faber_michael_key, michael_faber_verkey,
                                                                transcript_cred_offer_json.encode('utf-8'))

    logger.info("\"Faber\" -> Send authcrypted \"Transcript\" Credential Offer to michael")

    logger.info("\"michael\" -> Authdecrypted \"Transcript\" Credential Offer from Faber")
    faber_michael_verkey, authdecrypted_transcript_cred_offer_json, authdecrypted_transcript_cred_offer = \
        await auth_decrypt(michael_wallet, michael_faber_key, authcrypted_transcript_cred_offer)

    logger.info("\"michael\" -> Create and store \"michael\" Master Secret in Wallet")
    michael_master_secret_id = await anoncreds.prover_create_master_secret(michael_wallet, None)

    logger.info("\"michael\" -> Get \"Faber Transcript\" Credential Definition from Ledger")
    (faber_transcript_cred_def_id, faber_transcript_cred_def) = \
        await get_cred_def(pool_handle, michael_faber_did, authdecrypted_transcript_cred_offer['cred_def_id'])

    logger.info("\"michael\" -> Create \"Transcript\" Credential Request for Faber")
    (transcript_cred_request_json, transcript_cred_request_metadata_json) = \
        await anoncreds.prover_create_credential_req(michael_wallet, michael_faber_did,
                                                     authdecrypted_transcript_cred_offer_json,
                                                     faber_transcript_cred_def, michael_master_secret_id)

    logger.info("\"michael\" -> Authcrypt \"Transcript\" Credential Request for Faber")
    authcrypted_transcript_cred_request = await crypto.auth_crypt(michael_wallet, michael_faber_key, faber_michael_verkey,
                                                                  transcript_cred_request_json.encode('utf-8'))

    logger.info("\"michael\" -> Send authcrypted \"Transcript\" Credential Request to Faber")

    logger.info("\"Faber\" -> Authdecrypt \"Transcript\" Credential Request from michael")
    michael_faber_verkey, authdecrypted_transcript_cred_request_json, _ = \
        await auth_decrypt(faber_wallet, faber_michael_key, authcrypted_transcript_cred_request)

    logger.info("\"Faber\" -> Create \"Transcript\" Credential for michael")
    transcript_cred_values = json.dumps({
        "first_name": {"raw": "michael", "encoded": "1139481716457488690172217916278103335"},
        "last_name": {"raw": "Garcia", "encoded": "5321642780241790123587902456789123452"},
        "degree": {"raw": "Bachelor of Science, Marketing", "encoded": "12434523576212321"},
        "status": {"raw": "graduated", "encoded": "2213454313412354"},
        "ssn": {"raw": "123-45-6789", "encoded": "3124141231422543541"},
        "year": {"raw": "2015", "encoded": "2015"},
        "average": {"raw": "5", "encoded": "5"}
    })

    transcript_cred_json, _, _ = \
        await anoncreds.issuer_create_credential(faber_wallet, transcript_cred_offer_json,
                                                 authdecrypted_transcript_cred_request_json,
                                                 transcript_cred_values, None, None)

    logger.info("\"Faber\" -> Authcrypt \"Transcript\" Credential for michael")
    authcrypted_transcript_cred_json = await crypto.auth_crypt(faber_wallet, faber_michael_key, michael_faber_verkey,
                                                               transcript_cred_json.encode('utf-8'))

    logger.info("\"Faber\" -> Send authcrypted \"Transcript\" Credential to michael")

    logger.info("\"michael\" -> Authdecrypted \"Transcript\" Credential from Faber")
    _, authdecrypted_transcript_cred_json, _ = \
        await auth_decrypt(michael_wallet, michael_faber_key, authcrypted_transcript_cred_json)

    logger.info("\"michael\" -> Store \"Transcript\" Credential from Faber")
    await anoncreds.prover_store_credential(michael_wallet, None, transcript_cred_request_metadata_json,
                                            authdecrypted_transcript_cred_json, faber_transcript_cred_def, None)

    logger.info("==============================")
    logger.info("=== Apply for the job with sovrin ==")
    logger.info("==============================")
    logger.info("== Apply for the job with sovrin - Onboarding ==")
    logger.info("------------------------------")

    michael_wallet, sovrin_michael_key, michael_sovrin_did, michael_sovrin_key, sovrin_michael_connection_response = \
        await onboarding(pool_handle, "sovrin", sovrin_wallet, sovrin_did, "michael", michael_wallet, michael_wallet_config,
                         michael_wallet_credentials)

    logger.info("==============================")
    logger.info("== Apply for the job with sovrin - Transcript proving ==")
    logger.info("------------------------------")

    logger.info("\"sovrin\" -> Create \"Job-Application\" Proof Request")
    job_application_proof_request_json = json.dumps({
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
                'restrictions': [{'cred_def_id': faber_transcript_cred_def_id}]
            },
            'attr4_referent': {
                'name': 'status',
                'restrictions': [{'cred_def_id': faber_transcript_cred_def_id}]
            },
            'attr5_referent': {
                'name': 'ssn',
                'restrictions': [{'cred_def_id': faber_transcript_cred_def_id}]
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
                'restrictions': [{'cred_def_id': faber_transcript_cred_def_id}]
            }
        }
    })

    logger.info("\"sovrin\" -> Get key for michael did")
    #     michael_sovrin_verkey = await did.key_for_did(pool_handle, sovrin_wallet, sovrin_michael_connection_response['did'])
    michael_sovrin_verkey = await did.key_for_did(pool_handle, sovrin_wallet, sovrin_michael_connection_response['did'])

    logger.info("\"sovrin\" -> Authcrypt \"Job-Application\" Proof Request for michael")
    authcrypted_job_application_proof_request_json = \
        await crypto.auth_crypt(sovrin_wallet, sovrin_michael_key, michael_sovrin_verkey,
                                job_application_proof_request_json.encode('utf-8'))

    logger.info("\"sovrin\" -> Send authcrypted \"Job-Application\" Proof Request to michael")

    logger.info("\"michael\" -> Authdecrypt \"Job-Application\" Proof Request from sovrin")
    sovrin_michael_verkey, authdecrypted_job_application_proof_request_json, _ = \
        await auth_decrypt(michael_wallet, michael_sovrin_key, authcrypted_job_application_proof_request_json)

    logger.info("\"michael\" -> Get credentials for \"Job-Application\" Proof Request")

    search_for_job_application_proof_request = \
        await anoncreds.prover_search_credentials_for_proof_req(michael_wallet,
                                                                authdecrypted_job_application_proof_request_json, None)

    cred_for_attr1 = await get_credential_for_referent(search_for_job_application_proof_request, 'attr1_referent')
    cred_for_attr2 = await get_credential_for_referent(search_for_job_application_proof_request, 'attr2_referent')
    cred_for_attr3 = await get_credential_for_referent(search_for_job_application_proof_request, 'attr3_referent')
    cred_for_attr4 = await get_credential_for_referent(search_for_job_application_proof_request, 'attr4_referent')
    cred_for_attr5 = await get_credential_for_referent(search_for_job_application_proof_request, 'attr5_referent')
    cred_for_predicate1 = \
        await get_credential_for_referent(search_for_job_application_proof_request, 'predicate1_referent')

    await anoncreds.prover_close_credentials_search_for_proof_req(search_for_job_application_proof_request)

    creds_for_job_application_proof = {cred_for_attr1['referent']: cred_for_attr1,
                                       cred_for_attr2['referent']: cred_for_attr2,
                                       cred_for_attr3['referent']: cred_for_attr3,
                                       cred_for_attr4['referent']: cred_for_attr4,
                                       cred_for_attr5['referent']: cred_for_attr5,
                                       cred_for_predicate1['referent']: cred_for_predicate1}

    schemas_json, cred_defs_json, revoc_states_json = \
        await prover_get_entities_from_ledger(pool_handle, michael_faber_did, creds_for_job_application_proof, 'michael')

    logger.info("\"michael\" -> Create \"Job-Application\" Proof")
    job_application_requested_creds_json = json.dumps({
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

    job_application_proof_json = \
        await anoncreds.prover_create_proof(michael_wallet, authdecrypted_job_application_proof_request_json,
                                            job_application_requested_creds_json, michael_master_secret_id,
                                            schemas_json, cred_defs_json, revoc_states_json)

    logger.info("\"michael\" -> Authcrypt \"Job-Application\" Proof for sovrin")
    authcrypted_job_application_proof_json = await crypto.auth_crypt(michael_wallet, michael_sovrin_key, sovrin_michael_verkey,
                                                                     job_application_proof_json.encode('utf-8'))

    logger.info("\"michael\" -> Send authcrypted \"Job-Application\" Proof to sovrin")

    logger.info("\"sovrin\" -> Authdecrypted \"Job-Application\" Proof from michael")
    _, decrypted_job_application_proof_json, decrypted_job_application_proof = \
        await auth_decrypt(sovrin_wallet, sovrin_michael_key, authcrypted_job_application_proof_json)

    schemas_json, cred_defs_json, revoc_ref_defs_json, revoc_regs_json = \
        await verifier_get_entities_from_ledger(pool_handle, sovrin_did,
                                                decrypted_job_application_proof['identifiers'], 'sovrin')

    logger.info("\"sovrin\" -> Verify \"Job-Application\" Proof from michael")
    assert 'Bachelor of Science, Marketing' == \
           decrypted_job_application_proof['requested_proof']['revealed_attrs']['attr3_referent']['raw']
    assert 'graduated' == \
           decrypted_job_application_proof['requested_proof']['revealed_attrs']['attr4_referent']['raw']
    assert '123-45-6789' == \
           decrypted_job_application_proof['requested_proof']['revealed_attrs']['attr5_referent']['raw']

    assert 'michael' == decrypted_job_application_proof['requested_proof']['self_attested_attrs']['attr1_referent']
    assert 'Garcia' == decrypted_job_application_proof['requested_proof']['self_attested_attrs']['attr2_referent']
    assert '123-45-6789' == decrypted_job_application_proof['requested_proof']['self_attested_attrs']['attr6_referent']

    assert await anoncreds.verifier_verify_proof(job_application_proof_request_json,
                                                 decrypted_job_application_proof_json,
                                                 schemas_json, cred_defs_json, revoc_ref_defs_json, revoc_regs_json)

    logger.info("==============================")
    logger.info("== Apply for the job with sovrin - Getting Job-Certificate Credential ==")
    logger.info("------------------------------")
    input("Press Enter to continue...")

    logger.info("\"sovrin\" -> Create \"Job-Certificate\" Credential Offer for michael")
    job_certificate_cred_offer_json = \
        await anoncreds.issuer_create_credential_offer(sovrin_wallet, sovrin_job_certificate_cred_def_id)

    logger.info("\"sovrin\" -> Get key for michael did")
    michael_sovrin_verkey = await did.key_for_did(pool_handle, sovrin_wallet, sovrin_michael_connection_response['did'])

    logger.info("\"sovrin\" -> Authcrypt \"Job-Certificate\" Credential Offer for michael")
    authcrypted_job_certificate_cred_offer = await crypto.auth_crypt(sovrin_wallet, sovrin_michael_key, michael_sovrin_verkey,
                                                                     job_certificate_cred_offer_json.encode('utf-8'))

    logger.info("\"sovrin\" -> Send authcrypted \"Job-Certificate\" Credential Offer to michael")

    logger.info("\"michael\" -> Authdecrypted \"Job-Certificate\" Credential Offer from sovrin")
    sovrin_michael_verkey, authdecrypted_job_certificate_cred_offer_json, authdecrypted_job_certificate_cred_offer = \
        await auth_decrypt(michael_wallet, michael_sovrin_key, authcrypted_job_certificate_cred_offer)

    logger.info("\"michael\" -> Get \"sovrin Job-Certificate\" Credential Definition from Ledger")
    (_, sovrin_job_certificate_cred_def) = \
        await get_cred_def(pool_handle, michael_sovrin_did, authdecrypted_job_certificate_cred_offer['cred_def_id'])

    logger.info("\"michael\" -> Create and store in Wallet \"Job-Certificate\" Credential Request for sovrin")
    (job_certificate_cred_request_json, job_certificate_cred_request_metadata_json) = \
        await anoncreds.prover_create_credential_req(michael_wallet, michael_sovrin_did,
                                                     authdecrypted_job_certificate_cred_offer_json,
                                                     sovrin_job_certificate_cred_def, michael_master_secret_id)

    logger.info("\"michael\" -> Authcrypt \"Job-Certificate\" Credential Request for sovrin")
    authcrypted_job_certificate_cred_request_json = \
        await crypto.auth_crypt(michael_wallet, michael_sovrin_key, sovrin_michael_verkey,
                                job_certificate_cred_request_json.encode('utf-8'))

    logger.info("\"michael\" -> Send authcrypted \"Job-Certificate\" Credential Request to sovrin")

    logger.info("\"sovrin\" -> Authdecrypt \"Job-Certificate\" Credential Request from michael")
    michael_sovrin_verkey, authdecrypted_job_certificate_cred_request_json, _ = \
        await auth_decrypt(sovrin_wallet, sovrin_michael_key, authcrypted_job_certificate_cred_request_json)

    logger.info("\"sovrin\" -> Create \"Job-Certificate\" Credential for michael")
    michael_job_certificate_cred_values_json = json.dumps({
        "first_name": {"raw": "michael", "encoded": "245712572474217942457235975012103335"},
        "last_name": {"raw": "Garcia", "encoded": "312643218496194691632153761283356127"},
        "employee_status": {"raw": "Contract", "encoded": "2143135425425143112321314321"},
        "start_date": {"raw": "10", "encoded": "10"},
        "end_date": {"raw": "100", "encoded": "100"}
    })

    job_certificate_cred_json, _, _ = \
        await anoncreds.issuer_create_credential(sovrin_wallet, job_certificate_cred_offer_json,
                                                 authdecrypted_job_certificate_cred_request_json,
                                                 michael_job_certificate_cred_values_json, None, None)

    logger.info("\"sovrin\" -> Authcrypt \"Job-Certificate\" Credential for michael")
    authcrypted_job_certificate_cred_json = \
        await crypto.auth_crypt(sovrin_wallet, sovrin_michael_key, michael_sovrin_verkey,
                                job_certificate_cred_json.encode('utf-8'))

    logger.info("\"sovrin\" -> Send authcrypted \"Job-Certificate\" Credential to michael")

    logger.info("\"michael\" -> Authdecrypted \"Job-Certificate\" Credential from sovrin")
    _, authdecrypted_job_certificate_cred_json, _ = \
        await auth_decrypt(michael_wallet, michael_sovrin_key, authcrypted_job_certificate_cred_json)

    logger.info("\"michael\" -> Store \"Job-Certificate\" Credential")
    await anoncreds.prover_store_credential(michael_wallet, None, job_certificate_cred_request_metadata_json,
                                            authdecrypted_job_certificate_cred_json,
                                            sovrin_job_certificate_cred_def_json, None)

    logger.info("==============================")
    logger.info("=== Apply for the login with access ==")
    logger.info("==============================")
    logger.info("== Apply for the login with access - Onboarding ==")
    logger.info("------------------------------")
    input("Press Enter to continue...")
    _, access_michael_key, michael_access_did, michael_access_key, \
    access_michael_connection_response = await onboarding(pool_handle, "access", access_wallet, access_did, "michael",
                                                        michael_wallet, michael_wallet_config, michael_wallet_credentials)

    logger.info("==============================")
    logger.info("== Apply for the login with access - Job-Certificate proving  ==")
    logger.info("------------------------------")

    logger.info("\"access\" -> Create \"login-Application-Basic\" Proof Request")
    apply_login_proof_request_json = json.dumps({
        'nonce': '123432421212',
        'name': 'login-Application-Basic',
        'version': '0.1',
        'requested_attributes': {
            'attr1_referent': {
                'name': 'employee_status',
                'restrictions': [{'cred_def_id': sovrin_job_certificate_cred_def_id}]
            }
        },
        'requested_predicates': {
            'predicate1_referent': {
                'name': 'start_date',
                'p_type': '>=',
                'p_value': 10,
                'restrictions': [{'cred_def_id': sovrin_job_certificate_cred_def_id}]
            },
            'predicate2_referent': {
                'name': 'end_date',
                'p_type': '>=',
                'p_value': 90,
                'restrictions': [{'cred_def_id': sovrin_job_certificate_cred_def_id}]
            }
        }
    })

    logger.info("\"access\" -> Get key for michael did")
    michael_access_verkey = await did.key_for_did(pool_handle, access_wallet, access_michael_connection_response['did'])

    logger.info("\"access\" -> Authcrypt \"login-Application-Basic\" Proof Request for michael")
    authcrypted_apply_login_proof_request_json = \
        await crypto.auth_crypt(access_wallet, access_michael_key, michael_access_verkey,
                                apply_login_proof_request_json.encode('utf-8'))

    logger.info("\"access\" -> Send authcrypted \"login-Application-Basic\" Proof Request to michael")

    logger.info("\"michael\" -> Authdecrypt \"login-Application-Basic\" Proof Request from access")
    access_michael_verkey, authdecrypted_apply_login_proof_request_json, _ = \
        await auth_decrypt(michael_wallet, michael_access_key, authcrypted_apply_login_proof_request_json)

    logger.info("\"michael\" -> Get credentials for \"login-Application-Basic\" Proof Request")

    search_for_apply_login_proof_request = \
        await anoncreds.prover_search_credentials_for_proof_req(michael_wallet,
                                                                authdecrypted_apply_login_proof_request_json, None)

    cred_for_attr1 = await get_credential_for_referent(search_for_apply_login_proof_request, 'attr1_referent')
    cred_for_predicate1 = await get_credential_for_referent(search_for_apply_login_proof_request, 'predicate1_referent')
    cred_for_predicate2 = await get_credential_for_referent(search_for_apply_login_proof_request, 'predicate2_referent')

    await anoncreds.prover_close_credentials_search_for_proof_req(search_for_apply_login_proof_request)

    creds_for_apply_login_proof = {cred_for_attr1['referent']: cred_for_attr1,
                                  cred_for_predicate1['referent']: cred_for_predicate1,
                                  cred_for_predicate2['referent']: cred_for_predicate2}

    schemas_json, cred_defs_json, revoc_states_json = \
        await prover_get_entities_from_ledger(pool_handle, michael_access_did, creds_for_apply_login_proof, 'michael')

    logger.info("\"michael\" -> Create \"login-Application-Basic\" Proof")
    apply_login_requested_creds_json = json.dumps({
        'self_attested_attributes': {},
        'requested_attributes': {
            'attr1_referent': {'cred_id': cred_for_attr1['referent'], 'revealed': True}
        },
        'requested_predicates': {
            'predicate1_referent': {'cred_id': cred_for_predicate1['referent']},
            'predicate2_referent': {'cred_id': cred_for_predicate2['referent']}
        }
    })
    michael_apply_login_proof_json = \
        await anoncreds.prover_create_proof(michael_wallet, authdecrypted_apply_login_proof_request_json,
                                            apply_login_requested_creds_json, michael_master_secret_id, schemas_json,
                                            cred_defs_json, revoc_states_json)

    logger.info("\"michael\" -> Authcrypt \"login-Application-Basic\" Proof for access")
    authcrypted_michael_apply_login_proof_json = \
        await crypto.auth_crypt(michael_wallet, michael_access_key, access_michael_verkey,
                                michael_apply_login_proof_json.encode('utf-8'))

    logger.info("\"michael\" -> Send authcrypted \"login-Application-Basic\" Proof to access")

    logger.info("\"access\" -> Authdecrypted \"login-Application-Basic\" Proof from michael")
    _, authdecrypted_michael_apply_login_proof_json, authdecrypted_michael_apply_login_proof = \
        await auth_decrypt(access_wallet, access_michael_key, authcrypted_michael_apply_login_proof_json)

    logger.info("\"access\" -> Get Schemas, Credential Definitions and Revocation Registries from Ledger"
                " required for Proof verifying")

    schemas_json, cred_defs_json, revoc_defs_json, revoc_regs_json = \
        await verifier_get_entities_from_ledger(pool_handle, access_did,
                                                authdecrypted_michael_apply_login_proof['identifiers'], 'access')

    logger.info("\"access\" -> Verify \"login-Application-Basic\" Proof from michael")
    assert 'Contract' == \
           authdecrypted_michael_apply_login_proof['requested_proof']['revealed_attrs']['attr1_referent']['raw']

    assert await anoncreds.verifier_verify_proof(apply_login_proof_request_json,
                                                 authdecrypted_michael_apply_login_proof_json,
                                                 schemas_json, cred_defs_json, revoc_defs_json, revoc_regs_json)


    logger.info("==============================")

    logger.info(" \"Sovrin Steward\" -> Close and Delete wallet")
    await wallet.close_wallet(steward_wallet)
    await wallet.delete_wallet(steward_wallet_config, steward_wallet_credentials)

    logger.info("\"Government\" -> Close and Delete wallet")
    await wallet.close_wallet(government_wallet)
    await wallet.delete_wallet(government_wallet_config, government_wallet_credentials)

    logger.info("\"Faber\" -> Close and Delete wallet")
    await wallet.close_wallet(faber_wallet)
    await wallet.delete_wallet(faber_wallet_config, faber_wallet_credentials)

    logger.info("\"sovrin\" -> Close and Delete wallet")
    await wallet.close_wallet(sovrin_wallet)
    await wallet.delete_wallet(sovrin_wallet_config, sovrin_wallet_credentials)

    logger.info("\"access\" -> Close and Delete wallet")
    await wallet.close_wallet(access_wallet)
    await wallet.delete_wallet(access_wallet_config, access_wallet_credentials)

    logger.info("\"michael\" -> Close and Delete wallet")
    await wallet.close_wallet(michael_wallet)
    await wallet.delete_wallet(michael_wallet_config, michael_wallet_credentials)

    logger.info("Close and Delete pool")
    await pool.close_pool_ledger(pool_handle)
    await pool.delete_pool_ledger_config(pool_name)

    logger.info("Getting started -> done")


async def onboarding(pool_handle, _from, from_wallet, from_did, to, to_wallet: Optional[str], to_wallet_config: str,
                     to_wallet_credentials: str):
    logger.info("\"{}\" -> Create and store in Wallet \"{} {}\" DID".format(_from, _from, to))
    (from_to_did, from_to_key) = await did.create_and_store_my_did(from_wallet, "{}")

    logger.info("\"{}\" -> Send Nym to Ledger for \"{} {}\" DID".format(_from, _from, to))
    await send_nym(pool_handle, from_wallet, from_did, from_to_did, from_to_key, None)

    logger.info("\"{}\" -> Send connection request to {} with \"{} {}\" DID and nonce".format(_from, to, _from, to))
    connection_request = {
        'did': from_to_did,
        'nonce': 123456789
    }

    if not to_wallet:
        logger.info("\"{}\" -> Create wallet".format(to))
        try:
            await wallet.create_wallet(to_wallet_config, to_wallet_credentials)
        except IndyError as ex:
            if ex.error_code == ErrorCode.PoolLedgerConfigAlreadyExistsError:
                pass
        to_wallet = await wallet.open_wallet(to_wallet_config, to_wallet_credentials)

    logger.info("\"{}\" -> Create and store in Wallet \"{} {}\" DID".format(to, to, _from))
    (to_from_did, to_from_key) = await did.create_and_store_my_did(to_wallet, "{}")

    logger.info("\"{}\" -> Get key for did from \"{}\" connection request".format(to, _from))
    from_to_verkey = await did.key_for_did(pool_handle, to_wallet, connection_request['did'])

    logger.info("\"{}\" -> Anoncrypt connection response for \"{}\" with \"{} {}\" DID, verkey and nonce"
                .format(to, _from, to, _from))
    connection_response = json.dumps({
        'did': to_from_did,
        'verkey': to_from_key,
        'nonce': connection_request['nonce']
    })
    anoncrypted_connection_response = await crypto.anon_crypt(from_to_verkey, connection_response.encode('utf-8'))

    logger.info("\"{}\" -> Send anoncrypted connection response to \"{}\"".format(to, _from))

    logger.info("\"{}\" -> Anondecrypt connection response from \"{}\"".format(_from, to))
    decrypted_connection_response = \
        json.loads((await crypto.anon_decrypt(from_wallet, from_to_key,
                                              anoncrypted_connection_response)).decode("utf-8"))

    logger.info("\"{}\" -> Authenticates \"{}\" by comparision of Nonce".format(_from, to))
    assert connection_request['nonce'] == decrypted_connection_response['nonce']

    logger.info("\"{}\" -> Send Nym to Ledger for \"{} {}\" DID".format(_from, to, _from))
    await send_nym(pool_handle, from_wallet, from_did, to_from_did, to_from_key, None)

    return to_wallet, from_to_key, to_from_did, to_from_key, decrypted_connection_response


async def get_verinym(pool_handle, _from, from_wallet, from_did, from_to_key,
                      to, to_wallet, to_from_did, to_from_key, role):
    logger.info("\"{}\" -> Create and store in Wallet \"{}\" new DID".format(to, to))
    (to_did, to_key) = await did.create_and_store_my_did(to_wallet, "{}")

    logger.info("\"{}\" -> Authcrypt \"{} DID info\" for \"{}\"".format(to, to, _from))
    did_info_json = json.dumps({
        'did': to_did,
        'verkey': to_key
    })
    authcrypted_did_info_json = \
        await crypto.auth_crypt(to_wallet, to_from_key, from_to_key, did_info_json.encode('utf-8'))

    logger.info("\"{}\" -> Send authcrypted \"{} DID info\" to {}".format(to, to, _from))

    logger.info("\"{}\" -> Authdecrypted \"{} DID info\" from {}".format(_from, to, to))
    sender_verkey, authdecrypted_did_info_json, authdecrypted_did_info = \
        await auth_decrypt(from_wallet, from_to_key, authcrypted_did_info_json)

    logger.info("\"{}\" -> Authenticate {} by comparision of Verkeys".format(_from, to, ))
    assert sender_verkey == await did.key_for_did(pool_handle, from_wallet, to_from_did)

    logger.info("\"{}\" -> Send Nym to Ledger for \"{} DID\" with {} Role".format(_from, to, role))
    await send_nym(pool_handle, from_wallet, from_did, authdecrypted_did_info['did'],
                   authdecrypted_did_info['verkey'], role)

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


async def get_cred_def(pool_handle, _did, schema_id):
    get_cred_def_request = await ledger.build_get_cred_def_request(_did, schema_id)
    get_cred_def_response = await ledger.submit_request(pool_handle, get_cred_def_request)
    return await ledger.parse_get_cred_def_response(get_cred_def_response)


async def get_credential_for_referent(search_handle, referent):
    credentials = json.loads(
        await anoncreds.prover_fetch_credentials_for_proof_req(search_handle, referent, 10))
    return credentials[0]['cred_info']


async def prover_get_entities_from_ledger(pool_handle, _did, identifiers, actor):
    schemas = {}
    cred_defs = {}
    rev_states = {}
    for item in identifiers.values():
        logger.info("\"{}\" -> Get Schema from Ledger".format(actor))
        (received_schema_id, received_schema) = await get_schema(pool_handle, _did, item['schema_id'])
        schemas[received_schema_id] = json.loads(received_schema)

        logger.info("\"{}\" -> Get Claim Definition from Ledger".format(actor))
        (received_cred_def_id, received_cred_def) = await get_cred_def(pool_handle, _did, item['cred_def_id'])
        cred_defs[received_cred_def_id] = json.loads(received_cred_def)

        if 'rev_reg_seq_no' in item:
            pass  # TODO Create Revocation States

    return json.dumps(schemas), json.dumps(cred_defs), json.dumps(rev_states)


async def verifier_get_entities_from_ledger(pool_handle, _did, identifiers, actor):
    schemas = {}
    cred_defs = {}
    rev_reg_defs = {}
    rev_regs = {}
    for item in identifiers:
        logger.info("\"{}\" -> Get Schema from Ledger".format(actor))
        (received_schema_id, received_schema) = await get_schema(pool_handle, _did, item['schema_id'])
        schemas[received_schema_id] = json.loads(received_schema)

        logger.info("\"{}\" -> Get Claim Definition from Ledger".format(actor))
        (received_cred_def_id, received_cred_def) = await get_cred_def(pool_handle, _did, item['cred_def_id'])
        cred_defs[received_cred_def_id] = json.loads(received_cred_def)

        if 'rev_reg_seq_no' in item:
            pass  # TODO Get Revocation Definitions and Revocation Registries

    return json.dumps(schemas), json.dumps(cred_defs), json.dumps(rev_reg_defs), json.dumps(rev_regs)


async def auth_decrypt(wallet_handle, key, message):
    from_verkey, decrypted_message_json = await crypto.auth_decrypt(wallet_handle, key, message)
    decrypted_message_json = decrypted_message_json.decode("utf-8")
    decrypted_message = json.loads(decrypted_message_json)
    return from_verkey, decrypted_message_json, decrypted_message


if __name__ == '__main__':
    run_coroutine(run)
    time.sleep(1)  # FIXME waiting for libindy thread complete
