#!/usr/bin/env python3
import struct
import sys
import argparse
from pathlib import Path
from uuid import UUID
from enum import Enum
import string
# for PEM and DER certificate validation and interconvertion
from cryptography import x509
from cryptography.hazmat.primitives import serialization

class CONFIG_PRESETS(Enum):
    ESL_CERT_CREATE = 0,
    ESL_CERT_APPEND = 1,
    ESL_HASH_APPEND = 2,
    ESL_HASH_CREATE = 3

SHA256_SUM_SIZE = 32
HASH_SIZE = SHA256_SUM_SIZE
HASH_LENGTH = HASH_SIZE * 2

# UEFI specified values
ESL_X509_GUID = "a5c059a1-94e4-4aa7-87b5-ab155c2bf072"
ESL_HASH_GUID = "c1c41626-504c-4092-aca9-41f936934328"
ESL_META_SIZE = 16 + 12
OWNER_GUID_SIZE = 16
ESL_HASH_SIZE = OWNER_GUID_SIZE + SHA256_SUM_SIZE
SINGLE_DIGEST_ESL_FILE_SIZE = ESL_META_SIZE + ESL_HASH_SIZE
# little-endian encoded buffer of the above variables
ESL_HASH_GUID_BUFFER = b'\x26\x16\xc4\xc1\x4c\x50\x92\x40\xac\xa9\x41\xf9\x36\x93\x43\x28'
ESL_X509_GUID_BUFFER = b'\xa1\x59\xc0\xa5\xe4\x94\xa7\x4a\x87\xb5\xab\x15\x5c\x2b\xf0\x72'
ESL_HEAD_SIZE_BUFFER = b'\x00\x00\x00\x00'
ESL_HASH_SIZE_BUFFER = b'\x30\x00\x00\x00'
SINGLE_DIGEST_ESL_FILE_SIZE_BUFFER = b'\x4c\x00\x00\x00'

def create_esl_meta(certificate_size = None):
    # ESL_META for digest
    if certificate_size == None: return b''.join([ESL_HASH_GUID_BUFFER, SINGLE_DIGEST_ESL_FILE_SIZE_BUFFER, ESL_HEAD_SIZE_BUFFER, ESL_HASH_SIZE_BUFFER])
    # ESL_META for DER certificate
    esl_data_size_buffer = struct.pack('<I', OWNER_GUID_SIZE + certificate_size)
    esl_file_size = ESL_META_SIZE + OWNER_GUID_SIZE + certificate_size
    esl_file_size_buffer = struct.pack('<I', esl_file_size)
    return b''.join([ESL_X509_GUID_BUFFER, esl_file_size_buffer, ESL_HEAD_SIZE_BUFFER, esl_data_size_buffer])

def job_router(output_file_size, config_flag, certificate_file, digest_buffer, output_file, signature_owner_guid):
    signature_owner_guid_buffer = signature_owner_guid.bytes_le # little-endian bytes
    certificate_file_size = None if certificate_file == None else Path(certificate_file.name).stat().st_size
    
    if certificate_file_size != None:
        if certificate_file_size < 300: raise ValueError("DER certificate too small (<300 bytes)")
        if certificate_file_size > 1024 * 1024: raise ValueError("Certificate too large (>1MB)")
    
    if config_flag == CONFIG_PRESETS.ESL_HASH_APPEND:
        with output_file as output_file:
            output_file.write(signature_owner_guid_buffer)
            output_file.write(digest_buffer)
        
        # Update file size
        with open(output_file.name, 'r+b') as output_file:
            output_file.seek(0x10)
            output_file.write(struct.pack('<I', output_file_size + ESL_HASH_SIZE))
    
    if config_flag == CONFIG_PRESETS.ESL_HASH_CREATE:
        esl_meta_buffer = create_esl_meta() # parameter = None, default meta for digest
        with output_file as output_file:
            output_file.write(esl_meta_buffer)
            output_file.write(signature_owner_guid_buffer)
            output_file.write(digest_buffer)
    
    if config_flag == CONFIG_PRESETS.ESL_CERT_APPEND:
        esl_meta_buffer = create_esl_meta(certificate_file_size)
        # Check if certificate is X509 DER format
        with certificate_file as certificate_file:
            certificate_content = certificate_file.read()
            
            try:
                certificate = x509.load_der_x509_certificate(certificate_content)
                print("✅ Valid X.509 DER certificate")
            except:
                try:
                    certificate = x509.load_pem_x509_certificate(certificate_content)
                    print("✅ Valid X.509 PEM certificate. Converting to DER")
                    certificate_content = certificate.public_bytes(serialization.Encoding.DER)
                except:
                    print("❌ Not a valid PEM or DER X.509 certificate")
                    output_file.close()
                    sys.exit(1)
        # write ESL certificate file
        with output_file as output_file:
            output_file.write(esl_meta_buffer)
            output_file.write(signature_owner_guid_buffer)
            output_file.write(certificate_content)

def main():
    args = format_arguments()
    outfile_size = validate_arguments(args.append, args.outfile)
    config_flag = parse_configuration(args.append, args.cert, args.digest, outfile_size)
    job_router(outfile_size, config_flag, args.cert, args.digest, args.outfile, args.owner)

def parse_configuration(append, cert, digest, outfile_size):
    if digest != None: # smallest ESL_HASH_FILE with only one SHA256 digest
        if append and outfile_size >= 76: return CONFIG_PRESETS.ESL_HASH_APPEND
        else: return CONFIG_PRESETS.ESL_HASH_CREATE
    # CERT_CREATE starts empty output file but CERT_APPEND starts with non-empty output file. But the data is same
    if cert != None: return CONFIG_PRESETS.ESL_CERT_APPEND

def validate_arguments(append, outfile):
    outfile_size = Path(outfile.name).stat().st_size
    if not append and outfile_size > 0:
        print(f"Error: File '{outfile.name}' already exists and is not empty. Use --append to append.")
        outfile.close()
        sys.exit(1)
    return outfile_size

def format_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--outfile", metavar='FILE.esl', type=argparse.FileType('ab', 0), required=True, help="path to output binary file")
    parser.add_argument("-g", "--owner", metavar='XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX', type=UUID, required=True, help="signature owner GUID")
    parser.add_argument("-a", "--append", action="store_true", default=False, 
        help="if digest is provided, will append digest to existing output file that only contains digests.\n"
        "if certificate is provided, will append generated the ESL content to the existing output file")
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-d", "--digest", metavar='YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY', type=SHA256_bytes, help="SHA256 digest")
    group.add_argument("-c", "--cert", metavar='CERT.der', type=argparse.FileType('rb', 0), help="path to input file - X.509 PEM or DEM certificate")
    
    return parser.parse_args()

def SHA256_bytes(s):
    if len(s) == HASH_LENGTH and all(c in string.hexdigits for c in s): return int(s, 16).to_bytes(32, 'big')
    raise argparse.ArgumentTypeError(f"Invalid hex digest: {s} SHA256 sum must be 64 characters and only contain 0-9a-fA-F")

if __name__ == "__main__": main()
