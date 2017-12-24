import base64
import hashlib
import hmac
import subprocess
import sys
import glob
import os
import binascii
import datetime
import struct
import sqlite3
import platform
from Foundation import NSData, NSPropertyListSerialization


def get_gen_time(token_value):
    # it appears that apple stores the generation time of the token into
    # the token. this data is stored in 4 bytes, as a big endian integer.
    # this function extracts the bytes, decodes them, and converts them
    # to a datetime object, and returns a string representation of that
    # datetime object
    try:
        token_c = token_value.replace("\"", "").replace("~", "=")
        time_d = base64.b64decode(token_c).encode("hex").split("00000000")[1:]
        time_h = [x for x in time_d if not x.startswith("0")][0][:8]
        time_i = struct.unpack(">I", binascii.unhexlify(time_h))[0]
        gen_time = "{}".format(datetime.datetime.fromtimestamp(time_i))
        # hate to catch generic exception, but getting generation time
        # is second to getting tokens, and the above code is not
        # perfect for splitting out the encoded time in the tokens
        # error is usually for bad base64 padding though
    except Exception:
        gen_time = "Could not find creation time."

    return gen_time


def bin2str(token_bplist, account_bplist=None):
    # convert the decrypted binary plist to an NSData object that can be read
    bin_list = NSData.dataWithBytes_length_(token_bplist, len(token_bplist))

    # convert the binary NSData object into a dictionary object
    token_plist = NSPropertyListSerialization.propertyListWithData_options_format_error_(bin_list,
                                                                                         0, None, None)[0]

    # accounts db cache
    if "$objects" in token_plist:
        # bc it is accounts db cache, we should also have been passed
        # account_bplist.
        bin_list = NSData.dataWithBytes_length_(account_bplist,
                                                len(account_bplist))
        dsid_plist = NSPropertyListSerialization.propertyListWithData_options_format_error_(bin_list,
                                                                                            0, None, None)[0]
        for obj in dsid_plist["$objects"]:
            if "{}".format(obj).startswith("urn:ds:"):
                dsid = obj.replace("urn:ds:", "")

        token_dict = {"dsid": dsid}

        # do some parsing to get the data out bc it is not stored
        # in a format that is easy to process with stdlibs
        token_l = [x.strip().replace(",", "") for x in
                   "{}".format(token_plist["$objects"]).splitlines()]

        pos_start = token_l.index("mmeBTMMInfiniteToken")
        pos_end = (token_l.index("cloudKitToken") - pos_start + 1) * 2

        token_short = token_l[pos_start:pos_start + pos_end]
        zipped = zip(token_short[:len(token_short) / 2],
                     token_short[len(token_short) / 2:])

        for token_type, token_value in zipped:
            # attempt to get generation time
            # this parsing is a little hacky, but it seems to be the best way
            # to handle all different kinds of iCloud tokens (new and old)
            gen_time = get_gen_time(token_value)

            token_dict[token_type] = (token_value, gen_time)

        return token_dict

    else:
        return token_plist


def main():
    # try to find information in database first.
    root_path = "{}/Library/Accounts".format(os.path.expanduser("~"))
    accounts_db = "{}/Accounts3.sqlite".format(root_path)

    if os.path.isfile("{}/Accounts4.sqlite".format(root_path)):
        accounts_db = "{}/Accounts4.sqlite".format(root_path)

    conn = sqlite3.connect(accounts_db)
    curr = conn.cursor()
    data = curr.execute("SELECT * FROM ZACCOUNTPROPERTY WHERE "
                        "ZKEY='AccountDelegate'")

    # 5th index is the value we are interested in (bplist of tokens)
    token_bplist = data.fetchone()[5]

    data = curr.execute("SELECT * FROM ZACCOUNTPROPERTY WHERE "
                        "ZKEY='account-info'")

    # 5th index will be a bplist with dsid
    dsid_bplist = data.fetchone()[5]

    if not int(platform.mac_ver()[0].split(".")[1]) >= 13:
        print("Tokens are not cached on >= 10.13")
        token_bplist = ""

    # we got the bplists
    if "{}".format(token_bplist).startswith("bplist00"):
        print("{}Parsing tokens from cached accounts database at [{}]{}"
              "".format(bold, accounts_db.split("/")[-1], end))
        token_dict = bin2str("{}".format(token_bplist),
                             "{}".format(dsid_bplist))

        print("{}DSID: {}{}\n".format(bold, token_dict["dsid"], end))
        del token_dict["dsid"]

        for t_type, t_val in token_dict.items():
            print("{}{}{}: {}".format(violet, t_type, end, t_val[0]))
            print("{}Creation time: {}{}\n".format(green, t_val[1], end))
        return

    print("Checking keychain.")
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
            # we can convert to int, that means we have the dsid file.
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
    token_plist = bin2str(decrypted)
    print("Successfully decrypted token plist!\n")
    print("{} [{} -> {}]\n".format(token_plist["appleAccountInfo"]["primary"
                                                                   "Email"],
                                   token_plist["appleAccountInfo"]["full"
                                                                   "Name"],
                                   token_plist["appleAccountInfo"]["dsPr"
                                                                   "sID"]))

    for t_type, t_value in token_plist["tokens"].items():
        print("{}{}{}: {}".format(violet, t_type, end, t_value))
        print("{}Creation time: {}{}\n".format(green, get_gen_time(t_value),
                                               end))


green = "\033[32m"
violet = "\033[35m"
bold = "\033[1m"
end = "\033[0m"

if __name__ == "__main__":
    main()
