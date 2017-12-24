# MMeTokenDecrypt

**Update December 24, 2017**

***Token extraction without needing Keychain***

Authentication tokens are cached in a database on **macOS < 10.13 (pre High-Sierra)**. Any testers for other macOS versions would be appreciated.

This update adds a function to hunt for these cached authentication tokens in ~/Library/Accounts/Accounts3.sqlite and ~/Library/Accounts/Accounts4.sqlite. Authentication tokens seem to be stored in this database under the table ZACCOUNTPROPERTY where ZKEY = AccountDelegate. This field contains a binary plist that can be converted to XML, yielding plaintext authentication tokens.

No decryption is needed to access this information in the Accounts database. 

**Implications** of this:

* No more keychain. 
* No more keychain means that if a forensics investigator (or attacker) has read access to a filesystem they can extract these authentication tokens, **without** having to know the user's keychain password, (or if the user is logged in, **without** having to prompt the user for keychain access).

Also, added some code to display when these authentication tokens were generated on Apple's servers.

## Purpose

This program decrypts / extracts all authentication tokens on macOS / OS X / OSX. No user authentication is needed, due to the flawed way in which macOS authorizes keychain access.

Authentication tokens are stored in `/Users/*/Library/Application Support/iCloud/Accounts/DSID` where DSID is Apple's backend identifier for each iCloud account in their system. 

This `DSID` file is encrypted with `AES-128 CBC` and an empty `intialization vector` (IV). The decryption key for this file is stored in the User's `keychain`, under the service name entry `iCloud`, with the name being the primary email address associated with an iCloud account.

This `decryption key` is decoded in base64, and then used as the message in a standard `MD5 Hmac`. The problem is, the key to the Hmac is buried deep in the `internals of MacOS`. This key is a 44 character long string of random letters that is necessary to decrypt the DSID file. This key is included in the source code of this repository, and as far as I know, has been published no where else on the internet.

## Significance

The only software that performs a similar function is the forensics grade "Elcomsoft Phone Breaker". MMeTokenDecrypt allows any developer to incorporate the decryption of iCloud authorization files into their projects, open sourced.

Apple needs to redesign the way that keychain information is requested. Because this program forks a security subprocess, which is an Apple signed binary, the user is not alerted to the potential dangerous nature of the keychain request dialog. Additionally, an attacker can repeatedly present the user with the keychain dialog, until the user accepts the keychain request, because Apple does not put a timeout on the "deny" attempts. This allows for trivial compromization of iCloud authorization tokens, which can be used to access almost every iCloud service, including `iOS backups, iCloud Contacts, iCloud Drive, iCloud Photo Library, Find my Friends, and Find my iPhone` (see my other repositories).

## Timeline and Reporting

* Reached out to Apple on October 17, 2016. I extensively detailed the broken way in which user keychain authentication occurs on all versions of macOS. 

* I have not heard back from Apple as of November 6, 2016. 

* The bug report encompasses broken keychain access as a whole. MMeTokenDecrypt is one implementation of this bug. See my other repository, OSXChromeDecrypt for another implementation of this bug.

* One notable excerpt from the bug report is as follows `Furthermore, if we are a remote attacker, and if "ask for keychain password" is not checked, it is very trivial to implement code that essentially forces a user to click "allow", by forcing the prompt on them until they click accept and we retrieve the password. However, if "ask for keychain password" is checked, and the user clicks "deny" once, it becomes significantly trickier to repeatedly force the prompt (see references).`

* I have uploaded the bug report to this repository, and will update this file with any updates from Apple.

---
## Usage

```
python MMeDecrypt.py
```

```
Decrypting token plist -> [/Users/bob/Library/Application Support/iCloud/Accounts/123456789]

Successfully decrypted token plist!

bobloblaw@gmail.com Bob Loblaw -> [123456789]

cloudKitToken = AQAAAABYXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX~

mapsToken = AQAAAAXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX~

mmeAuthToken = AQAAAABXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX=

mmeBTMMInfiniteToken = AQAAAABXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX~

mmeFMFAppToken = AQAAAABXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX~

mmeFMIPToken = AQAAAABXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX~
```

## Notes

If you are using a homebrew-installed version of python you may see the following error when running the script:

```
user@system:~/code/MMeTokenDecrypt $ python MMeDecrypt.py
Traceback (most recent call last):
  File "MMeDecrypt.py", line 2, in <module>
    from Foundation import NSData, NSPropertyListSerialization
ImportError: No module named Foundation
```

You can work around this error by manually specifying the full path to the default system version of python that ships with your OS X version:
```
user@system:~/code/MMeTokenDecrypt $ /usr/bin/python MMeDecrypt.py
Decrypting token plist -> [/Users/user/Library/Application Support/iCloud/Accounts/123413453]

Successfully decrypted token plist!

user@email.com [First Last -> 123413453]
{
    cloudKitToken = "AQAAAABXXXXXXXXXXXXXXXXXXXXXXXXXXXXX~";
    mapsToken = "AQAAAAXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX~";
    mmeAuthToken = "AQAAAABXXXXXXXXXXXXXXXXXXXXXXXXXXXXX=";
    mmeBTMMInfiniteToken = "AQAAAABXXXXXXXXXXXXXXXXXXXXXXXXXXXXX~";
    mmeFMFAppToken = "AQAAAABXXXXXXXXXXXXXXXXXXXXXXXXXXXXX~";
    mmeFMIPToken = "AQAAAABXXXXXXXXXXXXXXXXXXXXXXXXXXXXX~";
}
```
***Verified on Mac OS X El Capitan***
