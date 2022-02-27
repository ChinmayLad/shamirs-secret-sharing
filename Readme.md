# Shamir's Secret Sharing

Implementation for Shamir's Secret Sharing Algorithm used for splitting the private key (key thresholding) into number of parts and regenerating the private key back.

**Language**

Python 3.6

**Libraries Used:**
- Crypto (https://github.com/dlitz/pycrypto)

**Steps:**
1. Execute Initiator.py and follow the steps that appear on the console.
2. Execute ShareCalculator.py which creates decryption shares for each part (di).
3. Execute DecryptMessage.py for decrypting the cipher text.

**Note:**
On executing Initiator.py the message to be encrypted is provided as input.
The decrypted message will be shown to the user on execution of DecryptMessage.py.
