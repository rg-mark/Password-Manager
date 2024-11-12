# Password-Manager
https://github.com/rg-mark/Password-Manager
Contributors:
138906 Mark Munene Rugendo
151777_Emmanuel Mugambi Riungu
149912 Chiman Garang Diing

This project is a Password Manager implemented in JavaScript, utilizing cryptographic principles to securely store and manage user passwords and sensitive data. Key features include:


1. We prevent adversaries from learning information about the length of passwords by  encrypting each password along with padding to make all passwords appear to be the same size.

2. We prevent swap attacks by Encrypting passwords in the memory using AES-GCM. Furthermore, we avoid storing encryption keys that are easily accessible.

3. Rollback attacks can be mitigated using techniques such as:
Timestamps: Including a version number with the data that allows the system to verify whether the data has been modified.
Versioning: Storing a cryptographic version number or hash in the password database to indicate which version of the data is valid.

4. When using a randomized MAC, we cannot use the MAC key directly because the output changes upon every operation. Therefore, we store the hash of the MAC along with the password maintaining the MAC’s integrity without exposing it. This poses a minimal performance penalty as it is more computationally expensive.
  
5. Approaches to reduce the information leaked about the number of records:
 Dummy records: Adding random records to obscure the true number of records. 
 Blinding: The number of records is made unintelligible.

6. Multi-user support for specific sites could be achieved by storing domain passwords separately for each user using symmetric encryption. When Alice and Bob need access to a shared password, the password can be encrypted using a shared key which is derived from their master passwords.
