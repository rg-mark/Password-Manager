"use strict";

/********* External Imports ********/

const { stringToBuffer, bufferToString, encodeBuffer, decodeBuffer, getRandomBytes } = require("./lib");
const { subtle } = require('crypto').webcrypto;

/********* Constants ********/

const PBKDF2_ITERATIONS = 100000; // number of iterations for PBKDF2 algorithm
const MAX_PASSWORD_LENGTH = 64;   // we can assume no password is longer than this many characters

/********* Implementation ********/
class Keychain {
  /**
   * Initializes the keychain using the provided information. Note that external
   * users should likely never invoke the constructor directly and instead use
   * either Keychain.init or Keychain.load. 
   * Arguments:
   *  You may design the constructor with any parameters you would like. 
   * Return Type: void
   */
  constructor() {
    this.data = { 
      /* Store member variables that you intend to be public here
         (i.e. information that will not compromise security if an adversary sees) */
         salt_master_key: null,
         salt_mac_key: null,
         salt_aes_key: null,
         password_sig: null,
         kvs_salts: {},
         kvs: {}
    };
    this.secrets = {
      /* Store member variables that you intend to be private here
         (information that an adversary should NOT see). */
         mac_key: null,
         aes_key: null,
         kvs_hash: null
    };
    this.decryptData = this.decryptData.bind(this);
  };

  /** 
    * Creates an empty keychain with the given password.
    *
    * Arguments:
    *   password: string
    * Return Type: void
    */
  static async init(password) {
    if (password.length > MAX_PASSWORD_LENGTH) {
      throw new Error("Password exceeds maximum length");
    }
  
    // Generate random salts for key derivation (16 bytes each)
    const salt_master_key = getRandomBytes(16);
    const salt_mac_key = getRandomBytes(16);
    const salt_aes_key = getRandomBytes(16);
  
    // Convert password string to ArrayBuffer
    const passwordBuffer = stringToBuffer(password);
  
    // Import password buffer as a CryptoKey for PBKDF2
    const baseKey = await subtle.importKey(
      "raw",
      passwordBuffer,
      "PBKDF2",
      false,
      ["deriveKey"]
    );
  
    // Derive the master key using PBKDF2
    const master_key = await subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt_master_key,
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256"
      },
      baseKey, // Use the imported CryptoKey as the baseKey
      { name: "HMAC", hash: "SHA-256", length: 256 },
      false,
      ["sign", "verify"]
    );
  
    // Derive MAC and AES keys by signing the salts with the master key
    const raw_mac_key = await subtle.sign("HMAC", master_key, salt_mac_key);
    const raw_aes_key = await subtle.sign("HMAC", master_key, salt_aes_key);
  
    // Import the raw derived keys as CryptoKeys
    const mac_key = await subtle.importKey(
      "raw",
      raw_mac_key,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign", "verify"]
    );
  
    const aes_key = await subtle.importKey(
      "raw",
      raw_aes_key,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  
    // Initialize keychain and store derived keys and salts
    const keychain = new Keychain();
    keychain.data.salt_master_key = salt_master_key;
    keychain.data.salt_mac_key = salt_mac_key;
    keychain.data.salt_aes_key = salt_aes_key;
    keychain.secrets.mac_key = mac_key;
    keychain.secrets.aes_key = aes_key;
  
    return keychain;
  }
  

  // Derive an encryption key from the password and salt using PBKDF2.
  static async deriveKey(password, salt) {
    const passwordBuffer = stringToBuffer(password);

    const baseKey = await subtle.importKey(
      "raw",
      passwordBuffer,
      "PBKDF2",
      false,
      ["deriveKey"]
    );

    return subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: salt,
        iterations: PBKDF2_ITERATIONS,
        hash: "SHA-256"
      },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  /** 
    * Loads the keychain state from the provided representation (repr). The
    * repr variable will contain a JSON encoded serialization of the contents
    * of the KVS (as returned by the dump function). The trustedDataCheck
    * is an *optional* SHA-256 checksum that can be used to validate the 
    * integrity of the contents of the KVS. If the checksum is provided and the
    * integrity check fails, an exception should be thrown. You can assume that
    * the representation passed to load is well-formed (i.e., it will be
    * a valid JSON object).Returns a Keychain object that contains the data
    * from repr. 
    *
    * Arguments:
    *   password:           string
    *   repr:               string
    *   trustedDataCheck: string
    * Return Type: Keychain
    */

  
  async decryptData(encryptedData, key) {
    const iv = getRandomBytes(12);  // Ensure IV matches the one used during encryption
    try {
      // Decrypt the encrypted data using AES-GCM
      const decryptedBuffer = await subtle.decrypt(
        {
          name: "AES-GCM",
          iv: iv,  // Use the IV that was used during encryption
        },
        key,  // The AES key used for decryption
        encryptedData  // The encrypted data to decrypt
      );
  
      // Return the decrypted data (as a string, for example)
      return bufferToString(decryptedBuffer);
    } catch (error) {
      console.error("Decryption failed:", error);
      throw new Error("Decryption failed");
    }
  }
      
  
  static async load(password, repr, trustedDataCheck) {
    const { data, secrets, salt, checksum, kvs } = JSON.parse(repr);

    // Derive the key from the password and salt.
    const derivedKey = await this.deriveKey(password, decodeBuffer(salt));

    // Verify the integrity of the loaded data
    if (trustedDataCheck) {
      const computedChecksum = await this.computeChecksum(repr);
      if (computedChecksum !== trustedDataCheck) {
        throw new Error("Data integrity check failed.");
      }
    }

    // Decrypt the encrypted data
    const decryptedData = await this.decryptData(data, derivedKey);

    // Return a Keychain instance initialized with the decrypted data and derived key.
    const keychain = new Keychain();
    keychain.data = decryptedData;
    keychain.secrets = secrets;
    keychain.data.kvs = kvs;

    return keychain;
  }

  // Compute a SHA-256 checksum of the given data.
  static async computeChecksum(data) {
    const dataBuffer = stringToBuffer(data);
    const hashBuffer = await subtle.digest("SHA-256", dataBuffer);
    return bufferToString(hashBuffer); // Convert buffer to string
  }

  /**
    * Returns a JSON serialization of the contents of the keychain that can be 
    * loaded back using the load function. The return value should consist of
    * an array of two strings:
    *   arr[0] = JSON encoding of password manager
    *   arr[1] = SHA-256 checksum (as a string)
    * As discussed in the handout, the first element of the array should contain
    * all of the data in the password manager. The second element is a SHA-256
    * checksum computed over the password manager to preserve integrity.
    *
    * Return Type: array
    * @returns {PromiseArray<string>>}
    */ 
  async dump() {
    // Serialize data, secrets, and salt to JSON
    const serializedData = JSON.stringify({
      data: this.data,
      secrets: this.secrets,
      salt: encodeBuffer(this.data.salt_master_key),
      kvs: this.data.kvs 
    });
    
    // Compute a SHA-256 Checksum of the serialized data
    const checksum = await subtle.digest("SHA-256", stringToBuffer(serializedData));

    // Return the serialized data and checksum as an array
    return [serializedData, bufferToString(checksum)];
  }

  /**
    * Fetches the data (as a string) corresponding to the given domain from the KVS.
    * If there is no entry in the KVS that matches the given domain, then return
    * null.
    *
    * Arguments:
    *   name: string
    * Return Type: Promise<string>
    */
  async get(name) {
    // Check if the specified key exists in secrets
    if (!(name in this.secrets)) {
      return null; // Return null if key is not found
    }

    // Extract the encrypted data and initialization vector (IV)
    const { encryptedData, iv } = this.secrets[name];

    try {
      // Decrypt the encrypted data using AES-GCM and return the plaintext
      const decryptedBuffer = await subtle.decrypt(
        {
          name: "AES-GCM",
          iv: decodeBuffer(iv) // Decode IV for decryption
        },
        this.secrets.aes_key,
        decodeBuffer(encryptedData) // Decode encrypted data
      );

      return bufferToString(decryptedBuffer);
    } catch (error) {
      console.error("Decryption failed:", error);
      return null; // Return null if decryption fails
    }
  }

  /** 
    * Inserts the domain and associated data into the KVS. If the domain is
    * already in the password manager, this method should update its value. If
    * not, create a new entry in the password manager.
    *
    * Arguments:
    *   name: string
    *   value: string
    * Return Type: void
    */
  async set(name, value) {
    const iv = getRandomBytes(12);

    // Convert value to an ArrayBuffer for encryption
    const valueBuffer = stringToBuffer(value);
    const nameBuffer = stringToBuffer(name);

    try {
      // Encrypt the data with AES-GCM encryption
      const encryptedBuffer = await subtle.encrypt(
       {
        name: "AES-GCM",
        iv: iv, // Initialization vector
       },
       this.secrets.aes_key,
       valueBuffer
      );
      // Store the encrypted data and IV in secrets
      this.secrets[name] = {
        encryptedData: encodeBuffer(encryptedBuffer),
        iv: encodeBuffer(iv)
      };
    } catch (error) {
      console.error("Encryption failed:", error);
    }
  }

  /**
    * Removes the specified domain from the password manager. If the domain
    * does not exist in the password manager, return false.
    *
    * Arguments:
    *   name: string
    * Return Type: boolean
    */
  async remove(name) {
    // Check if the domain exists and remove it from secrets
    if (name in this.secrets) {
      delete this.secrets[name];
      return true; // Return true if removed
    }
    return false; // Return false if domain does not exist
  }

  /**
    * Placeholder method to handle decryption of data. You can expand on this
    * based on your specific decryption needs. This method will take data and
    * use the provided key to decrypt it.
    *
    * Arguments:
    *   data: string
    *   key: ArrayBuffer
    * Return Type: string
    */
  
}

module.exports = { Keychain };
