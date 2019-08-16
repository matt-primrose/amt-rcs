/*
Copyright 2019 Intel Corporation

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
const crypto = require('crypto');
const forge = require('node-forge');
let cryptoHelpers = new Object();
/**
* @description Signs the concatinated nonce with the private key of the provisioning certificate and encodes as base64
* @param {string} message Message to be signed
* @param {string} key Private key of provisioning certificate
* @returns {string} Returns the signed string
*/
cryptoHelpers.signString = function(message, key) {
    try {
        let signer = crypto.createSign('sha256');
        signer.update(message);
        let sign = signer.sign(forge.pki.privateKeyToPem(key), 'base64');
        return sign;
    } catch (e) {
        return { errorText: "Unable to create Digital Signature" };
    }
};

/**
* @description Verification check that the digital signature is correct.  Only used for debug
* @param {string} message Message to be checked
* @param {cert} cert Certificate used to sign
* @param {string} sign Signature used to sign
* @returns {boolean} True = pass, False = fail
*/
cryptoHelpers.verifyString = function(message, cert, sign) {
    let verify = crypto.createVerify('sha256');
    verify.update(message);
    let ver = verify.verify(forge.pki.certificateToPem(cert), sign, 'base64');
    return ver;
};

/**
* @description Generates the console nonce used validate the console.  AMT only accepts a nonce that is 20 bytes long of random data
* @returns {buffer} Returns console nonce used to verify RCS server to AMT
*/
cryptoHelpers.generateNonce = function() { 
    return Buffer.from(crypto.randomBytes(20), 0, 20); 
};

/**
 * @description Creates a hash of the data using the specified algorithm and returns in the specified output format
 * @param algorithm Algorithm used to create the hash
 * @param data Data to be hashed
 * @param format Format used to output the hashed data
 * @returns Hashed data in the provided format
 */
cryptoHelpers.createHash = function(algorithm, data, format){
    let hashedString = crypto.createHash(algorithm).update(data).digest(format);
    return hashedString;
}

module.exports = cryptoHelpers;