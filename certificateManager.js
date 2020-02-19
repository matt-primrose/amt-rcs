/*
Copyright 2019-2020 Intel Corporation

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

const fs = require('fs');
const forge = require('node-forge');

let certificateManager = new Object();
/**
 * @description Disect the provisioning certificate
 * @param {string} cert certificate location
 * @param {string} certpass certificate password
 * @returns {object} Returns pfx object
 */
certificateManager.getProvisioningCertObj = function(cert, certpass) {
    // Verify that the certificate path points to a file that exists
    let certFound = false;
    try {
        if (fs.existsSync(cert)) {
            certFound = true;
        }
    } catch (e) { }
    if (certFound == false) {
        return { errorText: "AMT Provisioning Certificate not found on server" };
    }
    // convert the certificate pfx to an object
    let pfxobj = certificateManager.convertPfxToObject(cert, certpass);
    // return the certificate chain pems and private key
    return pfxobj;
};

/**
* @description Pulls the provisioning certificate apart and exports each PEM for injecting into AMT.  Only supports certificate chains up to 4 certificates long
* @param {object} pfxobj Certificate object from convertPfxToObject function
* @returns {object} Returns provisioning certificiate object with certificate chain in proper order
*/
certificateManager.dumpPfx = function(pfxobj) {
    let provisioningCertificateObj = new Object();
    let interObj = new Array();
    let leaf = new Object();
    let root = new Object();
    if (pfxobj) {
        if (pfxobj.certs && Array.isArray(pfxobj.certs)) {
            for (let i = 0; i < pfxobj.certs.length; i++) {
                let cert = pfxobj.certs[i];
                let pem = forge.pki.certificateToPem(cert);
                //Need to trim off the BEGIN and END so we just have the raw pem
                pem = pem.replace('-----BEGIN CERTIFICATE-----', '');
                pem = pem.replace('-----END CERTIFICATE-----', '');
                // pem = pem.replace(/(\r\n|\n|\r)/g, '');
                // Index 0 = Leaf, Root subject.hash will match issuer.hash, rest are Intermediate.
                if (i == 0) {
                    leaf.pem = pem;
                    leaf.subject = cert.subject.hash;
                    leaf.issuer = cert.issuer.hash;
                }
                else if (cert.subject.hash == cert.issuer.hash) {
                    root.pem = pem;
                    root.subject = cert.subject.hash;
                    root.issuer = cert.issuer.hash;
                    let der = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
                    let md = forge.md.sha256.create();
                    md.update(der);
                    root.fingerprint = md.digest().toHex();
                }
                else {
                    let inter = new Object();
                    inter.pem = pem;
                    inter.subject = cert.subject.hash;
                    inter.issuer = cert.issuer.hash;
                    interObj.push(inter);
                }
            }
        }
        // Need to put the certificate PEMs in the correct order before sending to AMT.  
        // This currently only supports certificate chains that are no more than 4 certificates long
        provisioningCertificateObj.certChain = new Array();
        // Leaf PEM is first
        provisioningCertificateObj.certChain.push(leaf.pem);
        // Need to figure out which Intermediate PEM is next to the Leaf PEM
        for (let k = 0; k < interObj.length; k++) {
            if (!certificateManager.sortCertificate(interObj[k], root)) {
                provisioningCertificateObj.certChain.push(interObj[k].pem);
            }
        }
        // Need to figure out which Intermediate PEM is next to the Root PEM
        for (let l = 0; l < interObj.length; l++) {
            if (certificateManager.sortCertificate(interObj[l], root)) {
                provisioningCertificateObj.certChain.push(interObj[l].pem);
            }
        }
        // Root PEM goes in last
        provisioningCertificateObj.certChain.push(root.pem);
        provisioningCertificateObj.rootFingerprint = new Object(root.fingerprint);
        if (pfxobj.keys && Array.isArray(pfxobj.keys)) {
            for (let i = 0; i < pfxobj.keys.length; i++) {
                let key = pfxobj.keys[i];
                //Just need the key in key format for signing.  Keeping the private key in memory only.
                provisioningCertificateObj.privateKey = key;
            }
        }
    }
    return provisioningCertificateObj;
};

/**
 * @description Extracts the provisioning certificate into an object for later manipulation
 * @param {string} pfxpath Path to provisioning certificate
 * @param {string} passphrase Password to open provisioning certificate
 * @returns {object} Object containing cert pems and private key
 */
certificateManager.convertPfxToObject = function(pfxpath, passphrase) {
    let pfx_out = { certs: [], keys: [] };
    let pfxbuf = fs.readFileSync(pfxpath);
    let pfxb64 = Buffer.from(pfxbuf).toString('base64');
    let pfxder = forge.util.decode64(pfxb64);
    let asn = forge.asn1.fromDer(pfxder);
    let pfx;
    try {
        pfx = forge.pkcs12.pkcs12FromAsn1(asn, true, passphrase);
    } catch (e) {
        return { errorText: "Decrypting provisining certificate failed." };
    }
    // Get the certs from certbags
    let bags = pfx.getBags({ bagType: forge.pki.oids.certBag });
    for (let i = 0; i < bags[forge.pki.oids.certBag].length; i++) {
        // dump cert into DER
        let cert = bags[forge.pki.oids.certBag][i];
        pfx_out.certs.push(cert.cert);
    }
    // get shrouded key from key bags
    bags = pfx.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
    for (let i = 0; i < bags[forge.pki.oids.pkcs8ShroudedKeyBag].length; i++) {
        // dump cert into DER
        let cert = bags[forge.pki.oids.pkcs8ShroudedKeyBag][i];
        pfx_out.keys.push(cert.key);
    }
    return pfx_out;
};

/**
 * @description Sorts the intermediate certificates to properly order the certificate chain
 * @param {Object} intermediate
 * @param {Object} root
 * @returns {Boolean} Returns true if issuer is from root.  Returns false if issuer is not from root.
 */
certificateManager.sortCertificate = function(intermediate, root) {
    if (intermediate.issuer == root.subject) {
        return true;
    } else {
        return false;
    }
};
module.exports = certificateManager;