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

/** 
* @description Intel(r) AMT Remote Configuration Service
* @author Matt Primrose
* @version v0.1.0
* @dependencies node-forge, ws
*/

'use strict'
process.title = 'RCS-WebSocketServer';
const forge = require('node-forge');
const fs = require('fs');
const crypto = require('crypto');
const ws = require('./wsserver');
var wsServer, rcsConfig;
const RCSMessageProtocolVersion = 1; // RCS Message Protocol Version.
const RCSConfigFile = './rcs-config.json';
var connection = {};

/**
 * @description Main function to start the RCS service
 */
function rcs() { startWebSocketServer(); }

/**
* @description Start the WebSocket Server
*/
function startWebSocketServer() {
    console.log((new Date()) + ' Starting RCS Server...');
    fs.readFile(RCSConfigFile, 'utf8', function (err, file) {
        rcsConfig = JSON.parse(file.trim());
        wsServer = ws(rcsConfig.WSConfiguration.WebSocketPort, rcsConfig.WSConfiguration.WebSocketTLS, rcsConfig.WSConfiguration.WebSocketCertificate, rcsConfig.WSConfiguration.WebSocketCertificateKey, wsConnectionHandler);
        console.log((new Date()) + ' RCS Server running on port: ' + rcsConfig.WSConfiguration.WebSocketPort);
    });   
}

/**
 * @description Callback from WebSocket Server to handle incomming messages
 * @param {string} event The event type coming from websocket
 * @param {string|buffer|object} message The message coming in over the websocket
 * @param {number} index The connection index of the connected device
 */
function wsConnectionHandler(event, message, index) {
    if (connection[index] == undefined) { connection[index] = {}; }
    // Parse the incoming JSON message and figure out what type data message is coming in (string, buffer, or object)
    if (typeof message == 'string') {
        try { message = JSON.parse(message); }
        catch (e) { message = message; }
        if (message.event) { event = message.event; }
        if (message.data) {
            try { message.data = JSON.parse(message.data); }
            catch (e) { message.data = message.data; }
        }
        if (message.data.type && message.data.type == 'Buffer') { message.data = Buffer.from(message.data); }
    }
    switch (event) {
        // Handles 'cmd' messages
        case 'cmd':
            if (message.data.profile) {
                connection[index]["profile"] = message.data.profile;
            }
            if (message.data.dnsSuffix) {
                connection[index]["dnsSuffix"] = message.data.dnsSuffix;
            }
            if (message.data.digestRealm) {
                connection[index]["digestRealm"] = message.data.digestRealm;
            }
            if (message.data.fwNonce) {
                connection[index]["fwNonce"] = Buffer.from(message.data.fwNonce, 'base64');
            }
            if (message.data.certHashes) {
                connection[index]["certHashes"] = message.data.certHashes;
            }
            if (message.data == 'acm' || message.data.cmd == 'acm') {
                var rcsObj = remoteConfiguration(connection[index].fwNonce, index);
                if (rcsObj.error) { console.log((new Date()) + ' ' + rcsObj.error); sendMessage(index, "error", "error", rcsObj.error); }
                sendMessage(index, "ok", "message", rcsObj);
            }
            break;
        // Handles 'error' type messages
        case 'error':
            console.log('AMT Device ' + index + ' received "error" message: ' + message.data);
            break;
        // Handles 'close' type messages when the socket closes
        case 'close':
            console.log((new Date()) + ' ' + message.data);
            delete connection[index];
            break;
        // Handles 'finish' type messages to indicate when the configuration process has completed (success or failure)
        case 'finish':
            console.log((new Date()) + ' AMT Configuration of device ' + index + ' ' + message.data);
            break;
        // Catches anything that falls through the cracks.  Shouldn't ever see this message
        default:
            console.log('Detected a new websocket message type (need to handle this): ' + event);
            break;
    }
}

/**
 * @description Main function for handling the remote configuration tasks.  Needs the fwNonce from AMT to start and returns the configuration object to be passed down to AMT
 * @param {buffer} fwNonce AMT firmware nonce as a buffer
 * @param {number} cindex Connection index of the device sending the message
 * @returns {object} returns the configuration object to be passed down to AMT
 */
function remoteConfiguration(fwNonce, cindex) {
    var rcsObj = {};
    // Verify we have a valid connection index and error out if we do not
    if (!connection[cindex]) { rcsObj = { error: "WebSocket connection not found in list of connected clients." }; return rcsObj; }
    // Gets all of the certificate information needed by AMT
    var dnsSuffix = null;
    // Check the connection array if the dnsSuffix is set for this connection.
    if (connection[cindex].dnsSuffix) { dnsSuffix = connection[cindex].dnsSuffix; }
    rcsObj.provCertObj = getProvisioningCertObj(dnsSuffix, cindex);
    // Check if we got an error while getting the provisioning cert object
    if (rcsObj.provCertObj.error) { return rcsObj.provCertObj; }
    var privateKey = rcsObj.provCertObj.privateKey;
    // Removes the private key information from the certificate object - don't send private key to the client!!
    delete rcsObj.provCertObj.privateKey;
    // Create a one time nonce that allows AMT to verify the digital signature of the management console performing the provisioning
    rcsObj.mcNonce = generateMcnonce();
    // Need to create a new array so we can concatinate both nonces (fwNonce first, McNonce second)
    var arr = [fwNonce, rcsObj.mcNonce];
    // mcNonce needs to be in base64 format to send over WebSocket connection
    rcsObj.mcNonce = rcsObj.mcNonce.toString('base64');
    // Then we need to sign the concatinated nonce with the private key of the provisioning certificate and encode as base64.
    rcsObj.digitalSignature = signString(Buffer.concat(arr), privateKey);
    if (rcsObj.digitalSignature.error) { return rcsObj.digitalSignature; }
    // Grab the AMT password from the specified profile in rcsConfig file and add that to the rcsObj so we can set the new MEBx password
    var amtPassword
    if (!connection[cindex].profile || connection[cindex].profile == "" || connection[cindex].profile == null) { amtPassword = rcsConfig.AMTConfigurations[0].AMTPassword; }  // If profile is not specified, set the profile to the first profile in rcs-config.json
    else {
        var match = false;
        for (var x = 0; x < rcsConfig.AMTConfigurations.length; x++) {
            if (rcsConfig.AMTConfigurations[x].ProfileName == connection[cindex].profile) {
                // Got a match, set AMT Profile Password in rcsObj
                amtPassword = rcsConfig.AMTConfigurations[x].AMTPassword;
                match = true;
                break;
            } 
        }
        if (!match) {
            // An AMT profile was specified but it doesn't match any of the profile names in rcs-config.json.  Send warning to console and default to first AMT profile listed.
            console.log((new Date()) + ' Specified AMT profile name does not match list of available AMT profiles.');
            return { error: "Specified AMT profile name does not match list of available AMT profiles." };
        }
    }
    var data = 'admin:' + connection[cindex].digestRealm  + ':' + amtPassword;
    rcsObj.passwordHash = crypto.createHash('md5').update(data).digest('hex');
    if (rcsConfig.AMTConfigurations[cindex].ConfigurationScript !== null && rcsConfig.AMTConfigurations[cindex].ConfigurationScript !== "") {
        try { rcsObj.profileScript = fs.readFileSync(rcsConfig.AMTConfigurations[cindex].ConfigurationScript, 'utf8'); }
        catch (e) { rcsObj.profileScript = null; }
    }
    return rcsObj;
}

/**
 * @description Disect the provisioning certificate
 * @param {string} domain DNS Suffix of AMT device
 * @returns {object} Returns the provisioning certificate object
 */
function getProvisioningCertObj(domain, index) {
    var cert, certpass;
    if (domain == null || domain == '') {
        // If no domain is specified, return error.
        return { error: "AMT domain suffix not specified." };
    } else {
        var match = false;
        for (var x = 0; x < rcsConfig.AMTDomains.length; x++) {
            if (rcsConfig.AMTDomains[x].DomainSuffix == domain) {
                // Got a match, set AMT Provisioning certificate and key
                cert = rcsConfig.AMTDomains[x].ProvisioningCert;
                certpass = rcsConfig.AMTDomains[x].ProvisioningCertPassword;
                match = true;
                break;
            } 
        }
        if (!match) {
            // An AMT domain suffix was specified but it doesn't match any of the domain suffix specified in rcs-config.json.
            console.log((new Date()) + ' Specified AMT domain suffix does not match list of available AMT domain suffixes.');
            return { error: "Specified AMT domain suffix does not match list of available AMT domain suffixes." };
        }
    }
    // Verify that the certificate path points to a file that exists
    var certFound = false;
    try {
        if (fs.existsSync(cert)) {
            certFound = true;
        }
    } catch (e) { }
    if (certFound == false) {
        return { error: "AMT Provisioning Certificate not found on server" }; }
    // convert the certificate pfx to an object
    var pfxobj = convertPfxToObject(cert, certpass);
    if (pfxobj.error) { return pfxobj; }
    // return the certificate chain pems and private key
    return dumpPfx(pfxobj, index);
}

/**
 * @description Extracts the provisioning certificate into an object for later manipulation
 * @param {string} pfxpath Path to provisioning certificate
 * @param {string} passphrase Password to open provisioning certificate
 * @returns {object} Object containing cert pems and private key
 */
function convertPfxToObject(pfxpath, passphrase) {
    var pfx_out = { certs: [], keys: [] };
    var pfxbuf = fs.readFileSync(pfxpath);
    var pfxb64 = Buffer.from(pfxbuf).toString('base64');
    var pfxder = forge.util.decode64(pfxb64);
    var asn = forge.asn1.fromDer(pfxder);
    var pfx;
    try {
        pfx = forge.pkcs12.pkcs12FromAsn1(asn, true, passphrase);
    } catch (e) {
        return { error: "Decrypting provisining certificate failed." };
    }
    // Get the certs from certbags
    var bags = pfx.getBags({ bagType: forge.pki.oids.certBag });
    for (var i = 0; i < bags[forge.pki.oids.certBag].length; i++) {
        // dump cert into DER
        var cert = bags[forge.pki.oids.certBag][i];
        pfx_out.certs.push(cert.cert);
    }
    // get shrouded key from key bags
    bags = pfx.getBags({ bagType: forge.pki.oids.pkcs8ShroudedKeyBag });
    for (var i = 0; i < bags[forge.pki.oids.pkcs8ShroudedKeyBag].length; i++) {
        // dump cert into DER
        var cert = bags[forge.pki.oids.pkcs8ShroudedKeyBag][i];
        pfx_out.keys.push(cert.key);
    }
    return pfx_out;
}

/**
    * @description Pulls the provisioning certificate apart and exports each PEM for injecting into AMT
    * @param {object} pfxobj Certificate object from convertPfxToObject function
    * @returns {object} Returns provisioning certificiate object with certificate chain in proper order
    */
function dumpPfx(pfxobj, index) {
    var provisioningCertificateObj = {};
    var certObj = {};
    if (pfxobj) {
        var fingerprint;
        if (pfxobj.certs && Array.isArray(pfxobj.certs)) {
            for (var i = 0; i < pfxobj.certs.length; i++) {
                var cert = pfxobj.certs[i];
                var pem = forge.pki.certificateToPem(cert);
                //Need to trim off the BEGIN and END so we just have the raw pem
                pem = pem.replace('-----BEGIN CERTIFICATE-----', '');
                pem = pem.replace('-----END CERTIFICATE-----', '');
                // pem = pem.replace(/(\r\n|\n|\r)/g, '');
                // Index 0 = Leaf, Index 1 = Root, rest are Intermediate.  Inject in reverse order (Leaf, last Intermediate, previous Intermediate, ..., Root)
                if (i == 0) { certObj['leaf'] = pem; }
                else if (i == 1) {
                    certObj['root'] = pem;
                    var der = forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes();
                    var md = forge.md.sha256.create();
                    md.update(der);
                    fingerprint = md.digest().toHex().toUpperCase();
                }
                else { certObj['inter' + i] = pem; }
            }
        }
        provisioningCertificateObj['certChain'] = [];
        provisioningCertificateObj['certChain'].push(certObj['leaf']);
        if (certObj['inter3'] !== undefined) { provisioningCertificateObj['certChain'].push(certObj['inter3']); }
        provisioningCertificateObj['certChain'].push(certObj['inter2']);
        provisioningCertificateObj['certChain'].push(certObj['root']);
        if (pfxobj.keys && Array.isArray(pfxobj.keys)) {
            for (var i = 0; i < pfxobj.keys.length; i++) {
                var key = pfxobj.keys[i];
                //Just need the key in key format for signing.  Keeping the private key in memory only.
                provisioningCertificateObj['privateKey'] = key;
            }
        }
        // Check that provisioning certificate root matches one of the trusted roots from AMT
        for (var x = 0; x < connection[index].certHashes.length; x++) {
            if (connection[index].certHashes[x].certificateHash == fingerprint) {
                return provisioningCertificateObj;
            } 
        }
        return { error: "Provisioning Certificate doesn't match any trusted certificates from AMT" };
    }
}

/**
    * @description Generates the console nonce used validate the console.  AMT only accepts a nonce that is 20 bytes long of random data
    * @returns {buffer} Returns console nonce used to verify RCS server to AMT
    */
function generateMcnonce() { var mcNonce = Buffer.from(crypto.randomBytes(20), 0, 20); return mcNonce; }

/**
    * @description Verification check that the digital signature is correct.  Only used for debug
    * @param {string} message Message to be checked
    * @param {cert} cert Certificate used to sign
    * @param {string} sign Signature used to sign
    * @returns {boolean} True = pass, False = fail
    */
function verifyString(message, cert, sign) {
    var crypto = require('crypto');
    var verify = crypto.createVerify('sha256');
    verify.update(message);
    var ver = verify.verify(forge.pki.certificateToPem(cert), sign, 'base64');
    return ver;
}

/**
    * @description Signs the concatinated nonce with the private key of the provisioning certificate and encodes as base64
    * @param {string} message Message to be signed
    * @param {string} key Private key of provisioning certificate
    * @returns {string} Returns the signed string
    */
function signString(message, key) {
    try {
        var crypto = require('crypto');
        var signer = crypto.createSign('sha256');
        signer.update(message);
        var sign = signer.sign(forge.pki.privateKeyToPem(key), 'base64');
        return sign;
    } catch (e) {
        return { error: "Unable to create Digital Signature" };
    }
    
}

/**
    * @description Sends messages to WebSocket server using RCS message protocol
    * @description Message Protocol: JSON: { version: int, status: "ok"|"error", event: EVENT_NAME, data: OBJ|Buffer|String }
    * @param {number} index Index of the device connected to the websocket server
    * @param {string} status OK|Error status message type
    * @param {string} event Event type { cmd, message, error, close, finish }
    * @param {string|buffer|object} message Message blob going to device
    */
function sendMessage(index, status, event, message) {
    if (wsServer == null) { console.log((new Date()) + ' WebSocket Server not initialized.'); }
    if (status == null) { status = 'ok'; }
    var obj = { "version": RCSMessageProtocolVersion, "status": status, "event": event, "data": message };
    wsServer.sendMessage(index, obj);
}
rcs();