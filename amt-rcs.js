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
const RCSMessageProtocolVersion = 1; // RCS Message Protocol Version
const RCSConfigFile = './rcs-config.json';
var connection = {};

function rcs() {
    startWebSocketServer();
}

// Start the WebSocket Server
function startWebSocketServer() {
    console.log('Starting RCS Server...');
    fs.readFile(RCSConfigFile, 'utf8', function (err, file) {
        rcsConfig = JSON.parse(file.trim());
        wsServer = ws(rcsConfig.WSConfiguration.WebSocketPort, rcsConfig.WSConfiguration.WebSocketTLS, rcsConfig.WSConfiguration.WebSocketCertificate, rcsConfig.WSConfiguration.WebSocketCertificateKey, wsConnectionHandler);
        console.log('RCS Server running on port: ' + rcsConfig.WSConfiguration.WebSocketPort);
    });   
}

// Callback from WebSocket Server to handle incomming messages
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
            if (message.data.dnssuffix) {
                connection[index]["dnssuffix"] = message.data.dnssuffix;
            }
            if (message.data == 'acm' || message.data.cmd == 'acm') { sendMessage(index, "ok", "cmd", "acmready"); }
            break;
        // Handles 'message' type messages - these are typically buffer or object messages
        case 'message':
            if (Buffer.isBuffer(message.data)) {
                var rcsObj = remoteConfiguration(message.data, index);
                sendMessage(index, "ok", "message", rcsObj);
            } else {
                if (message.data.Header && message.data.Header.HttpError) { console.log((new Date()) + ' Http Error from client: ' + message.data.Header.HttpError); }
                else if (message.data.ReturnValueStr) { console.log((new Date()) + ' Configuration Result from client: ' + message.data.ReturnValueStr); }
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

// Main function for handling the remote configuration tasks.  Needs the fwNonce from AMT to start and returns the configuration object to be passed down to AMT
function remoteConfiguration(fwNonce, cindex) {
    var rcsObj = {};
    var privateKey;
    // Gets all of the certificate information needed by AMT
    var dnsSuffix = null;
    // Check the connection array if the dnssuffix is set for this connection.  If not leave null and hope the default AMT provisioning certificate matches the AMT DNS Suffix.
    if (connection[cindex] && connection[cindex].dnssuffix) { dnsSuffix = connection[cindex].dnssuffix; }
    rcsObj.provCertObj = getProvisioningCertObj(dnsSuffix);
    privateKey = rcsObj.provCertObj.privateKey;
    // Removes the private key information from the certificate object - don't send private key to the client!!
    delete rcsObj.provCertObj.privateKey;
    // Create a one time nonce that allows AMT to verify the digital signature
    rcsObj.mcNonce = generateMcnonce();
    // Need to create a new array so we can concatinate both nonces (FWNonce first, McNonce second)
    var arr = [fwNonce, rcsObj.mcNonce];
    // mcNonce needs to be in base64 format to successfully send over WebSocket connection
    rcsObj.mcNonce = rcsObj.mcNonce.toString('base64');
    // Then we need to sign the concatinated nonce with the private key of the provisioning certificate and encode as base64.
    rcsObj.digitalSignature = signString(Buffer.concat(arr), privateKey);
    // Grab the AMT password from the specified profile in rcsConfig file and add that to the rcsObj so we can set the new MEBx password
    if (!connection[cindex] || !connection[cindex].profile || connection[cindex].profile == "" || connection[cindex].profile == null) { rcsObj.amtPassword == rcsConfig.AMTConfigurations[0].AMTPassword; }  // If profile is not specified, set the profile to the first profile in rcs-config.json
    else {
        var match = false;
        for (var x = 0; x < rcsConfig.AMTConfigurations.length; x++) {
            if (rcsConfig.AMTConfigurations[x].ProfileName == connection[cindex].profile) { rcsObj.amtPassword = rcsConfig.AMTConfigurations[x].AMTPassword; match = true; break;} // Got a match, set AMT Profile Password in rcsObj
        }
        if (!match) {
            // An AMT profile was specified but it doesn't match any of the profile names in rcs-config.json.  Send warning to console and default to first AMT profile listed.
            console.log((new Date()) + ' Specified AMT profile name does not match list of available AMT profiles.  Setting AMT password to default AMT profile.');
            rcsObj.amtPassword = rcsConfig.AMTConfigurations[0].AMTPassword
        }
    }
    return rcsObj;
}

// Disect the provisioning certificate.
function getProvisioningCertObj(domain) {
    var cert, certpass;
    if (domain == null || domain == '') {
        // If no domain is specified, default to the first AMT domain specified in rcs-config.json
        cert = rcsConfig.AMTDomains[0].ProvisioningCert;
        certpass = rcsConfig.AMTDomains[0].ProvisioningCertPassword;
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
            // An AMT domain suffix was specified but it doesn't match any of the domain suffix specified in rcs-config.json.  Send warning to console and default to try to use first AMT domain suffix listed.
            console.log((new Date()) + ' Specified AMT domain suffix does not match list of available AMT domain suffixes.  Setting AMT provisioning certificate to default AMT provisioning certificate.');
            cert = rcsConfig.AMTDomains[0].ProvisioningCert;
            certpass = rcsConfig.AMTDomains[0].ProvisioningCertPassword;
        }
    }
    // convert the certificate pfx to an object
    var pfxobj = convertPfxToObject(cert, certpass);
    // return the certificate chain pems and private key
    return dumpPfx(pfxobj);
}

// Extracts the provisioning certificate into an object for later manipulation
function convertPfxToObject(pfxpath, passphrase) {
    var pfx_out = { certs: [], keys: [] };
    var pfxbuf = fs.readFileSync(pfxpath);
    var pfxb64 = Buffer.from(pfxbuf).toString('base64');
    var pfxder = forge.util.decode64(pfxb64);
    var asn = forge.asn1.fromDer(pfxder);
    var pfx = forge.pkcs12.pkcs12FromAsn1(asn,true,passphrase);    
    // Get the certs from certbags
    var bags = pfx.getBags({bagType: forge.pki.oids.certBag});
    for (var i=0; i<bags[forge.pki.oids.certBag].length; i++) {
        // dump cert into DER
        var cert = bags[forge.pki.oids.certBag][i];
        pfx_out.certs.push(cert.cert);        
    }
    // get shrouded key from key bags
    bags = pfx.getBags({bagType: forge.pki.oids.pkcs8ShroudedKeyBag});
    for (var i=0; i<bags[forge.pki.oids.pkcs8ShroudedKeyBag].length; i++) {
        // dump cert into DER
        var cert = bags[forge.pki.oids.pkcs8ShroudedKeyBag][i];
        pfx_out.keys.push(cert.key);        
    }
    return pfx_out;
}

// Pulls the provisioning certificate apart and exports each PEM for injecting into AMT
function dumpPfx(pfxobj) {
    var provisioningCertificateObj = {};
    var certObj = {};
    if (pfxobj) {
        if (pfxobj.certs && Array.isArray(pfxobj.certs)) {
            for (var i = 0; i < pfxobj.certs.length; i++) {
                var cert = pfxobj.certs[i];
                var pem = forge.pki.certificateToPem(cert);
                //Need to trim off the BEGIN and END so we just have the raw pem
                pem = pem.replace('-----BEGIN CERTIFICATE-----', '');
                pem = pem.replace('-----END CERTIFICATE-----', '');
                // Index 0 = Leaf, Index 1 = Root, rest are Intermediate.  Inject in reverse order (Leave, last Intermediate, previous Intermediate, ..., Root)
                if (i == 0) {
                    certObj['leaf'] = pem;
                } else if (i == 1) {
                    certObj['root'] = pem;
                } else {
                    certObj['inter' + i] = pem;
                }
            }         
        }
        provisioningCertificateObj['certChain'] = [];
        provisioningCertificateObj['certChain'].push(certObj['leaf']);
        if (certObj['inter3'] !== undefined) { provisioningCertificateObj['certChain'].push(certObj['inter3']); }
        provisioningCertificateObj['certChain'].push(certObj['inter2']);
        provisioningCertificateObj['certChain'].push(certObj['root']);
        if (pfxobj.keys && Array.isArray(pfxobj.keys)) {
            for (var i=0; i< pfxobj.keys.length; i++) {
                var key = pfxobj.keys[i];
                //var pem = forge.pki.privateKeyToPem(key);
                //Just need the key in key format for signing.  Keeping the private key in memory only.
                provisioningCertificateObj['privateKey'] = key;
            }
        }
        
        return provisioningCertificateObj;
    }
}

// Generates the console nonce used validate the console.  AMT only accepts a nonce that is 20 bytes long of random data
function generateMcnonce() {
    var mcNonce = Buffer.from(crypto.randomBytes(20), 0, 20);
    //console.log(mcNonce);
    return mcNonce;   
}

// Verification check that the digital signature is correct
function verifyString(message, cert, sign) {
    var crypto = require('crypto');
    var verify = crypto.createVerify('sha256');
    verify.update(message);
    var ver = verify.verify(forge.pki.certificateToPem(cert), sign, 'base64');
    return ver;
}

// Signs the concatinated nonce with the private key of the provisioning certificate and encodes at base64
function signString(message, key) {
    var crypto = require('crypto');
    var signer = crypto.createSign('sha256');
    signer.update(message);
    var sign = signer.sign(forge.pki.privateKeyToPem(key), 'base64');
    return sign;
}

// Sends messages to WebSocket server using RCS message protocol
// Message Protocol: JSON: { version: int, status: "ok"|"error", event: EVENT_NAME, data: OBJ|Buffer|String }
function sendMessage(index, status, event, message) {
    if (wsServer == null) { console.log((new Date()) + ' WebSocket Server not initialized.'); }
    if (status == null) { status = 'ok'; }
    var obj = { "version": RCSMessageProtocolVersion, "status": status, "event": event, "data": message };
    wsServer.sendMessage(index, obj);
}

rcs();