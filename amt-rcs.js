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

function rcs() {
    startWebSocketServer();
}

// Start the WebSocket Server
function startWebSocketServer() {
    console.log('Starting RCS Server...');
    fs.readFile('./rcs-config.json', 'utf8', function (err, file) {
        rcsConfig = JSON.parse(file.trim());
        wsServer = ws(rcsConfig.WSConfiguration.WebSocketPort, rcsConfig.WSConfiguration.WebSocketCertificate, wsConnectionHandler);
        console.log('RCS Server running on port: ' + rcsConfig.WSConfiguration.WebSocketPort);
    });   
}

function wsConnectionHandler(type, message, index) {
    if (typeof message == 'string') {
        try {
            message = JSON.parse(message);
        } catch (e) {
            message = message;
        }
        if (message.Type) {
            type = message.Type;
        } else if (message.type && message.type == 'Buffer') {
            message = Buffer.from(message);
        }
    }
    switch (type) {
        case 'cmd':
            if (message.Body == 'acm') {
                var acm = {};
                acm.Type = 'cmd';
                acm.Body = 'acmready';
                wsServer.sendMessage(index, acm);
            }
            break;
        case 'message':
            if (Buffer.isBuffer(message)) {
                var rcsObj = remoteConfiguration(message);
                wsServer.sendMessage(index, rcsObj);
            } else {
                if (message.Header && message.Header.HttpError) {
                    console.log((new Date()) + ' Http Error from client: ' + message.Header.HttpError);
                } else if (message.ReturnValueStr) {
                    console.log((new Date()) + ' Configuration Result from client: ' + message.ReturnValueStr);
                }
                
            }
            break;
        case 'error':
            console.log('Received "error" Message: ' + message);
            break;
        case 'close':
            console.log((new Date()) + ' ' + message);
            break;
        case 'finish':
            console.log((new Date()) + ' AMT Configuration of device ' + index + ' ' + message.Body);
            break;
        default:
            console.log('Detected a new websocket message type (need to handle this): ' + type);
            break;
    }
}

function remoteConfiguration(fwNonce) {
    var rcsObj = {};
    var privateKey;
    //console.log('Starting Remote Configuration');
    //console.log('Received fwNonce: ' + fwNonce);
    rcsObj.provCertObj = getProvisioningCertObj();
    privateKey = rcsObj.provCertObj.privateKey;
    delete rcsObj.provCertObj.privateKey;
    //console.log('Generated Certificate Object: \n\r' + JSON.stringify(rcsObj.provCertObj));
    rcsObj.mcNonce = generateMcnonce();
    //console.log('Generated McNonce: ' + rcsObj.mcNonce);
    //Need to create a new array so we can concatinate both nonces (FWNonce first, McNonce second)
    var arr = [fwNonce, rcsObj.mcNonce];
    rcsObj.mcNonce = rcsObj.mcNonce.toString('base64');
    //console.log('Added nonces to Array: ' + arr);
    //Then we need to sign the concatinated nonce with the private key of the provisioning certificate and encode as base64.
    rcsObj.digitalSignature = signString(Buffer.concat(arr), privateKey);
    //console.log('Generated digital signature: ' + rcsObj.digitalSignature);
    //console.log('rcsObj: \n\r' + JSON.stringify(rcsObj));
    rcsObj.amtPassword = rcsConfig.AMTConfiguration.AMTPassword;
    //console.log(rcsObj);
    return rcsObj;
}

// Disect the provisioning certificate.  At some point may need to support domain suffix matching with multiple provisioning certs
function getProvisioningCertObj(cert, certpass) {
    if ((cert == null) || (certpass == null)) {
        cert = rcsConfig.AMTConfiguration.ProvisioningCert[0];
        certpass = rcsConfig.AMTConfiguration.ProvisioningCertPassword[0];
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

rcs();