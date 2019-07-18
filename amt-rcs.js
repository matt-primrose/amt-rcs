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
* @module amt-rcs
*/

/** 
* @description Intel(r) AMT Remote Configuration Service
* @author Matt Primrose
* @version v0.2.0
* @dependencies node-forge, ws
*/

'use strict'
const fs = require('fs');
const crypto = require('crypto');
const websocket = require('./wsserver');
const helpers = require('./cryptoHelpers');
const RCSMessageProtocolVersion = 1; // RCS Message Protocol Version.
/**

 * @constructor
 * @description Creates and returns an instance of the RCS object
 * @param {JSON} config RCS configuration JSON object.
 * @param {Object} ws (Optional) WebSocket connection.
 * @param {Object} logger (Optional) Logging callback.
 * @param {Object} db (Optional) Database callback.
 * @returns {Object} RCS service object
 */
function CreateRcs(config, ws, logger, db) {

    let obj = new Object();    
    obj.rcsConfig = config;
    obj.wsServer = ws;
    obj.logger = logger;
    obj.db = db;
    obj.connection = {};
    obj.output = function (msg) { console.log((new Date()) + ' ' + msg); if (obj.logger !== undefined) { obj.logger(msg); } }
    obj.rcsConfig.AMTConfigurations = helpers.validateAMTPasswords(obj.rcsConfig.AMTConfigurations, function(message){
        obj.output(message);
    });
    

    /**
     * @description Main function to start the RCS service
     */
    obj.start = function() { obj.startWebSocketServer(); }

    /**
    * @description Start the WebSocket Server
    */
    obj.startWebSocketServer = function () {
        obj.output('Starting RCS Server...');
        if (obj.wsServer === undefined) { // Start the basic websocket server included in amt-rcs
            try{
                obj.wsServer = websocket(obj.rcsConfig.WSConfiguration.WebSocketPort, obj.rcsConfig.WSConfiguration.WebSocketTLS, obj.rcsConfig.WSConfiguration.WebSocketCertificate, obj.rcsConfig.WSConfiguration.WebSocketCertificateKey, obj.wsConnectionHandler);
                obj.output('RCS Server running on port: ' + obj.rcsConfig.WSConfiguration.WebSocketPort);
            } catch (e){
                obj.output('Failed to start Web Socket Server. ' + e) ;
                process.exit(1);
            }
        } else {
            // Handle any custom websocket initialization here
        }
    }

    /**
     * @description Callback from WebSocket Server to handle incomming messages
     * @param {string} event The event type coming from websocket
     * @param {string|buffer|object} message The message coming in over the websocket
     * @param {number} tunnel The connection reference of the connected device
     */
    obj.wsConnectionHandler = function(event, message, tunnel) {
        // Parse the incoming JSON message and figure out what type data message is coming in (string, buffer, or object)
        if (typeof message == 'string') {
            try { message = JSON.parse(message); } catch (e) { let msg = { "errorText": "Invalid message from client" }; obj.output(msg.errorText); obj.sendMessage(tunnel, msg);}
            if (message.action) { event = message.action; }
        }
        let client = {};
        let rcsObj = {};
        if ((event !== 'close') && (event !== 'error') && (event !== 'message')){
            if (message.client) { client.client = message.client; }
            if (message.action) { client.action = message.action; }
            if (message.profile) { client.profile = message.profile; }
            if (message.fqdn) { client.dnsSuffix = message.fqdn; }
            if (message.realm) { client.digestRealm = message.realm; }
            if (message.nonce) { client.fwNonce = Buffer.from(message.nonce, 'base64'); }
            if (message.hashes) { client.certHashes = message.hashes; }
            if (message.uuid) { client.amtGuid = message.uuid; }
            if (message.ver) { client.amtVer = message.ver; }
            if (message.modes) { client.provisionModes = message.modes; }
            if (message.currentMode) { client.currentMode = message.currentMode; }
            if (message.tag) { client.tag = message.tag; }
            if (tunnel) { client.tunnel = tunnel; }
            if (obj.connection[client.uuid] === undefined) { obj.connection[client.uuid] = client; }
            if (obj.db) { obj.db(client); }
        }
        switch (event) {
            // Handles 'acmactivate' messages
            case 'acmactivate':
                rcsObj = obj.remoteConfiguration(client.fwNonce, client.uuid, event);
                if (rcsObj.errorText) { 
                    obj.output(rcsObj.errorText); 
                    obj.sendMessage(tunnel, rcsObj)
                }
                let acm = {'version': RCSMessageProtocolVersion, 'status': 'ok', 'certs': rcsObj.certs, 'action': rcsObj.action, 'nonce': rcsObj.nonce, 'signature': rcsObj.signature, 'profileScript': rcsObj.profileScript, 'password': rcsObj.passwordHash};
                if (obj.db) { obj.db(rcsObj); }
                if (obj.logger) { obj.logger(rcsObj); }
                obj.sendMessage(tunnel, acm);
                break;
            // Handles 'ccmactivate' messages
            case 'ccmactivate':
                rcsObj = obj.remoteConfiguration((client.fwNonce ? client.fwNonce : null), client.uuid, event);
                if (rcsObj.errorText) { 
                    obj.output(rcsObj.errorText); 
                    obj.sendMessage(tunnel, rcsObj);
                }
                let ccm = {'version': RCSMessageProtocolVersion, 'status': 'ok', 'certs': rcsObj.certs, 'action': rcsObj.action, 'nonce': rcsObj.nonce, 'signature': rcsObj.signature, 'profileScript': rcsObj.profileScript, 'password': rcsObj.passwordHash}
                if (obj.db) { obj.db(rcsObj); }
                if (obj.logger) { obj.logger(rcsObj); }
                obj.sendMessage(tunnel, ccm);
                break;
            // Handles 'error' type messages
            case 'error':                
                obj.output('AMT Device received "error" message: ' + message.data);
                break;
            // Handles 'close' type messages when the socket closes
            case 'close':
                obj.output(message.data);
                delete obj.connection[message.uuid];
                break;
            // Handles 'acmactivate-success' and 'ccmactivate-success' messages to indicate when the configuration process has completed
            case 'acmactivate-success':
            case 'ccmactivate-success':
                obj.output('AMT Configuration of device ' + message.uuid + ' success');
                break;
            // Generally this is a malformed message from the client.
            case 'message':
                break;
            // Catches anything that falls through the cracks.  Shouldn't ever see this message
            default:
                obj.output('Detected a new websocket message type (need to handle this): ' + event);
                break;
        }
    }

    /**
     * @description Main function for handling the remote configuration tasks.  Needs the fwNonce from AMT to start and returns the configuration object to be passed down to AMT
     * @param {buffer} fwNonce AMT firmware nonce as a buffer
     * @param {number} uuid Connection uuid of the device sending the message
     * @returns {object} returns the configuration object to be passed down to AMT
     */
    obj.remoteConfiguration = function(fwNonce, uuid, event) {
        let rcsObj = {};
        // Verify we have a valid connection reference and error out if we do not
        if (!obj.connection[uuid]) { rcsObj = { errorText: "AMT Device " + uuid + " not found in list of connected clients." }; return rcsObj; }
        rcsObj.action = event;
        for (let x in obj.rcsConfig.AMTConfigurations){
            if (obj.rcsConfig.AMTConfigurations[x].ProfileName === obj.connection[uuid].profile){
                rcsObj.action = obj.rcsConfig.AMTConfigurations[x].Activation;
            }
        }
        if (rcsObj.action == 'acmactivate') {
            // Verify we have the required information to configure AMT in ACM mode
            if (fwNonce == null) { rcsObj = { errorText: "Not enough information to configure AMT: Missing Nonce."}; return rcsObj; }
            // Gets all of the certificate information needed by AMT
            let dnsSuffix = null;
            // Check the connection array if the dnsSuffix is set for this connection.
            if (obj.connection[uuid].dnsSuffix) { dnsSuffix = obj.connection[uuid].dnsSuffix; }
            else { return { errorText: "AMT domain suffix not specified."}; }
            let match = false;
            let cert, certpass;
            for (let x = 0; x < obj.rcsConfig.AMTDomains.length; x++) {
                if (obj.rcsConfig.AMTDomains[x].DomainSuffix == dnsSuffix) {
                    // Got a match, set AMT Provisioning certificate and key
                    cert = obj.rcsConfig.AMTDomains[x].ProvisioningCert;
                    certpass = obj.rcsConfig.AMTDomains[x].ProvisioningCertPassword;
                    match = true;
                    break;
                }
            }
            if (!match) {
                // An AMT domain suffix was specified but it doesn't match any of the domain suffix specified in rcs-config.json.
                return { errorText: "Specified AMT domain suffix does not match list of available AMT domain suffixes." };
            }
            let pfxobj = helpers.getProvisioningCertObj(cert, certpass);
            
            // Check if we got an error while getting the provisioning cert object
            if (pfxobj.errorText) { return pfxobj; }
            let certObj = helpers.dumpPfx(pfxobj);

            // Check that provisioning certificate root matches one of the trusted roots from AMT
            let hashMatch = false;
            for (let x = 0; x < obj.connection[uuid].certHashes.length; x++) { 
                if (obj.connection[uuid].certHashes[x].toUpperCase() == certObj.rootFingerprint.toUpperCase()) { hashMatch = true; } }
            if (hashMatch == false){ return { errorText: "Provisioning Certificate doesn't match any trusted certificates from AMT" }; }
            
            // Don't send private key to the client!!
            let privateKey = certObj.privateKey;
            rcsObj.certs = certObj.certChain;
            // Create a one time nonce that allows AMT to verify the digital signature of the management console performing the provisioning
            let nonce = helpers.generateNonce();
            rcsObj.nonce = nonce.toString('base64');
            // Need to create a new array so we can concatinate both nonces (fwNonce first, Nonce second)
            let arr = [fwNonce, nonce];
            // mcNonce needs to be in base64 format to send over WebSocket connection
            // Then we need to sign the concatinated nonce with the private key of the provisioning certificate and encode as base64.
            rcsObj.signature = helpers.signString(Buffer.concat(arr), privateKey);
            if (rcsObj.signature.errorText) { return rcsObj.signature; }
            // Grab the AMT password from the specified profile in rcsConfig file and add that to the rcsObj so we can set the new MEBx password
            rcsObj.profileScript = null;
            for (let x = 0; x < obj.rcsConfig.AMTConfigurations.length; x++){
                if (obj.rcsConfig.AMTConfigurations[x].ProfileName === obj.connection[uuid].profile) {
                    if (obj.rcsConfig.AMTConfigurations[x].ConfigurationScript !== null && obj.rcsConfig.AMTConfigurations[x].ConfigurationScript !== ""){
                        try { rcsObj.profileScript = fs.readFileSync(obj.rcsConfig.AMTConfigurations[x].ConfigurationScript, 'utf8'); }
                        catch (e) { rcsObj.profileScript = null; }
                    }
                }
            }
        }
        let amtPassword;
        let match = false;
        for (let x = 0; x < obj.rcsConfig.AMTConfigurations.length; x++) {
            if (obj.rcsConfig.AMTConfigurations[x].ProfileName == obj.connection[uuid].profile) {
                // Got a match, set AMT Profile Password in rcsObj
                if(obj.rcsConfig.AMTConfigurations[x].GenerateRandomPassword === true){
                    amtPassword = helpers.generateRandomPassword(obj.rcsConfig.AMTConfigurations[x].RandomPasswordCharacters, obj.rcsConfig.AMTConfigurations[x].RandomPasswordLength);
                    obj.output("Create random password for device " + obj.connection[uuid].amtGuid + ".");
                    if (obj.db == null && obj.logger == null){
                        // DB or Logger link not mapped and randomized password will be lost after device disconnects.  Output password to console window as a last ditch attempt to save password
                        obj.output('Random password not saved anywhere!! Device with AMT GUID: ' + obj.connection[uuid].amtGuid + ' has password: ' + amtPassword);
                    }
                } else {
                    amtPassword = obj.rcsConfig.AMTConfigurations[x].AMTPassword;
                }
                match = true;
                break;
            }
        }
        if (!match) {
            // An AMT profile was specified but it doesn't match any of the profile names in rcs-config.json.  Send warning to console and default to first AMT profile listed.
            return { errorText: "Specified AMT profile name does not match list of available AMT profiles." };
        }
        let data = 'admin:' + obj.connection[uuid].digestRealm + ':' + amtPassword;
        rcsObj.passwordHash = crypto.createHash('md5').update(data).digest('hex');
        rcsObj.password = amtPassword;
        return rcsObj;
    }
    
    /**
    * @description Sends messages to WebSocket server using RCS message protocol
    * @description Message Protocol: JSON: { version: int, status: "ok"|"error", event: EVENT_NAME, data: OBJ|Buffer|String }
    * @param {number} tunnel connection reference to the device connected to the websocket server
    * @param {string} status OK|Error status message type
    * @param {string} event Event type { cmd, message, error, close, finish }
    * @param {string|buffer|object} message Message blob going to device
    */
    obj.sendMessage = function(tunnel, message) {
        if (obj.wsServer == null) { obj.output('WebSocket Server not initialized.'); } 
        else {
            if (message.status == null) { message.status = 'ok'; }
            message.version = RCSMessageProtocolVersion;
            obj.wsServer.sendMessage(tunnel, message);
        }
    }
    return obj;
}
module.exports = CreateRcs;