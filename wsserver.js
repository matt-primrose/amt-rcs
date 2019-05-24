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

/*
* @fileoverview Simple WebSocket Server
* @author Matt Primrose
* @version v0.1.0
*/

"use strict";
const WebSocket = require('ws');
function WebSocketServer(port, wsscert, connectionHandler) {   
    var obj = new Object();
    obj.port = port;
    obj.wsscert = wsscert;
    obj.crypt
    obj.clients = [];
    obj.wsServer = new WebSocket.Server({ port: obj.port });
    obj.wsServer.on('connection', (connection) => {
        // we need to know client index to remove them on 'close' event
        var index = obj.clients.push(connection) - 1;
        console.log((new Date()) + ' Connection accepted.');
        // message received
        connection.on('message', function (message) {
            obj.eventHandler('message', message, index);
        });
        // error received
        connection.on('error', function (event) { obj.eventHandler('error', event); });
        // client disconnected
        connection.on('close', function (connection) {
            obj.eventHandler('close', 'AMT Device ' + index + ' disconnected.');
            // remove client from the list of connected clients
            obj.clients.splice(index, 1);
        });
    });
    obj.sendMessage = function (index, message) { obj.clients[index].send(JSON.stringify(message)); };
    obj.eventHandler = function (type, message, index) { connectionHandler(type, message, index); };
    return obj;
}
module.exports = WebSocketServer;