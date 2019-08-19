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
const wsServer = require('../wsserver');
const config = {'port':8080, 'tls':false, 'wsscert':null, 'wsscertkey':null};
test("Constructor returns a valid object", ()=>{
    let callback = function(){};
    let server = wsServer(config.port, config.tls, config.wsscert, config.wsscertkey, callback);
    expect(server.port).toBe(8080);
    expect(server.tls).toBe(false);
    expect(server.wsServer).toBeDefined();
    expect(server.sendMessage).toBeDefined();
    expect(server.eventHandler).toBeDefined();
});