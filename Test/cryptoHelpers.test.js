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
const cryptoHelpers = require('../cryptoHelpers');
const certMgr = require('../certificateManager');
test('Returns error message if signing fails', ()=>{
    let message = 'test message';
    let key = '';
    expect(cryptoHelpers.signString(message, key)).toHaveProperty('errorText', "Unable to create Digital Signature");
});
test('Verifies signed string is valid', ()=>{
    let message = 'test message';
    let cert = 'vprodemo.pfx';
    let certPass = 'P@ssw0rd';
    let pfxobj = certMgr.getProvisioningCertObj(cert, certPass);
    let key = certMgr.dumpPfx(pfxobj).privateKey;
    expect(cryptoHelpers.signString(message, key)).toBe("jiszvYn4/Wz+L61m1XgIQfIJoM1yMU7yv3MBiBpAAa4YNCr2BaQtJ1fge4rxmOVaFijJFxE3JHfzAPff+bwcG8a2YYZnjKPM1vYyZ2rKAXeItZy9C2OHAxZBr3BvPBE8FqO8AZaIT5RL7v/4Jlvjak6mNOvDKBRO+HrEZiPLH2VbsteZhVXZLEK899u2j2HfncbbGQnkmRBBc6QAYoBfhl83I/qqKxQ1k2l7JZ3aatJuLXSR+nP/cJqnbtWIdGVtVyl3AKbrrMkMLgtF69QH2oE8zGUgJdgbcOrpzMgrUnpqygxpG6HrTP1CewdcoXJ0KI1/Y2sIkZO22CyoGIYFfQ==");
});
test('Verify nonce has length of 20', ()=>{
    let nonce = cryptoHelpers.generateNonce();
    expect(nonce).toHaveLength(20);
});
test('Verify nonce is a buffer object', ()=>{
    let nonce = cryptoHelpers.generateNonce();
    expect(Buffer.isBuffer(nonce)).toBe(true);
});