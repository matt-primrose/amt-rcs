const cryptoHelpers = require('../cryptoHelpers');
test('Returns error message if cert path does not resolve to a file', ()=> {
    let cert = '';
    let certPass = 'password';
    expect(cryptoHelpers.getProvisioningCertObj(cert, certPass)).toHaveProperty('errorText', "AMT Provisioning Certificate not found on server");
});
test('Returns error message if cert password can not access certificate', ()=>{
    let cert = 'vprodemo.pfx';
    let certPass = 'password';
    expect(cryptoHelpers.convertPfxToObject(cert, certPass)).toHaveProperty('errorText', "Decrypting provisining certificate failed.");
});
test('Returns valid certificate object if certificate can be read', ()=>{
    let cert = 'vprodemo.pfx';
    let certPass = 'P@ssw0rd';
    expect(cryptoHelpers.convertPfxToObject(cert, certPass)).toHaveProperty('certs');
    expect(cryptoHelpers.convertPfxToObject(cert, certPass)).toHaveProperty('keys');
});
test('Returns valid certChain in provisioning certificate object', ()=>{
    let cert = 'vprodemo.pfx';
    let certPass = 'P@ssw0rd';
    let pfxobj = cryptoHelpers.getProvisioningCertObj(cert, certPass);
    expect(cryptoHelpers.dumpPfx(pfxobj)).toHaveProperty('certChain');
    expect(cryptoHelpers.dumpPfx(pfxobj).certChain).toBeDefined();
});
test('Returns valid privateKey in provisioning certificate object', ()=>{
    let cert = 'vprodemo.pfx';
    let certPass = 'P@ssw0rd';
    let pfxobj = cryptoHelpers.getProvisioningCertObj(cert, certPass);
    expect(cryptoHelpers.dumpPfx(pfxobj)).toHaveProperty('privateKey');
    expect(cryptoHelpers.dumpPfx(pfxobj).privateKey).toBeDefined();
});
test('Returns valid rootFingerprint in provisioning certificate object', ()=>{
    let cert = 'vprodemo.pfx';
    let certPass = 'P@ssw0rd';
    let pfxobj = cryptoHelpers.getProvisioningCertObj(cert, certPass);
    expect(cryptoHelpers.dumpPfx(pfxobj)).toHaveProperty('rootFingerprint');
    expect(cryptoHelpers.dumpPfx(pfxobj).rootFingerprint).toBeDefined();
});
test('Returns error message if signing fails', ()=>{
    let message = 'test message';
    let key = '';
    expect(cryptoHelpers.signString(message, key)).toHaveProperty('errorText', "Unable to create Digital Signature");
});
test('Returns valid signed string', ()=>{
    let message = 'test message';
    let cert = 'vprodemo.pfx';
    let certPass = 'P@ssw0rd';
    let pfxobj = cryptoHelpers.getProvisioningCertObj(cert, certPass);
    let key = cryptoHelpers.dumpPfx(pfxobj).privateKey;
    expect(cryptoHelpers.signString(message, key)).toBe("jiszvYn4/Wz+L61m1XgIQfIJoM1yMU7yv3MBiBpAAa4YNCr2BaQtJ1fge4rxmOVaFijJFxE3JHfzAPff+bwcG8a2YYZnjKPM1vYyZ2rKAXeItZy9C2OHAxZBr3BvPBE8FqO8AZaIT5RL7v/4Jlvjak6mNOvDKBRO+HrEZiPLH2VbsteZhVXZLEK899u2j2HfncbbGQnkmRBBc6QAYoBfhl83I/qqKxQ1k2l7JZ3aatJuLXSR+nP/cJqnbtWIdGVtVyl3AKbrrMkMLgtF69QH2oE8zGUgJdgbcOrpzMgrUnpqygxpG6HrTP1CewdcoXJ0KI1/Y2sIkZO22CyoGIYFfQ==");
});
test('Returns a 20 byte length string', ()=>{
    let nonce = cryptoHelpers.generateNonce();
    expect(nonce).toHaveLength(20);
});
test('Return true if certificate issuer matches certificate subject', ()=> {
    let inter = {'issuer': 'issuer1.godaddy.com'};
    let root = {'subject': 'issuer1.godaddy.com'};
    expect(cryptoHelpers.sortCertificate(inter, root)).toBe(true);
});
test('Return false if certificate issuer does not match certificate subject', ()=> {
    let inter = {'issuer': 'issuer2.godaddy.com'};
    let root = {'subject': 'issuer1.godaddy.com'};
    expect(cryptoHelpers.sortCertificate(inter, root)).toBe(false);
});
test('Returns true if password meets criteria', () =>{
    expect(cryptoHelpers.passwordCheck('P@ssw0rd')).toBe(true);
});
test('Returns false if password does not meet criteria', () =>{
    expect(cryptoHelpers.passwordCheck('password')).toBe(false);
});
test('Returns a random password 8 characters long', ()=>{
    let length = 8;
    let characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890!@#$%&?*";
    let password = cryptoHelpers.generateRandomPassword(characters, length);
    expect(password.length).toBe(8);
});
test('Returns a random password 20 times', ()=>{
    let length = 8;
    let characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890!@#$%&?*";
    let i = 0;
    let spy = jest.spyOn(cryptoHelpers, 'generateRandomPassword');
    while (i < 20){
        expect(cryptoHelpers.generateRandomPassword(characters, length).length).toBe(8);
        i++;
    }
    expect(spy).toHaveBeenCalledTimes(20);
});