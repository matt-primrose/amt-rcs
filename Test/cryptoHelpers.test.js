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
test('Verifies certificate object contains certs and keys properties', ()=>{
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
test('Verifies signed string is valid', ()=>{
    let message = 'test message';
    let cert = 'vprodemo.pfx';
    let certPass = 'P@ssw0rd';
    let pfxobj = cryptoHelpers.getProvisioningCertObj(cert, certPass);
    let key = cryptoHelpers.dumpPfx(pfxobj).privateKey;
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
test('Returns a password with only "A" characters', ()=>{
    let length = 8;
    let characters = "A";
    let password = cryptoHelpers.generateRandomPassword(characters, length);
    expect(password).toBe("AAAAAAAA");
});
test('Returns a random password 50 times', ()=>{
    let length = 8;
    let characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890~`!@#$%^&*()_-+=|}]{[;:?.>,<";
    let i = 0;
    let spy = jest.spyOn(cryptoHelpers, 'generateRandomPassword');
    while (i < 50){
        expect(cryptoHelpers.generateRandomPassword(characters, length).length).toBe(8);
        i++;
    }
    expect(spy).toHaveBeenCalledTimes(50);
});
test('Returns an error if no password characters are passed in', ()=>{
    let length = 8;
    let characters = "";
    let cbMessage = "";
    cryptoHelpers.generateRandomPassword(characters, length, function(message){
        cbMessage = message.errorText
    });
    expect(cbMessage).toBe("Not enough valid characters to create random password.");
});
test('Returns an error if password length is too short', ()=>{
    let length = 4;
    let characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890~`!@#$%^&*()_-+=|}]{[;:?.>,<";
    let cbMessage = "";
    cryptoHelpers.generateRandomPassword(characters, length, function(message){
        cbMessage = message.errorText
    });
    expect(cbMessage).toBe("Invalid password length specified.");
});
test('Returns an error if password length is too long', ()=>{
    let length = 33;
    let characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890~`!@#$%^&*()_-+=|}]{[;:?.>,<";
    let cbMessage = "";
    cryptoHelpers.generateRandomPassword(characters, length, function(message){
        cbMessage = message.errorText
    });
    expect(cbMessage).toBe("Invalid password length specified.");
});
test('Returns error message if a bad AMT password is detected', async ()=>{
    let list = [{"ProfileName": "profile1","AMTPassword": "password","GenerateRandomPassword": false,"RandomPasswordLength": 8,"RandomPasswordCharacters": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890~`!@#$%^&*()_-+=|}]{[;:?.>,<","Activation": "ccmactivate","ConfigurationScript": null}];
    let cbMessage = '';
    cryptoHelpers.validateAMTPasswords(list, function(message){ cbMessage = message; });
    expect(cbMessage.errorText).toBe("Detected bad AMT password for profile: profile1./n/rRemoving profile1 profile from list of available AMT profiles.");
});
test('Returns error message if random AMT password length is too short', async ()=>{
    let list = [{"ProfileName": "profile1","AMTPassword": "<StrongPassword>","GenerateRandomPassword": true,"RandomPasswordLength": 7,"RandomPasswordCharacters": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890~`!@#$%^&*()_-+=|}]{[;:?.>,<","Activation": "ccmactivate","ConfigurationScript": null}];
    let cbMessage = '';
    cryptoHelpers.validateAMTPasswords(list, function(message){ cbMessage = message; });
    expect(cbMessage.errorText).toBe("Detected bad AMT password length for profile: profile1./n/rRemoving profile1 profile from list of available AMT profiles.");
});
test('Returns error message if random AMT password length is too long', async ()=>{
    let list = [{"ProfileName": "profile1","AMTPassword": "<StrongPassword>","GenerateRandomPassword": true,"RandomPasswordLength": 33,"RandomPasswordCharacters": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890~`!@#$%^&*()_-+=|}]{[;:?.>,<","Activation": "ccmactivate","ConfigurationScript": null}];
    let cbMessage = '';
    cryptoHelpers.validateAMTPasswords(list, function(message){ cbMessage = message; });
    expect(cbMessage.errorText).toBe("Detected bad AMT password length for profile: profile1./n/rRemoving profile1 profile from list of available AMT profiles.");
});
test('Returns list without bad profile', async ()=>{
    let list = [{"ProfileName": "profile1","AMTPassword": "<StrongPassword>","GenerateRandomPassword": true,"RandomPasswordLength": 33,"RandomPasswordCharacters": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890~`!@#$%^&*()_-+=|}]{[;:?.>,<","Activation": "ccmactivate","ConfigurationScript": null}];
    list = cryptoHelpers.validateAMTPasswords(list, function(message){});
    expect(list.length).toBe(0);
});
test('Returns list with good profile - Set Password', async ()=>{
    let list = [{"ProfileName": "profile1","AMTPassword": "P@ssw0rd","GenerateRandomPassword": false,"RandomPasswordLength": 33,"RandomPasswordCharacters": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890~`!@#$%^&*()_-+=|}]{[;:?.>,<","Activation": "ccmactivate","ConfigurationScript": null}];
    list = cryptoHelpers.validateAMTPasswords(list, function(message){});
    expect(list.length).toBe(1);
});
test('Returns list with good profile - Random Password', async ()=>{
    let list = [{"ProfileName": "profile1","AMTPassword": "password","GenerateRandomPassword": true,"RandomPasswordLength": 10,"RandomPasswordCharacters": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890~`!@#$%^&*()_-+=|}]{[;:?.>,<","Activation": "ccmactivate","ConfigurationScript": null}];
    list = cryptoHelpers.validateAMTPasswords(list, function(message){});
    expect(list.length).toBe(1);
});