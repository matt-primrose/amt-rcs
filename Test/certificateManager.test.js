const certMgr = require('../certificateManager');
test('Returns error message if cert path does not resolve to a file', ()=> {
    let cert = '';
    let certPass = 'password';
    expect(certMgr.getProvisioningCertObj(cert, certPass)).toHaveProperty('errorText', "AMT Provisioning Certificate not found on server");
});
test('Returns error message if cert password can not access certificate', ()=>{
    let cert = 'vprodemo.pfx';
    let certPass = 'password';
    expect(certMgr.convertPfxToObject(cert, certPass)).toHaveProperty('errorText', "Decrypting provisining certificate failed.");
});
test('Verifies certificate object contains certs and keys properties', ()=>{
    let cert = 'vprodemo.pfx';
    let certPass = 'P@ssw0rd';
    expect(certMgr.convertPfxToObject(cert, certPass)).toHaveProperty('certs');
    expect(certMgr.convertPfxToObject(cert, certPass)).toHaveProperty('keys');
});
test('Returns valid certChain in provisioning certificate object', ()=>{
    let cert = 'vprodemo.pfx';
    let certPass = 'P@ssw0rd';
    let pfxobj = certMgr.getProvisioningCertObj(cert, certPass);
    expect(certMgr.dumpPfx(pfxobj)).toHaveProperty('certChain');
    expect(certMgr.dumpPfx(pfxobj).certChain).toBeDefined();
});
test('Returns valid privateKey in provisioning certificate object', ()=>{
    let cert = 'vprodemo.pfx';
    let certPass = 'P@ssw0rd';
    let pfxobj = certMgr.getProvisioningCertObj(cert, certPass);
    expect(certMgr.dumpPfx(pfxobj)).toHaveProperty('privateKey');
    expect(certMgr.dumpPfx(pfxobj).privateKey).toBeDefined();
});
test('Returns valid rootFingerprint in provisioning certificate object', ()=>{
    let cert = 'vprodemo.pfx';
    let certPass = 'P@ssw0rd';
    let pfxobj = certMgr.getProvisioningCertObj(cert, certPass);
    expect(certMgr.dumpPfx(pfxobj)).toHaveProperty('rootFingerprint');
    expect(certMgr.dumpPfx(pfxobj).rootFingerprint).toBeDefined();
});
test('Return true if certificate issuer matches certificate subject', ()=> {
    let inter = {'issuer': 'issuer1.godaddy.com'};
    let root = {'subject': 'issuer1.godaddy.com'};
    expect(certMgr.sortCertificate(inter, root)).toBe(true);
});
test('Return false if certificate issuer does not match certificate subject', ()=> {
    let inter = {'issuer': 'issuer2.godaddy.com'};
    let root = {'subject': 'issuer1.godaddy.com'};
    expect(certMgr.sortCertificate(inter, root)).toBe(false);
});