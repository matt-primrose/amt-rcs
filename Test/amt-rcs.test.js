const rcs = require('../amt-rcs');
const config = {"Name": "RCS Configuration File","Description": "Contains settings to configure the RCS Server","WSConfiguration": {"WebSocketPort": 8080,"WebSocketTLS": false,"WebSocketCertificate": "tlscert.pem","WebSocketCertificateKey": "tlskey.pem"},"AMTConfigurations": [{"ProfileName": "profile1","AMTPassword": "P@ssw0rd","GenerateRandomPassword": true,"RandomPasswordLength": 8,"RandomPasswordCharacters": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890~`!@#$%^&*()_-+=|}]{[;:?.>,<","Activation": "ccmactivate","ConfigurationScript": null},{"ProfileName": "profile2","AMTPassword": "P@ssw0rd","GenerateRandomPassword": false,"RandomPasswordLength": 8,"RandomPasswordCharacters": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890~`!@#$%^&*()_-+=|}]{[;:?.>,<","Activation": "acmactivate","ConfigurationScript": null}],"AMTDomains": [{"Name": "domain1","DomainSuffix": "vprodemo.com","ProvisioningCert": "vprodemo.pfx","ProvisioningCertPassword": "P@ssw0rd"},{"Name": "domain2","DomainSuffix": "d2.com","ProvisioningCert": "d2.pfx","ProvisioningCertPassword": "password"}]};

test("Creates an amt-rcs object", ()=> {
    let amtrcs = rcs(config);
    expect(amtrcs.rcsConfig.Name).toBe('RCS Configuration File');
    expect(amtrcs.rcsConfig.Description).toBe("Contains settings to configure the RCS Server");
    expect(amtrcs.rcsConfig.AMTConfigurations.length).toBe(2);
    expect(amtrcs.rcsConfig.AMTDomains.length).toBe(2);
});
test("Good ACM Activate message returns good provisioning message", ()=>{
    let tunnel = {};
    let acmMessage = JSON.stringify({'client':'MeshCMD','action':'acmactivate','profile':'profile2','fqdn':'vprodemo.com','realm':'Digest:84910000000000000000000000000000','nonce':'klFsYQ/ro4aSmCrbWiWywgNpS08=','hashes':['E7685634EFACF69ACE939A6B255B7B4FABEF42935B50A265ACB5CB6027E44E70','EB04CF5EB1F39AFA762F2BB120F296CBA520C1B97DB1589565B81CB9A17B7244','C3846BF24B9E93CA64274C0EC67C1ECC5E024FFCACD2D74019350E81FE546AE4','D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4','1465FA205397B876FAA6F0A9958E5590E40FCC7FAA4FB7C2C8677521FB5FB658','83CE3C1229688A593D485F81973C0F9195431EDA37CC5E36430E79C7A888638B','A4B6B3996FC2F306B3FD8681BD63413D8C5009CC4FA329C2CCF0E2FA1B140305','9ACFAB7E43C8D880D06B262A94DEEEE4B4659989C3D0CAF19BAF6405E41AB7DF','A53125188D2110AA964B02C7B7C6DA3203170894E5FB71FFFB6667D5E6810A36','16AF57A9F676B0AB126095AA5EBADEF22AB31119D644AC95CD4B93DBF3F26AEB','960ADF0063E96356750C2965DD0A0867DA0B9CBD6E77714AEAFB2349AB393DA3','68AD50909B04363C605EF13581A939FF2C96372E3F12325B0A6861E1D59F6603','6DC47172E01CBCB0BF62580D895FE2B8AC9AD4F873801E0C10B9C837D21EB177','73C176434F1BC6D5ADF45B0E76E727287C8DE57616C1E6E6141A2B2CBC7D8E4C','2399561127A57125DE8CEFEA610DDF2FA078B5C8067F4E828290BFB860E84B3C','45140B3247EB9CC8C5B4F0D7B53091F73292089E6E5A63E2749DD3ACA9198EDA','43DF5774B03E7FEF5FE40D931A7BEDF1BB2E6B42738C4E6D3841103D3AA7F339','2CE1CB0BF9D2F9E102993FBE215152C3B2DD0CABDE1C68E5319B839154DBB7F5','70A73F7F376B60074248904534B11482D5BF0E698ECC498DF52577EBF2E93B9A'],'uuid':'ca77988a-3e12-4406-b838-54b2031cd33b','ver':'11.8.55','modes':[2,1],'currentMode':'0','tag':''});
    let ws = {
        sendMessage: function(tunnel, message){
            expect(message.certs.length).toBe(4);
            expect(message.profileScript).toBeNull();
            expect(message.action).toBe('acmactivate');
            expect(message.status).toBe('ok');
            expect(message.signature).not.toBeNull();
            expect(message.password).not.toBeNull();
        }
    }
    let amtrcs = rcs(config, ws);
    amtrcs.output = function(msg){};
    amtrcs.start();
    amtrcs.wsConnectionHandler('message', acmMessage, tunnel);
});
test("Malformed acm message returns correct error message", ()=>{
    let tunnel = {};
    let acmMessage = "{'client':";
    let ws = {
        sendMessage: function(tunnel, message){
            expect(message.errorText).toBe("Invalid message from client");
        }
    }
    let amtrcs = rcs(config, ws);
    amtrcs.output = function(msg){};
    amtrcs.start();
    amtrcs.wsConnectionHandler('message', acmMessage, tunnel);
});
test("Good CCM Activate message returns good provisioning message", ()=>{
    let tunnel = {};
    let ccmMessage = JSON.stringify({'client':'MeshCMD','action':'ccmactivate','profile':'profile1','fqdn':'','realm':'Digest:84910000000000000000000000000000','nonce':'','hashes':'','uuid':'ca77988a-3e12-4406-b838-54b2031cd33b','ver':'11.8.55','modes':[2,1],'currentMode':'0','tag':''});
    let ws = {
        sendMessage: function(tunnel, message){
            expect(message.certs).toBeUndefined();
            expect(message.profileScript).toBeUndefined();
            expect(message.action).toBe('ccmactivate');
            expect(message.status).toBe('ok');
            expect(message.signature).toBeUndefined();
            expect(message.password).not.toBeNull();
        }
    }
    let amtrcs = rcs(config, ws);
    amtrcs.output = function(msg){};
    amtrcs.start();
    amtrcs.wsConnectionHandler('message', ccmMessage, tunnel);
});
test("Random Password is output to the console if logger and db are undefined", ()=>{
    let tunnel = {};
    let ccmMessage = JSON.stringify({'client':'MeshCMD','action':'ccmactivate','profile':'profile1','fqdn':'','realm':'Digest:84910000000000000000000000000000','nonce':'','hashes':'','uuid':'ca77988a-3e12-4406-b838-54b2031cd33b','ver':'11.8.55','modes':[2,1],'currentMode':'0','tag':''});
    let ws = {
        sendMessage: function(tunnel, message){
        }
    }
    let amtrcs = rcs(config, ws);
    amtrcs.start();
    let spy = jest.spyOn(amtrcs, 'output');
    amtrcs.wsConnectionHandler('message', ccmMessage, tunnel);
    expect(spy).toHaveBeenCalledTimes(2);
});
test("Random Password is output to logger", ()=>{
    let tunnel = {};
    let ccmMessage = JSON.stringify({'client':'MeshCMD','action':'ccmactivate','profile':'profile1','fqdn':'','realm':'Digest:84910000000000000000000000000000','nonce':'','hashes':'','uuid':'ca77988a-3e12-4406-b838-54b2031cd33b','ver':'11.8.55','modes':[2,1],'currentMode':'0','tag':''});
    let logger = function(msg){
        if (typeof msg == 'object'){
            expect(msg.action).toBe('ccmactivate');
            expect(msg.passwordHash).not.toBeUndefined();
            expect(msg.password).not.toBeUndefined();
        }
    }
    let ws = {
        sendMessage: function(tunnel, message){
        }
    }
    let amtrcs = rcs(config, ws, logger);
    amtrcs.start();
    amtrcs.wsConnectionHandler('message', ccmMessage, tunnel);
});
test("RCS receives error message", ()=>{
    let tunnel = {};
    let errorMessage = {'data':'Error received'};
    let ws = { sendMessage: function(tunnel, message){ } }
    let amtrcs = rcs(config, ws);
    amtrcs.start();
    let spy = jest.spyOn(amtrcs, 'output');
    amtrcs.wsConnectionHandler('error', errorMessage, tunnel);
    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy).toHaveBeenCalledWith('AMT Device received "error" message: Error received');
});
test("RCS receives close message", ()=>{
    let tunnel = {};
    let closeMessage = {'data':'closed'};
    let ws = { sendMessage: function(tunnel, message){ } }
    let amtrcs = rcs(config, ws);
    amtrcs.start();
    let spy = jest.spyOn(amtrcs, 'output');
    amtrcs.wsConnectionHandler('close', closeMessage, tunnel);
    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy).toHaveBeenCalledWith('closed');
});
test("RCS receives acmactivate-success message", ()=>{
    let tunnel = {};
    let acmSuccess = JSON.stringify({'client':'MeshCMD', 'uuid':'ca77988a-3e12-4406-b838-54b2031cd33b', 'action':'acmactivate-success'});
    let ws = { sendMessage: function(tunnel, message){ } }
    let amtrcs = rcs(config, ws);
    amtrcs.start();
    let spy = jest.spyOn(amtrcs, 'output');
    amtrcs.wsConnectionHandler('message', acmSuccess, tunnel);
    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy).toHaveBeenCalledWith('AMT Configuration of device ca77988a-3e12-4406-b838-54b2031cd33b success');
});
test("RCS receives ccmactivate-success message", ()=>{
    let tunnel = {};
    let ccmSuccess = JSON.stringify({'client':'MeshCMD', 'uuid':'ca77988a-3e12-4406-b838-54b2031cd33b', 'action':'ccmactivate-success'});
    let ws = { sendMessage: function(tunnel, message){ } }
    let amtrcs = rcs(config, ws);
    amtrcs.start();
    let spy = jest.spyOn(amtrcs, 'output');
    amtrcs.wsConnectionHandler('message', ccmSuccess, tunnel);
    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy).toHaveBeenCalledWith('AMT Configuration of device ca77988a-3e12-4406-b838-54b2031cd33b success');
});
test("End to end testing of acmactivate activation flow", ()=>{
    let tunnel = {};
    let acmMessage = JSON.stringify({'client':'MeshCMD','action':'acmactivate','profile':'profile2','fqdn':'vprodemo.com','realm':'Digest:84910000000000000000000000000000','nonce':'klFsYQ/ro4aSmCrbWiWywgNpS08=','hashes':['E7685634EFACF69ACE939A6B255B7B4FABEF42935B50A265ACB5CB6027E44E70','EB04CF5EB1F39AFA762F2BB120F296CBA520C1B97DB1589565B81CB9A17B7244','C3846BF24B9E93CA64274C0EC67C1ECC5E024FFCACD2D74019350E81FE546AE4','D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4','1465FA205397B876FAA6F0A9958E5590E40FCC7FAA4FB7C2C8677521FB5FB658','83CE3C1229688A593D485F81973C0F9195431EDA37CC5E36430E79C7A888638B','A4B6B3996FC2F306B3FD8681BD63413D8C5009CC4FA329C2CCF0E2FA1B140305','9ACFAB7E43C8D880D06B262A94DEEEE4B4659989C3D0CAF19BAF6405E41AB7DF','A53125188D2110AA964B02C7B7C6DA3203170894E5FB71FFFB6667D5E6810A36','16AF57A9F676B0AB126095AA5EBADEF22AB31119D644AC95CD4B93DBF3F26AEB','960ADF0063E96356750C2965DD0A0867DA0B9CBD6E77714AEAFB2349AB393DA3','68AD50909B04363C605EF13581A939FF2C96372E3F12325B0A6861E1D59F6603','6DC47172E01CBCB0BF62580D895FE2B8AC9AD4F873801E0C10B9C837D21EB177','73C176434F1BC6D5ADF45B0E76E727287C8DE57616C1E6E6141A2B2CBC7D8E4C','2399561127A57125DE8CEFEA610DDF2FA078B5C8067F4E828290BFB860E84B3C','45140B3247EB9CC8C5B4F0D7B53091F73292089E6E5A63E2749DD3ACA9198EDA','43DF5774B03E7FEF5FE40D931A7BEDF1BB2E6B42738C4E6D3841103D3AA7F339','2CE1CB0BF9D2F9E102993FBE215152C3B2DD0CABDE1C68E5319B839154DBB7F5','70A73F7F376B60074248904534B11482D5BF0E698ECC498DF52577EBF2E93B9A'],'uuid':'ca77988a-3e12-4406-b838-54b2031cd33b','ver':'11.8.55','modes':[2,1],'currentMode':'0','tag':''});
    let acmSuccess = JSON.stringify({'client':'MeshCMD', 'uuid':'ca77988a-3e12-4406-b838-54b2031cd33b', 'action':'acmactivate-success'});
    let ws = {
        sendMessage: function(tunnel, message){
            expect(message.certs.length).toBe(4);
            expect(message.profileScript).toBeNull();
            expect(message.action).toBe('acmactivate');
            expect(message.status).toBe('ok');
            expect(message.signature).not.toBeNull();
            expect(message.password).not.toBeNull();
        }
    }
    let amtrcs = rcs(config, ws);
    amtrcs.start();
    amtrcs.wsConnectionHandler('message', acmMessage, tunnel);
    let spy = jest.spyOn(amtrcs, 'output');
    amtrcs.wsConnectionHandler('message', acmSuccess, tunnel);
    expect(spy).toHaveBeenCalledWith('AMT Configuration of device ca77988a-3e12-4406-b838-54b2031cd33b success')
});
test("End to end testing of ccmactivate activation flow", ()=>{
    let tunnel = {};
    let ccmMessage = JSON.stringify({'client':'MeshCMD','action':'ccmactivate','profile':'profile1','fqdn':'','realm':'Digest:84910000000000000000000000000000','nonce':'','hashes':'','uuid':'ca77988a-3e12-4406-b838-54b2031cd33b','ver':'11.8.55','modes':[2,1],'currentMode':'0','tag':''});
    let ccmSuccess = JSON.stringify({'client':'MeshCMD', 'uuid':'ca77988a-3e12-4406-b838-54b2031cd33b', 'action':'ccmactivate-success'});
    let ws = {
        sendMessage: function(tunnel, message){
            expect(message.certs).toBeUndefined();
            expect(message.profileScript).toBeUndefined();
            expect(message.action).toBe('ccmactivate');
            expect(message.status).toBe('ok');
            expect(message.signature).toBeUndefined();
            expect(message.password).not.toBeNull();
        }
    }
    let amtrcs = rcs(config, ws);
    amtrcs.start();
    amtrcs.wsConnectionHandler('message', ccmMessage, tunnel);
    let spy = jest.spyOn(amtrcs, 'output');
    amtrcs.wsConnectionHandler('message', ccmSuccess, tunnel);
    expect(spy).toHaveBeenCalledWith('AMT Configuration of device ca77988a-3e12-4406-b838-54b2031cd33b success')
});
test("Requested acm but profile switches to ccm", ()=>{
    let tunnel = {};
    let acmMessage = JSON.stringify({'client':'MeshCMD','action':'acmactivate','profile':'profile1','fqdn':'vprodemo.com','realm':'Digest:84910000000000000000000000000000','nonce':'klFsYQ/ro4aSmCrbWiWywgNpS08=','hashes':['E7685634EFACF69ACE939A6B255B7B4FABEF42935B50A265ACB5CB6027E44E70','EB04CF5EB1F39AFA762F2BB120F296CBA520C1B97DB1589565B81CB9A17B7244','C3846BF24B9E93CA64274C0EC67C1ECC5E024FFCACD2D74019350E81FE546AE4','D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4','1465FA205397B876FAA6F0A9958E5590E40FCC7FAA4FB7C2C8677521FB5FB658','83CE3C1229688A593D485F81973C0F9195431EDA37CC5E36430E79C7A888638B','A4B6B3996FC2F306B3FD8681BD63413D8C5009CC4FA329C2CCF0E2FA1B140305','9ACFAB7E43C8D880D06B262A94DEEEE4B4659989C3D0CAF19BAF6405E41AB7DF','A53125188D2110AA964B02C7B7C6DA3203170894E5FB71FFFB6667D5E6810A36','16AF57A9F676B0AB126095AA5EBADEF22AB31119D644AC95CD4B93DBF3F26AEB','960ADF0063E96356750C2965DD0A0867DA0B9CBD6E77714AEAFB2349AB393DA3','68AD50909B04363C605EF13581A939FF2C96372E3F12325B0A6861E1D59F6603','6DC47172E01CBCB0BF62580D895FE2B8AC9AD4F873801E0C10B9C837D21EB177','73C176434F1BC6D5ADF45B0E76E727287C8DE57616C1E6E6141A2B2CBC7D8E4C','2399561127A57125DE8CEFEA610DDF2FA078B5C8067F4E828290BFB860E84B3C','45140B3247EB9CC8C5B4F0D7B53091F73292089E6E5A63E2749DD3ACA9198EDA','43DF5774B03E7FEF5FE40D931A7BEDF1BB2E6B42738C4E6D3841103D3AA7F339','2CE1CB0BF9D2F9E102993FBE215152C3B2DD0CABDE1C68E5319B839154DBB7F5','70A73F7F376B60074248904534B11482D5BF0E698ECC498DF52577EBF2E93B9A'],'uuid':'ca77988a-3e12-4406-b838-54b2031cd33b','ver':'11.8.55','modes':[2,1],'currentMode':'0','tag':''});
    let ccmSuccess = JSON.stringify({'client':'MeshCMD', 'uuid':'ca77988a-3e12-4406-b838-54b2031cd33b', 'action':'ccmactivate-success'});
    let ws = {
        sendMessage: function(tunnel, message){
            expect(message.certs).toBeUndefined();
            expect(message.profileScript).toBeUndefined();
            expect(message.action).toBe('ccmactivate');
            expect(message.status).toBe('ok');
            expect(message.signature).toBeUndefined();
            expect(message.password).not.toBeNull();
        }
    }
    let amtrcs = rcs(config, ws);
    amtrcs.start();
    amtrcs.wsConnectionHandler('message', acmMessage, tunnel);
    let spy = jest.spyOn(amtrcs, 'output');
    amtrcs.wsConnectionHandler('message', ccmSuccess, tunnel);
    expect(spy).toHaveBeenCalledWith('AMT Configuration of device ca77988a-3e12-4406-b838-54b2031cd33b success')
});
test("Requested ccm but profile switches to acm", ()=>{
    let tunnel = {};
    let ccmMessage = JSON.stringify({'client':'MeshCMD','action':'ccmactivate','profile':'profile2','fqdn':'vprodemo.com','realm':'Digest:84910000000000000000000000000000','nonce':'klFsYQ/ro4aSmCrbWiWywgNpS08=','hashes':['E7685634EFACF69ACE939A6B255B7B4FABEF42935B50A265ACB5CB6027E44E70','EB04CF5EB1F39AFA762F2BB120F296CBA520C1B97DB1589565B81CB9A17B7244','C3846BF24B9E93CA64274C0EC67C1ECC5E024FFCACD2D74019350E81FE546AE4','D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4','1465FA205397B876FAA6F0A9958E5590E40FCC7FAA4FB7C2C8677521FB5FB658','83CE3C1229688A593D485F81973C0F9195431EDA37CC5E36430E79C7A888638B','A4B6B3996FC2F306B3FD8681BD63413D8C5009CC4FA329C2CCF0E2FA1B140305','9ACFAB7E43C8D880D06B262A94DEEEE4B4659989C3D0CAF19BAF6405E41AB7DF','A53125188D2110AA964B02C7B7C6DA3203170894E5FB71FFFB6667D5E6810A36','16AF57A9F676B0AB126095AA5EBADEF22AB31119D644AC95CD4B93DBF3F26AEB','960ADF0063E96356750C2965DD0A0867DA0B9CBD6E77714AEAFB2349AB393DA3','68AD50909B04363C605EF13581A939FF2C96372E3F12325B0A6861E1D59F6603','6DC47172E01CBCB0BF62580D895FE2B8AC9AD4F873801E0C10B9C837D21EB177','73C176434F1BC6D5ADF45B0E76E727287C8DE57616C1E6E6141A2B2CBC7D8E4C','2399561127A57125DE8CEFEA610DDF2FA078B5C8067F4E828290BFB860E84B3C','45140B3247EB9CC8C5B4F0D7B53091F73292089E6E5A63E2749DD3ACA9198EDA','43DF5774B03E7FEF5FE40D931A7BEDF1BB2E6B42738C4E6D3841103D3AA7F339','2CE1CB0BF9D2F9E102993FBE215152C3B2DD0CABDE1C68E5319B839154DBB7F5','70A73F7F376B60074248904534B11482D5BF0E698ECC498DF52577EBF2E93B9A'],'uuid':'ca77988a-3e12-4406-b838-54b2031cd33b','ver':'11.8.55','modes':[2,1],'currentMode':'0','tag':''});
    let acmSuccess = JSON.stringify({'client':'MeshCMD', 'uuid':'ca77988a-3e12-4406-b838-54b2031cd33b', 'action':'acmactivate-success'});
    let ws = {
        sendMessage: function(tunnel, message){
            expect(message.certs.length).toBe(4);
            expect(message.profileScript).toBeNull();
            expect(message.action).toBe('acmactivate');
            expect(message.status).toBe('ok');
            expect(message.signature).not.toBeNull();
            expect(message.password).not.toBeNull();
        }
    }
    let amtrcs = rcs(config, ws);
    amtrcs.start();
    amtrcs.wsConnectionHandler('message', ccmMessage, tunnel);
    let spy = jest.spyOn(amtrcs, 'output');
    amtrcs.wsConnectionHandler('message', acmSuccess, tunnel);
    expect(spy).toHaveBeenCalledWith('AMT Configuration of device ca77988a-3e12-4406-b838-54b2031cd33b success')
});
test("Proper error returned if device is not found in list of connected devices", ()=>{
    let tunnel = {};
    let ws = { sendMessage: function(tunnel, message){ } }
    let amtrcs = rcs(config, ws);
    amtrcs.output = function(msg){};
    amtrcs.start();
    let testObj = amtrcs.remoteConfiguration('1234', '1234', 'acmactivate');
    expect(testObj.errorText).not.toBeUndefined();
    expect(testObj.errorText).toBe("AMT Device 1234 not found in list of connected clients.");
});
test("Proper error returned if fwNonce is not sent for ACM", ()=>{
    let tunnel = {};
    let ws = { sendMessage: function(tunnel, message){ } }
    let amtrcs = rcs(config, ws);
    amtrcs.output = function(msg){};
    amtrcs.start();
    amtrcs.connection = {};
    amtrcs.connection['1234'] = {'client':'MeshCMD','action':'acmactivate','profile':'profile2','dnsSuffix':'vprodemo.com','digestRealm':'Digest:84910000000000000000000000000000','fwNonce':'klFsYQ/ro4aSmCrbWiWywgNpS08=','certHashes':['E7685634EFACF69ACE939A6B255B7B4FABEF42935B50A265ACB5CB6027E44E70','EB04CF5EB1F39AFA762F2BB120F296CBA520C1B97DB1589565B81CB9A17B7244','C3846BF24B9E93CA64274C0EC67C1ECC5E024FFCACD2D74019350E81FE546AE4','D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4','1465FA205397B876FAA6F0A9958E5590E40FCC7FAA4FB7C2C8677521FB5FB658','83CE3C1229688A593D485F81973C0F9195431EDA37CC5E36430E79C7A888638B','A4B6B3996FC2F306B3FD8681BD63413D8C5009CC4FA329C2CCF0E2FA1B140305','9ACFAB7E43C8D880D06B262A94DEEEE4B4659989C3D0CAF19BAF6405E41AB7DF','A53125188D2110AA964B02C7B7C6DA3203170894E5FB71FFFB6667D5E6810A36','16AF57A9F676B0AB126095AA5EBADEF22AB31119D644AC95CD4B93DBF3F26AEB','960ADF0063E96356750C2965DD0A0867DA0B9CBD6E77714AEAFB2349AB393DA3','68AD50909B04363C605EF13581A939FF2C96372E3F12325B0A6861E1D59F6603','6DC47172E01CBCB0BF62580D895FE2B8AC9AD4F873801E0C10B9C837D21EB177','73C176434F1BC6D5ADF45B0E76E727287C8DE57616C1E6E6141A2B2CBC7D8E4C','2399561127A57125DE8CEFEA610DDF2FA078B5C8067F4E828290BFB860E84B3C','45140B3247EB9CC8C5B4F0D7B53091F73292089E6E5A63E2749DD3ACA9198EDA','43DF5774B03E7FEF5FE40D931A7BEDF1BB2E6B42738C4E6D3841103D3AA7F339','2CE1CB0BF9D2F9E102993FBE215152C3B2DD0CABDE1C68E5319B839154DBB7F5','70A73F7F376B60074248904534B11482D5BF0E698ECC498DF52577EBF2E93B9A'],'uuid':'ca77988a-3e12-4406-b838-54b2031cd33b','ver':'11.8.55','modes':[2,1],'currentMode':'0','tag':''};
    let testObj = amtrcs.remoteConfiguration(null, '1234', 'acmactivate');
    expect(testObj.errorText).not.toBeUndefined();
    expect(testObj.errorText).toBe("Not enough information to configure AMT: Missing Nonce.");
});
test("Proper error returned if dnsSuffix is not sent for ACM", ()=>{
    let tunnel = {};
    let ws = { sendMessage: function(tunnel, message){ } }
    let amtrcs = rcs(config, ws);
    amtrcs.output = function(msg){};
    amtrcs.start();
    amtrcs.connection = {};
    amtrcs.connection['1234'] = {'client':'MeshCMD','action':'acmactivate','profile':'profile2','digestRealm':'Digest:84910000000000000000000000000000','fwNonce':'klFsYQ/ro4aSmCrbWiWywgNpS08=','certHashes':['E7685634EFACF69ACE939A6B255B7B4FABEF42935B50A265ACB5CB6027E44E70','EB04CF5EB1F39AFA762F2BB120F296CBA520C1B97DB1589565B81CB9A17B7244','C3846BF24B9E93CA64274C0EC67C1ECC5E024FFCACD2D74019350E81FE546AE4','D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4','1465FA205397B876FAA6F0A9958E5590E40FCC7FAA4FB7C2C8677521FB5FB658','83CE3C1229688A593D485F81973C0F9195431EDA37CC5E36430E79C7A888638B','A4B6B3996FC2F306B3FD8681BD63413D8C5009CC4FA329C2CCF0E2FA1B140305','9ACFAB7E43C8D880D06B262A94DEEEE4B4659989C3D0CAF19BAF6405E41AB7DF','A53125188D2110AA964B02C7B7C6DA3203170894E5FB71FFFB6667D5E6810A36','16AF57A9F676B0AB126095AA5EBADEF22AB31119D644AC95CD4B93DBF3F26AEB','960ADF0063E96356750C2965DD0A0867DA0B9CBD6E77714AEAFB2349AB393DA3','68AD50909B04363C605EF13581A939FF2C96372E3F12325B0A6861E1D59F6603','6DC47172E01CBCB0BF62580D895FE2B8AC9AD4F873801E0C10B9C837D21EB177','73C176434F1BC6D5ADF45B0E76E727287C8DE57616C1E6E6141A2B2CBC7D8E4C','2399561127A57125DE8CEFEA610DDF2FA078B5C8067F4E828290BFB860E84B3C','45140B3247EB9CC8C5B4F0D7B53091F73292089E6E5A63E2749DD3ACA9198EDA','43DF5774B03E7FEF5FE40D931A7BEDF1BB2E6B42738C4E6D3841103D3AA7F339','2CE1CB0BF9D2F9E102993FBE215152C3B2DD0CABDE1C68E5319B839154DBB7F5','70A73F7F376B60074248904534B11482D5BF0E698ECC498DF52577EBF2E93B9A'],'uuid':'ca77988a-3e12-4406-b838-54b2031cd33b','ver':'11.8.55','modes':[2,1],'currentMode':'0','tag':''};
    let testObj = amtrcs.remoteConfiguration('1234', '1234', 'acmactivate');
    expect(testObj.errorText).not.toBeUndefined();
    expect(testObj.errorText).toBe("AMT domain suffix not specified.");
});
test("Proper error returned if dnsSuffix is null for ACM", ()=>{
    let tunnel = {};
    let ws = { sendMessage: function(tunnel, message){ } }
    let amtrcs = rcs(config, ws);
    amtrcs.output = function(msg){};
    amtrcs.start();
    amtrcs.connection = {};
    amtrcs.connection['1234'] = {'client':'MeshCMD','action':'acmactivate','profile':'profile2','dnsSuffix':null,'digestRealm':'Digest:84910000000000000000000000000000','fwNonce':'klFsYQ/ro4aSmCrbWiWywgNpS08=','certHashes':['E7685634EFACF69ACE939A6B255B7B4FABEF42935B50A265ACB5CB6027E44E70','EB04CF5EB1F39AFA762F2BB120F296CBA520C1B97DB1589565B81CB9A17B7244','C3846BF24B9E93CA64274C0EC67C1ECC5E024FFCACD2D74019350E81FE546AE4','D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4','1465FA205397B876FAA6F0A9958E5590E40FCC7FAA4FB7C2C8677521FB5FB658','83CE3C1229688A593D485F81973C0F9195431EDA37CC5E36430E79C7A888638B','A4B6B3996FC2F306B3FD8681BD63413D8C5009CC4FA329C2CCF0E2FA1B140305','9ACFAB7E43C8D880D06B262A94DEEEE4B4659989C3D0CAF19BAF6405E41AB7DF','A53125188D2110AA964B02C7B7C6DA3203170894E5FB71FFFB6667D5E6810A36','16AF57A9F676B0AB126095AA5EBADEF22AB31119D644AC95CD4B93DBF3F26AEB','960ADF0063E96356750C2965DD0A0867DA0B9CBD6E77714AEAFB2349AB393DA3','68AD50909B04363C605EF13581A939FF2C96372E3F12325B0A6861E1D59F6603','6DC47172E01CBCB0BF62580D895FE2B8AC9AD4F873801E0C10B9C837D21EB177','73C176434F1BC6D5ADF45B0E76E727287C8DE57616C1E6E6141A2B2CBC7D8E4C','2399561127A57125DE8CEFEA610DDF2FA078B5C8067F4E828290BFB860E84B3C','45140B3247EB9CC8C5B4F0D7B53091F73292089E6E5A63E2749DD3ACA9198EDA','43DF5774B03E7FEF5FE40D931A7BEDF1BB2E6B42738C4E6D3841103D3AA7F339','2CE1CB0BF9D2F9E102993FBE215152C3B2DD0CABDE1C68E5319B839154DBB7F5','70A73F7F376B60074248904534B11482D5BF0E698ECC498DF52577EBF2E93B9A'],'uuid':'ca77988a-3e12-4406-b838-54b2031cd33b','ver':'11.8.55','modes':[2,1],'currentMode':'0','tag':''};
    let testObj = amtrcs.remoteConfiguration('1234', '1234', 'acmactivate');
    expect(testObj.errorText).not.toBeUndefined();
    expect(testObj.errorText).toBe("AMT domain suffix not specified.");
});
test("Proper error returned if dnsSuffix does not match list of available DNS Suffixes", ()=>{
    let tunnel = {};
    let ws = { sendMessage: function(tunnel, message){ } }
    let amtrcs = rcs(config, ws);
    amtrcs.output = function(msg){};
    amtrcs.start();
    amtrcs.connection = {};
    amtrcs.connection['1234'] = {'client':'MeshCMD','action':'acmactivate','profile':'profile2','dnsSuffix':'hello.com','digestRealm':'Digest:84910000000000000000000000000000','fwNonce':'klFsYQ/ro4aSmCrbWiWywgNpS08=','certHashes':['E7685634EFACF69ACE939A6B255B7B4FABEF42935B50A265ACB5CB6027E44E70','EB04CF5EB1F39AFA762F2BB120F296CBA520C1B97DB1589565B81CB9A17B7244','C3846BF24B9E93CA64274C0EC67C1ECC5E024FFCACD2D74019350E81FE546AE4','D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4','1465FA205397B876FAA6F0A9958E5590E40FCC7FAA4FB7C2C8677521FB5FB658','83CE3C1229688A593D485F81973C0F9195431EDA37CC5E36430E79C7A888638B','A4B6B3996FC2F306B3FD8681BD63413D8C5009CC4FA329C2CCF0E2FA1B140305','9ACFAB7E43C8D880D06B262A94DEEEE4B4659989C3D0CAF19BAF6405E41AB7DF','A53125188D2110AA964B02C7B7C6DA3203170894E5FB71FFFB6667D5E6810A36','16AF57A9F676B0AB126095AA5EBADEF22AB31119D644AC95CD4B93DBF3F26AEB','960ADF0063E96356750C2965DD0A0867DA0B9CBD6E77714AEAFB2349AB393DA3','68AD50909B04363C605EF13581A939FF2C96372E3F12325B0A6861E1D59F6603','6DC47172E01CBCB0BF62580D895FE2B8AC9AD4F873801E0C10B9C837D21EB177','73C176434F1BC6D5ADF45B0E76E727287C8DE57616C1E6E6141A2B2CBC7D8E4C','2399561127A57125DE8CEFEA610DDF2FA078B5C8067F4E828290BFB860E84B3C','45140B3247EB9CC8C5B4F0D7B53091F73292089E6E5A63E2749DD3ACA9198EDA','43DF5774B03E7FEF5FE40D931A7BEDF1BB2E6B42738C4E6D3841103D3AA7F339','2CE1CB0BF9D2F9E102993FBE215152C3B2DD0CABDE1C68E5319B839154DBB7F5','70A73F7F376B60074248904534B11482D5BF0E698ECC498DF52577EBF2E93B9A'],'uuid':'ca77988a-3e12-4406-b838-54b2031cd33b','ver':'11.8.55','modes':[2,1],'currentMode':'0','tag':''};
    let testObj = amtrcs.remoteConfiguration('1234', '1234', 'acmactivate');
    expect(testObj.errorText).not.toBeUndefined();
    expect(testObj.errorText).toBe("Specified AMT domain suffix does not match list of available AMT domain suffixes.");
});
test("Proper error returned if certificate hash match is not found", ()=>{
    let tunnel = {};
    let ws = { sendMessage: function(tunnel, message){ } }
    let amtrcs = rcs(config, ws);
    amtrcs.output = function(msg){};
    amtrcs.start();
    amtrcs.connection = {};
    amtrcs.connection['1234'] = {'client':'MeshCMD','action':'acmactivate','profile':'profile2','dnsSuffix':'vprodemo.com','digestRealm':'Digest:84910000000000000000000000000000','fwNonce':'klFsYQ/ro4aSmCrbWiWywgNpS08=','certHashes':['70A73F7F376B60074248904534B11482D5BF0E698ECC498DF52577EBF2E93B9A'],'uuid':'ca77988a-3e12-4406-b838-54b2031cd33b','ver':'11.8.55','modes':[2,1],'currentMode':'0','tag':''};
    let testObj = amtrcs.remoteConfiguration('klFsYQ/ro4aSmCrbWiWywgNpS08=', '1234', 'acmactivate');
    expect(testObj.errorText).not.toBeUndefined();
    expect(testObj.errorText).toBe("Provisioning Certificate doesn't match any trusted certificates from AMT");
});
test("Proper error returned if certificate hash match is not found", ()=>{
    let tunnel = {};
    let ws = { sendMessage: function(tunnel, message){ } }
    let amtrcs = rcs(config, ws);
    amtrcs.output = function(msg){};
    amtrcs.start();
    let nonce = Buffer.from('klFsYQ/ro4aSmCrbWiWywgNpS08=', 'base64');
    amtrcs.connection = {};
    amtrcs.connection['1234'] = {'client':'MeshCMD','action':'acmactivate','profile':'profile3','dnsSuffix':'vprodemo.com','digestRealm':'Digest:84910000000000000000000000000000','fwNonce':nonce,'certHashes':['E7685634EFACF69ACE939A6B255B7B4FABEF42935B50A265ACB5CB6027E44E70','EB04CF5EB1F39AFA762F2BB120F296CBA520C1B97DB1589565B81CB9A17B7244','C3846BF24B9E93CA64274C0EC67C1ECC5E024FFCACD2D74019350E81FE546AE4','D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4','1465FA205397B876FAA6F0A9958E5590E40FCC7FAA4FB7C2C8677521FB5FB658','83CE3C1229688A593D485F81973C0F9195431EDA37CC5E36430E79C7A888638B','A4B6B3996FC2F306B3FD8681BD63413D8C5009CC4FA329C2CCF0E2FA1B140305','9ACFAB7E43C8D880D06B262A94DEEEE4B4659989C3D0CAF19BAF6405E41AB7DF','A53125188D2110AA964B02C7B7C6DA3203170894E5FB71FFFB6667D5E6810A36','16AF57A9F676B0AB126095AA5EBADEF22AB31119D644AC95CD4B93DBF3F26AEB','960ADF0063E96356750C2965DD0A0867DA0B9CBD6E77714AEAFB2349AB393DA3','68AD50909B04363C605EF13581A939FF2C96372E3F12325B0A6861E1D59F6603','6DC47172E01CBCB0BF62580D895FE2B8AC9AD4F873801E0C10B9C837D21EB177','73C176434F1BC6D5ADF45B0E76E727287C8DE57616C1E6E6141A2B2CBC7D8E4C','2399561127A57125DE8CEFEA610DDF2FA078B5C8067F4E828290BFB860E84B3C','45140B3247EB9CC8C5B4F0D7B53091F73292089E6E5A63E2749DD3ACA9198EDA','43DF5774B03E7FEF5FE40D931A7BEDF1BB2E6B42738C4E6D3841103D3AA7F339','2CE1CB0BF9D2F9E102993FBE215152C3B2DD0CABDE1C68E5319B839154DBB7F5','70A73F7F376B60074248904534B11482D5BF0E698ECC498DF52577EBF2E93B9A'],'uuid':'ca77988a-3e12-4406-b838-54b2031cd33b','ver':'11.8.55','modes':[2,1],'currentMode':'0','tag':''};
    let testObj = amtrcs.remoteConfiguration(nonce, '1234', 'acmactivate');
    expect(testObj.errorText).not.toBeUndefined();
    expect(testObj.errorText).toBe("Specified AMT profile name does not match list of available AMT profiles.");
});
test("sendMessage outputs proper error if webserver is not initialized", ()=>{
    let tunnel = {};
    let ws = { sendMessage: function(tunnel, message){ } }
    let amtrcs = rcs(config, ws);
    amtrcs.wsServer = null;
    let message = {'status':'ok', 'message':'hello'};
    amtrcs.output = function(msg){};
    amtrcs.start();
    amtrcs.output = function(msg){
        expect(msg).toBe('WebSocket Server not initialized.');
    };
    amtrcs.sendMessage(tunnel, message);
});
test("sendMessage sends a message to wsServer.sendMessage", ()=>{
    let tunnel = {};
    let ws = { sendMessage: function(tunnel, message){
        expect(message.status).toBe('ok');
        expect(message.message).toBe('hello');
        expect(message.version).toBe(1);
    }};
    let amtrcs = rcs(config, ws);
    let message = {'status':'ok', 'message':'hello'};
    amtrcs.output = function(msg){};
    amtrcs.start();
    amtrcs.sendMessage(tunnel, message);
});