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