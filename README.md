# amt-rcs
A Remote Configuration Service for configuring Intel:registered: AMT devices into admin control mode.  Depends on node-forge and ws NPM libraries.  Before running the server, you'll want to npm install both of these packages.
Built to work with MeshCMD which you can get here: https://www.meshcommander.com/meshcommander/meshcmd

### New Features
- Support for setting up tls for secure websocket communication
- Supports multiple AMT profiles (MEBx password only currently)
- Supports multiple AMT domain suffix

### Instructions
Requires: 
 - Intel:registered: AMT provisioning certificate that matches the DNS suffix of your Intel:registered: AMT machine

Modify the rcs-config.json file to specify the location of the provisioning certificate and specify the Intel:registered: AMT password to be set
```
{
  "Name": "RCS Configuration File",
  "Description": "Contains settings to configure the RCS Server",
  "WSConfiguration": {
    "WebSocketPort": 8080,
    "WebSocketTLS": false,
    "WebSocketCertificate": "tlscert.pem",
    "WebSocketCertificateKey": "tlskey.pem"
  },
  "AMTConfigurations": [
    {
      "ProfileName": "default",
      "AMTPassword": "password",
      "ConfigurationScript": ""
    },
    {
      "ProfileName": "config2",
      "AMTPassword": "password",
      "ConfigurationScript": ""
    }
  ],
  "AMTDomains": [
    {
      "Name": "domain1",
      "DomainSuffix": "amt.net",
      "ProvisioningCert": "d1.pfx",
      "ProvisioningCertPassword": "password"
    },
    {
      "Name": "domain2",
      "DomainSuffix": "somethingelse.com",
      "ProvisioningCert": "d2.pfx",
      "ProvisioningCertPassword": "password"
    }
  ]
}
```

Start from command line: node amt-rcs.js

### Future Work
 - Adding support for configuring Intel:registered: AMT with a profile (.mescript)

