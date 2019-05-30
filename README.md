# amt-rcs
A Remote Configuration Service for configuring Intel:registered: AMT devices into admin control mode.  Depends on node-forge and ws NPM libraries.  Before running the server, you'll want to npm install both of these packages.
# Instructions
Requires: 
 - Intel:registered: AMT provisioning certificate that matches the DNS suffix of your Intel:registered: AMT machine

Modify the rcs-config.json file to specify the location of the provisioning certificate and specify the Intel:registered: AMT password to be set
```
{
  "Name": "RCS Configuration File",
  "Description": "Contains settings to configure the RCS Server",
  "WSConfiguration": {
    "WebSocketPort": 8080,
    "WebSocketCertificate": "tlscert.pfx" - Currently not implemented
  },
  "AMTConfiguration": {
    "AMTPassword": "amtP@ssword", - new MEBx password for AMT
    "ProvisioningCert": [ "provcertificate.pfx" ], - provisioning certificate for Intel(r) AMT
    "ProvisioningCertPassword": [ "certpassword" ] - password to access provisioning certificate
  }
}
```

Start from command line: node amt-rcs.js

# Future Work
 - Adding support for TLS wss connections
 - Adding support for matching Intel:registered: AMT DNS suffix matching to provisioning certificate list
 - Adding support for configuring Intel:registered: AMT with a profile (.mescript)

