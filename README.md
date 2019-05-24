# amt-rcs
A Remote Configuration Service for configuring Intel(r) AMT devices into admin control mode.  Depends on node-forge and ws NPM libraries.  
# Instructions
Requires: 
 - Intel(r) AMT provisioning certificate that matches the DNS suffix of your Intel(r) AMT machine

Modify the rcs-config.json file to specify the location of the provisioning certificate and specify the Intel(r) AMT password to be set

# Future Work
 - Adding support for TLS wss connections
 - Adding support for matching Intel(r) AMT DNS suffix matching to provisioning certificate list
 - Adding support for configuring Intel(r) AMT with a profile (.mescript)

