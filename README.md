# Instructions

Extension for authentication using digital certificate for Zimbra

## To compile
- Copy the files from "/opt/zimbra/lib/jars" folder to the "lib" project folder
- Execute the ant command to compile and package, inside the project directory: "ant jar"

## Install
- Configure client ssl authentication on proxy and client certificate forwarding in the header "X-Client-Certificate" example:
```
proxy_set_header X-Client-Certificate $ssl_client_escaped_cert;
```
- Create the "certconsumer" directory inside "/opt/zimbra/lib/ext"
- Copy "certconsumer.jar", located, after compiled, in the "dist" folder, to the directory "/opt/zimbra/lib/ext/certconsumer"
- Restart mailbox "zmmailboxdctl restart"

## Use
- To consume authentication by certificate, you must access the "service/extension/cert/consumer" URL on the Zimbra server, for example: https://mail.example.com/service/extension/cert/consumer
- To authenticate to administrator you must configure to request client certificate and to foward it on the admin port and consume the URL passing the parameter "admin=true", "service/extension/cert/consumer?Admin=true", as for example: https://mail.serpro.gov.br:7071/service/extension/cert/consumer?admin=true
