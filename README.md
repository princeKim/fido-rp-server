#FIDO UAF Relying Party Server

## Purpose
This is a sample FIDO UAF relying party server application written in Java which uses IdentityX ([https://www.daon.com/identityX](https://www.daon.com/identityx))  to perform FIDO UAF operations.  It demonstrates how to integrate with IdentityX and use FIDO UAF Clients and Authenticators.

There is an associated FIDO UAF Relying Party Android App ([https://github.com/daoninc/fido-android-rp-app](https://github.com/daoninc/fido-android-rp-app)) which demonstrates how to interact with FIDO UAF Clients and Authenticators on Android. 

*IdentityX is a human authentication platform enabling people, across any channel to easily assert and protect their identity.*

For more details on how to get a sample App up and running please see [https://daoninc.github.io/fido-integration](https://daoninc.github.io/fido-integration).

##Integrating with other FIDO UAF Servers
One question you might have is whether this Relying Party Server can be used to connect to other FIDO UAF servers.  The FIDO Alliance UAF specifications describe the format of the messages to be sent between the FIDO server and the FIDO client but not the method of sending those messages i.e. the FIDO Server API.  This allows different vendors to implement different approaches but it does mean that in order for this Sample RP Server to work with another server, it would need to be changed to call the interface to that server.  The API you will see used by this project to talk to IdentityX is Daon's interface.  Other FIDO UAF Servers are likely to have a different interface.

If you have altered this project to work with another FIDO UAF Server, please send us a pull request and we will see if we can incorporate it in a way which allows a simple configuration flag to determine the target server.

##Made Changes?
If you have improvements or changes you feel would improve this project, please send us a pull request.

##Thanks
Our thanks to the FIDO Alliance who are helping to move the world beyond the tyranny of passwords.

##Help
Contact us via email at support@daon.com. You can also see the IdentityX documentation for more information.

##License
Apache 2.0, see [LICENSE](https://github.com/daoninc/fido-rp-server/blob/master/LICENSE.md).