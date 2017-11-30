* Add tests for the new options
* Add a variable ``Anonymize`` in the configuration that will ignore other options when building the packet
* Implement a MAC address randomization tool
 * Some higher level tool should enforce MAC address randomization when ``Anomize`` is used
* Not related to RFC7844 but in order to behave like most of clients do (and to minimize leaking which is the client being used):
 * implement retransmisions and timeouts according to RFC2132
 * implement RENEW and REBIND (following RFC2132)

