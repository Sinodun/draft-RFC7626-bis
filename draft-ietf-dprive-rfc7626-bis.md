%%%
    Title = "DNS Privacy Considerations"
    abbrev = "DNS Privacy Considerations"
    category = "info"
    docName= "draft-ietf-dprive-rfc7626-bis-03"
    ipr = "trust200902"
    area = "Internet Area"
    workgroup = "dprive"
    keyword = ["DNS"]
    obsoletes = [7626]
    date = 2019-11-06T00:00:00Z
    [pi]
    toc = "yes"
    tocdepth = "6"
    compact = "yes"
    symrefs = "yes"
    sortrefs = "yes"
    subcompact = "no"
    [[author]]
    initials="S."
    surname="Bortzmeyer"
    fullname="Stephane Bortzmeyer"
    organization = "AFNIC"
      [author.address]
      email = "bortzmeyer+ietf@nic.fr"
      [author.address.postal]
      streets = ["1, rue Stephenson", "Montigny-le-Bretonneux"]
      city = "France"
      code = "78180"
    [[author]]
    initials="S."
    surname="Dickinson"
    fullname="Sara Dickinson"
    organization = "Sinodun IT"
        [author.address]
        email = "sara@sinodun.com"
        [author.address.postal]
        streets = ["Magdalen Centre", "Oxford Science Park"]
        city = "Oxford"
        code = "OX4 4GA"
        country = 'United Kingdom'
%%%


.# Abstract

  This document describes the privacy issues associated with the use of the DNS
  by Internet users. It is intended to be an analysis of the present situation
  and does not prescribe solutions. This document obsoletes RFC 7626.
   
{mainmatter}

#  Introduction

   This document is an analysis of the DNS privacy issues, in the spirit
   of Section 8 of [@!RFC6973].

   The Domain Name System (DNS) is specified in [@!RFC1034], [@!RFC1035], and
   many later RFCs, which have never been consolidated. It is one of the most
   important infrastructure components of the Internet and often ignored or
   misunderstood by Internet users (and even by many professionals). Almost
   every activity on the Internet starts with a DNS query (and often several).
   Its use has many privacy implications and this document is an attempt at a
   comprehensive and accurate list.

   Let us begin with a simplified reminder of how the DNS works (See also
   [@?RFC8499]). A client, the stub resolver, issues a
   DNS query to a server, called the recursive resolver (also called caching
   resolver or full resolver or recursive name server). Let's use the query
   "What are the AAAA records for www.example.com?" as an example. AAAA is the
   QTYPE (Query Type), and www.example.com is the QNAME (Query Name). (The
   description that follows assumes a cold cache, for instance, because the
   server just started.) The recursive resolver will first query the root name
   servers. In most cases, the root name servers will send a referral. In this
   example, the referral will be to the .com name servers. The resolver repeats
   the query to one of the .com name servers. The .com name servers, in turn,
   will refer to the example.com name servers. The example.com name server will
   then return the answer. The root name servers, the name servers of .com, and
   the name servers of example.com are called authoritative name servers. It is
   important, when analyzing the privacy issues, to remember that the question
   asked to all these name servers is always the original question, not a
   derived question. The question sent to the root name servers is "What are
   the AAAA records for www.example.com?", not "What are the name servers of
   .com?". By repeating the full question, instead of just the relevant part of
   the question to the next in line, the DNS provides more information than
   necessary to the name server. In this simplified description, recursive
   resolvers do not implement QNAME minimization as described in [@RFC7816],
   which will only send the relevant part of the question to the upstream name
   server.

   Because DNS relies on caching heavily, the algorithm described
   above is actually a bit more complicated, and not all questions are
   sent to the authoritative name servers.  If a few seconds later the
   stub resolver asks the recursive resolver, "What are the SRV records
   of _xmpp-server._tcp.example.com?", the recursive resolver will
   remember that it knows the name servers of example.com and will just
   query them, bypassing the root and .com.  Because there is typically
   no caching in the stub resolver, the recursive resolver, unlike the
   authoritative servers, sees all the DNS traffic.  (Applications, like
   web browsers, may have some form of caching that does not follow DNS
   rules, for instance, because it may ignore the TTL.  So, the
   recursive resolver does not see all the name resolution activity.)

   It should be noted that DNS recursive resolvers sometimes forward
   requests to other recursive resolvers, typically bigger machines,
   with a larger and more shared cache (and the query hierarchy can be
   even deeper, with more than two levels of recursive resolvers).  From
   the point of view of privacy, these forwarders are like resolvers,
   except that they do not see all of the requests being made (due to
   caching in the first resolver).

  At the time of writing, almost all this DNS traffic is currently
  sent in clear (i.e., unencrypted). However there is increasing deployment
  of DNS-over-TLS (DoT) [@RFC7858] and DNS-over-HTTPS (DoH)
  [@RFC8484], particularly in mobile devices, browsers, and by
  providers of anycast recursive DNS resolution services. There are a
  few cases where there is some alternative channel encryption, for
  instance, in an IPsec VPN tunnel, at least between the stub resolver and
  the resolver.

   Today, almost all DNS queries are sent over UDP [@thomas-ditl-tcp]. This has
   practical consequences when considering encryption of the traffic as a
   possible privacy technique. Some encryption solutions are only designed for
   TCP, not UDP and new solutions are still emerging [@I-D.ietf-quic-transport].

   Another important point to keep in mind when analyzing the privacy
   issues of DNS is the fact that DNS requests received by a server are
   triggered by different reasons.  Let's assume an eavesdropper wants
   to know which web page is viewed by a user.  For a typical web page,
   there are three sorts of DNS requests being issued:

*   Primary request: this is the domain name in the URL that the user
  typed, selected from a bookmark, or chose by clicking on an
  hyperlink.  Presumably, this is what is of interest for the
  eavesdropper.

*   Secondary requests: these are the additional requests performed by
  the user agent (here, the web browser) without any direct
  involvement or knowledge of the user.  For the Web, they are
  triggered by embedded content, Cascading Style Sheets (CSS),
  JavaScript code, embedded images, etc.  In some cases, there can
  be dozens of domain names in different contexts on a single web
  page.

*   Tertiary requests: these are the additional requests performed by
  the DNS system itself.  For instance, if the answer to a query is
  a referral to a set of name servers, and the glue records are not
  returned, the resolver will have to do additional requests to turn
  the name servers' names into IP addresses.  Similarly, even if
  glue records are returned, a careful recursive server will do
  tertiary requests to verify the IP addresses of those records.

   It can be noted also that, in the case of a typical web browser, more
   DNS requests than strictly necessary are sent, for instance, to
   prefetch resources that the user may query later or when
   autocompleting the URL in the address bar.  Both are a big privacy
   concern since they may leak information even about non-explicit
   actions.  For instance, just reading a local HTML page, even without
   selecting the hyperlinks, may trigger DNS requests.

   For privacy-related terms, we will use the terminology from
   [@!RFC6973].

#   Scope

   This document focuses mostly on the study of privacy risks for the
   end user (the one performing DNS requests).  We consider the risks of
   pervasive surveillance [@!RFC7258] as well as risks coming from a more
   focused surveillance.

   This document does not attempt a comparison of specific privacy protections
   provided by individual networks or organisations, it makes only general
   observations about typical current practices.
   
   Privacy risks for the holder of a zone (the risk that someone gets the data)
   are discussed in [@RFC5936] and [@RFC5155].
   
   Privacy risks for recursive operators (including access providers and
   operators in enterprise networks) such as leakage of private namespaces or
   blocklists are out of scope for this document.
   
   Non-privacy risks (e.g security related concerns such as cache poisoning) are
   also out of scope.

   The privacy risks associated with the use of other protocols, e.g.,
   unencrypted TLS SNI extensions or HTTPS destination IP address fingerprinting
   are not considered here.

# Risks

##  The Alleged Public Nature of DNS Data

   It has long been claimed that "the data in the DNS is public".  While
   this sentence makes sense for an Internet-wide lookup system, there
   are multiple facets to the data and metadata involved that deserve a
   more detailed look.  First, access control lists (ACLs) and private
   namespaces notwithstanding, the DNS operates under the assumption
   that public-facing authoritative name servers will respond to "usual"
   DNS queries for any zone they are authoritative for without further
   authentication or authorization of the client (resolver).  Due to the
   lack of search capabilities, only a given QNAME will reveal the
   resource records associated with that name (or that name's non-
   existence).  In other words: one needs to know what to ask for, in
   order to receive a response.  The zone transfer QTYPE [@RFC5936] is
   often blocked or restricted to authenticated/authorized access to
   enforce this difference (and maybe for other reasons).

   Another differentiation to be considered is between the DNS data
   itself and a particular transaction (i.e., a DNS name lookup).  DNS
   data and the results of a DNS query are public, within the boundaries
   described above, and may not have any confidentiality requirements.
   However, the same is not true of a single transaction or a sequence
   of transactions; that transaction is not / should not be public.  A
   typical example from outside the DNS world is: the web site of
   Alcoholics Anonymous is public; the fact that you visit it should not
   be.

##  Data in the DNS Request

   The DNS request includes many fields, but two of them seem particularly
   relevant for the privacy issues: the QNAME and the source IP address. "source
   IP address" is used in a loose sense of "source IP address + maybe source
   port number", because the port number is also in the request and can be used to
   differentiate between several users sharing an IP address (behind a
   Carrier-Grade NAT (CGN) or a NPTv6, for instance [@RFC6269]).

   The QNAME is the full name sent by the user.  It gives information
   about what the user does ("What are the MX records of example.net?"
   means he probably wants to send email to someone at example.net,
   which may be a domain used by only a few persons and is therefore
   very revealing about communication relationships).  Some QNAMEs are
   more sensitive than others.  For instance, querying the A record of a
   well-known web statistics domain reveals very little (everybody
   visits web sites that use this analytics service), but querying the A
   record of www.verybad.example where verybad.example is the domain of
   an organization that some people find offensive or objectionable may
   create more problems for the user.  Also, sometimes, the QNAME embeds
   the software one uses, which could be a privacy issue.  For instance,
   _ldap._tcp.Default-First-Site-Name._sites.gc._msdcs.example.org.
   There are also some BitTorrent clients that query an SRV record for
   _bittorrent-tracker._tcp.domain.example.

   Another important thing about the privacy of the QNAME is the future
   usages.  Today, the lack of privacy is an obstacle to putting
   potentially sensitive or personally identifiable data in the DNS.  At
   the moment, your DNS traffic might reveal that you are doing email
   but not with whom.  If your Mail User Agent (MUA) starts looking up
   Pretty Good Privacy (PGP) keys in the DNS [@RFC7929], then
   privacy becomes a lot more important.  And email is just an example;
   there would be other really interesting uses for a more privacy-friendly DNS.

   For the communication between the stub resolver and the recursive resolver,
   the source IP address is the address of the user's machine. Therefore, all
   the issues and warnings about collection of IP addresses apply here. For the
   communication between the recursive resolver and the authoritative name
   servers, the source IP address has a different meaning; it does not have the
   same status as the source address in an HTTP connection. It is typically the
   IP address of the recursive resolver that, in a way, "hides" the real user.
   However, hiding does not always work. Sometimes EDNS(0) Client subnet
   [@RFC7871] is used (see its privacy analysis in [@denis-edns-client-subnet]).
   Sometimes the end user has a personal recursive resolver on her machine. In
   both cases, the IP address is as sensitive as it is for HTTP [@sidn-entrada].

   A note about IP addresses: there is currently no IETF document that
   describes in detail all the privacy issues around IP addressing.  In
   the meantime, the discussion here is intended to include both IPv4
   and IPv6 source addresses.  For a number of reasons, their assignment
   and utilization characteristics are different, which may have
   implications for details of information leakage associated with the
   collection of source addresses.  (For example, a specific IPv6 source
   address seen on the public Internet is less likely than an IPv4
   address to originate behind an address sharing scheme.)  However, for both
   IPv4 and IPv6 addresses, it is important to note that source addresses
   are propagated with queries and comprise metadata about the host,
   user, or application that originated them.

### Data in the DNS payload

At the time of writing there are no standardized client identifiers contained in
the DNS payload itself (ECS [@RFC7871] while widely used is only of Category
Informational). 

DNS Cookies [@RFC7873] are a lightweight DNS transaction security mechanism that
provides limited protection against a variety of increasingly common
denial-of-service and amplification/forgery or cache poisoning attacks by
off-path attackers. It is noted, however, that they are designed to just verify
IP addresses (and should change once a client's IP address changes), they are
not designed to actively track users (like HTTP cookies).

There are anecdotal accounts of [MAC
addresses]
(https://lists.dns-oarc.net/pipermail/dns-operations/2016-January/014141.html) 
and even user names being inserted in non-standard EDNS(0) options
for stub to resolver communications to support proprietary functionality
implemented at the resolver (e.g., parental filtering).

##  Cache Snooping

   The content of recursive resolvers' caches can reveal data about the
   clients using it (the privacy risks depend on the number of clients).
   This information can sometimes be examined by sending DNS queries
   with RD=0 to inspect cache content, particularly looking at the DNS
   TTLs [@grangeia.snooping].  Since this also is a reconnaissance
   technique for subsequent cache poisoning attacks, some counter
   measures have already been developed and deployed.

##  On the Wire

### Unencrypted Transports

   For unencrypted transports, DNS traffic can be seen by an eavesdropper like
   any other traffic. (DNSSEC, specified in [@RFC4033], explicitly excludes
   confidentiality from its goals.) So, if an initiator starts an HTTPS
   communication with a recipient, while the HTTP traffic will be encrypted, the
   DNS exchange prior to it will not be. When other protocols will become more
   and more privacy-aware and secured against surveillance (e.g., [@?RFC8446],
   [@I-D.ietf-quic-transport]), the use of unencrypted transports for DNS may
   become "the weakest link" in privacy. It is noted that at the time of writing
   there is on-going work attempting to encrypt the SNI in the TLS handshake
   [@I-D.ietf-tls-sni-encryption].

   An important specificity of the DNS traffic is that it may take a
   different path than the communication between the initiator and the
   recipient.  For instance, an eavesdropper may be unable to tap the
   wire between the initiator and the recipient but may have access to
   the wire going to the recursive resolver, or to the authoritative
   name servers.

   The best place to tap, from an eavesdropper's point of view, is
   clearly between the stub resolvers and the recursive resolvers,
   because traffic is not limited by DNS caching.

   The attack surface between the stub resolver and the rest of the
   world can vary widely depending upon how the end user's device is
   configured.  By order of increasing attack surface:

  * The recursive resolver can be on the end user's device.  In
  (currently) a small number of cases, individuals may choose to
  operate their own DNS resolver on their local machine.  In this
  case, the attack surface for the connection between the stub
  resolver and the caching resolver is limited to that single
  machine.

  * The recursive resolver may be at the local network edge.  For
  many/most enterprise networks and for some residential users, the
  caching resolver may exist on a server at the edge of the local
  network.  In this case, the attack surface is the local network.
  Note that in large enterprise networks, the DNS resolver may not
  be located at the edge of the local network but rather at the edge
  of the overall enterprise network.  In this case, the enterprise
  network could be thought of as similar to the Internet Access
  Provider (IAP) network referenced below.

  * The recursive resolver can be in the IAP network. For most residential
  users and potentially other networks, the typical case is for the end
  user's device to be configured (typically automatically through DHCP or
  RA options) with the addresses of the DNS proxy in the CPE, which in turns
  points to the DNS recursive resolvers at the IAP. The attack surface for
  on-the-wire attacks is therefore from the end user system across the
  local network and across the IAP network to the IAP's recursive resolvers.

  * The recursive resolver can be a public DNS service.  Some machines
  may be configured to use public DNS resolvers such as those
  operated by Google Public DNS or OpenDNS.  The end user may
  have configured their machine to use these DNS recursive resolvers
  themselves -- or their IAP may have chosen to use the public DNS
  resolvers rather than operating their own resolvers.  In this
  case, the attack surface is the entire public Internet between the
  end user's connection and the public DNS service.

  It is also noted that typically a device connected *only* to a modern cellular network
  is 
  
  * directly configured with only the recursive resolvers of the IAP and
  * all traffic (including DNS) between the device and the cellular network is
    encrypted following an encryption profile edited by the Third
    Generation Partnership Project ([3GPP](https://www.3gpp.org)).
  
  The attack surface for this specific scenario is not considered here.


### Encrypted Transports

The use of encrypted transports directly mitigates passive surveillance of the
DNS payload, however there are still some privacy attacks possible. This section
enumerates the residual privacy risks to an end user when an attacker can
passively monitor encrypted DNS traffic flows on the wire.

These are cases where user identification, fingerprinting or correlations may be
possible due to the use of certain transport layers or clear text/observable
features. These issues are not specific to DNS, but DNS traffic is susceptible
to these attacks when using specific transports.

There are some general examples, for example, certain studies have highlighted
that IPv4 TTL, IPv6 Hop Limit, or TCP Window sizes [os-fingerprint](http://netres.ec/?b=11B99BD)
values can be used to fingerprint client OS's or that various techniques can be
used to de-NAT DNS queries
[dns-de-nat](https://www.researchgate.net/publication/320322146_DNS-DNS_DNS-based_De-NAT_Scheme).

The use of clear text transport options to optimize latency may also identify a
user, e.g., using TCP Fast Open with TLS 1.2 [@RFC7413].

More specifically, (since the deployment of encrypted transports is not
widespread at the time of writing) users wishing to use encrypted transports for
DNS may in practice be limited in the resolver services available. Given this,
the choice of a user to configure a single resolver (or a fixed set of
resolvers) and an encrypted transport to use in all network environments can
actually serve to identify the user as one that desires privacy and can provide
an added mechanism to track them as they move across network environments.

Users of encrypted transports are also highly likely to re-use sessions for
multiple DNS queries to optimize performance (e.g., via DNS pipelining or HTTPS
multiplexing). Certain configuration options for encrypted transports could
also in principle fingerprint a user or client application. For example:

* TLS version or cipher suite selection
* session resumption
* the maximum number of messages to send or 
* a maximum connection time before closing a connections and re-opening.

Whilst there are known attacks on older versions of TLS the most recent
recommendations [@RFC7525] and developments [@RFC8446] in this
area largely mitigate those.

Traffic analysis of unpadded encrypted traffic is also possible
[@pitfalls-of-dns-encrption] because the sizes and timing of encrypted DNS
requests and responses can be correlated to unencrypted DNS requests upstream
of a recursive resolver.

##  In the Servers

   Using the terminology of [@!RFC6973], the DNS servers (recursive
   resolvers and authoritative servers) are enablers: they facilitate
   communication between an initiator and a recipient without being
   directly in the communications path.  As a result, they are often
   forgotten in risk analysis.  But, to quote again [@!RFC6973], "Although
   [...] enablers may not generally be considered as attackers, they may
   all pose privacy threats (depending on the context) because they are
   able to observe, collect, process, and transfer privacy-relevant
   data."  In [@!RFC6973] parlance, enablers become observers when they
   start collecting data.

   Many programs exist to collect and analyze DNS data at the servers -- from
   the "query log" of some programs like BIND to tcpdump and more sophisticated
   programs like PacketQ [@packetq] and DNSmezzo [@dnsmezzo]. The
   organization managing the DNS server can use this data itself, or it can be
   part of a surveillance program like PRISM [@prism] and pass data to an
   outside observer.

   Sometimes, this data is kept for a long time and/or distributed to
   third parties for research purposes [@ditl] [@day-at-root], security
   analysis, or surveillance tasks.  These uses are sometimes under some
   sort of contract, with various limitations, for instance, on
   redistribution, given the sensitive nature of the data.  Also, there
   are observation points in the network that gather DNS data and then
   make it accessible to third parties for research or security purposes
   ("passive DNS" [@passive-dns]).

###  In the Recursive Resolvers

   Recursive Resolvers see all the traffic since there is typically no
   caching before them.  To summarize: your recursive resolver knows a
   lot about you.  The resolver of a large IAP, or a large public
   resolver, can collect data from many users.

#### Resolver Selection

   Given all the above considerations, the choice of recursive resolver has
   direct privacy considerations for end users. Historically, end user devices
   have used the DHCP-provided local network recursive resolver, which may have
   strong, medium, or weak privacy policies depending on the network. Privacy
   policies for these servers may or may not be available and users need to be
   aware that privacy guarantees will vary with network.

   More recently some networks and end users have actively chosen to use a large
   public resolver instead, e.g., [Google Public
   DNS](https://developers.google.com/speed/public-dns),
   [Cloudflare](https://developers.cloudflare.com/1.1.1.1/setting-up-1.1.1.1/), 
   or [Quad9](https://www.quad9.net). There can be many reasons: cost
   considerations for network operators, better reliability or anti-censorship
   considerations are just a few. Such services typically do provide a privacy
   policy and the end user can get an idea of the data collected by such
   operators by reading one e.g., [Google Public DNS - Your
   Privacy](https://developers.google.com/speed/public-dns/privacy).

   Even more recently some applications have announced plans to deploy
   application-specific DNS settings which might be enabled by default. For
   example, current proposals by Firefox [@firefox] revolve around a default
   based on the geographic region, using a pre-configured list of large public
   resolver services which offer DoH, combined with non-standard probing and
   signalling mechanism to disable DoH in particular networks. Whereas Chrome
   [@chrome] is experimenting with using DoH to the DHCP-provided resolver if it
   is on a list of DoH-compatible providers. At the time of writing, efforts
   to provide standardized signalling mechanisms for applications to discover
   the services offered by local resolvers are in progress
   [@I-D.ietf-dnsop-resolver-information].

   If applications enable application-specific DNS settings without properly
   informing the user of the change (or do not provide an option for user
   configuration of the application's recursive resolver) there is a potential
   privacy issue; depending on the network context and the application default,
   the application might use a recursive server that provides less privacy
   protection than the default network-provided server without the user's full
   knowledge. Users that are fully aware of an application specific DNS setting
   may want to actively override any default in favour of their chosen recursive
   resolver.

   There are also concerns that, should the trend towards using large public
   resolvers increase, this will itself provide a privacy concern, due to a small
   number of operators having visibility of the majority of DNS requests
   globally and the potential for aggregating data across services about a user.
   Additionally the operating organisation of the resolver may be in a different
   legal jurisdiction than the user, which creates further privacy concerns around
   legal protections of and access to the data collected by the operator.

   At the time of writing the deployment models for DNS are evolving, their
   implications are complex and extend beyond the scope of this document. They
   are the subject of much other work including
   [@I-D.livingood-doh-implementation-risks-issues], the [IETF ADD mailing
   list](https://mailarchive.ietf.org/arch/browse/static/add) and the [Encrypted
   DNS Deployment Initiative](https://www.encrypted-dns.org).

####  Active Attacks on Resolver Configuration

  The previous section discussed DNS privacy, assuming that all the traffic
  was directed to the intended servers (i.e those that would be used in the
  absence of an active attack) and that the potential attacker was purely
  passive. But, in reality, we can have active attackers in the network
  redirecting the traffic, not just to observe it but also potentially change
  it.

  For instance, a DHCP server controlled by an attacker can direct you to a
  recursive resolver also controlled by that attacker. Most of the time, it
  seems to be done to divert traffic in order to also direct the user to a web
  server controlled by the attacker. However it could be used just to capture
  the traffic and gather information about you.

  Other attacks, besides using DHCP, are possible. The cleartext traffic from a
  DNS client to a DNS server can be intercepted along its way from originator
  to intended source, for instance, by transparent attacker controlled DNS
  proxies in the network that will divert the traffic intended for a legitimate
  DNS server. This server can masquerade as the intended server and respond
  with data to the client. (Attacker controlled servers that inject malicious
  data are possible, but it is a separate problem not relevant to privacy.) A
  server controlled by an attacker may respond correctly for a long period of
  time, thereby foregoing detection.

  Also, malware like DNSchanger [@dnschanger] can change the recursive resolver
  in the machine's configuration, or the routing itself can be subverted (for
  instance, [@ripe-atlas-turkey]).

#### Blocking of User Selected Services

  User privacy can also be at risk if there is blocking (by local network
  operators or more general mechanisms) of access to remote recursive servers
  that offer encrypted transports when the local resolver does not offer
  encryption and/or has very poor privacy policies. For example, active blocking
  of port 853 for DoT or of specific IP addresses (e.g., 1.1.1.1 or
  2606:4700:4700::1111) could restrict the resolvers available to the user. The
  extent of the risk to end user privacy is highly dependent on the specific
  network and user context; a user on a network that is known to perform
  surveillance would be compromised if they could not access such services,
  whereas a user on a trusted network might have no privacy motivation to do
  so.

  In some cases, networks might block access to remote resolvers for security
  reasons, for example to cripple malware and bots or to prevent data
  exfiltration methods that use encrypted DNS communications as transport. In
  these cases, if the network fully respects user privacy in other ways (i.e.
  encrypted DNS and good data handling policies) the block can serve to further
  protect user privacy by ensuring such security precautions.

  It is also noted that attacks on remote resolver services, e.g., DDoS could
  force users to switch to other services that do not offer encrypted transports
  for DNS.

#### Authentication of Servers

  Both DoH and Strict mode for DoT [@RFC8310] require authentication of the
  server and therefore as long as the authentication credentials are obtained
  over a secure channel then using either of these transports defeats the attack
  of re-directing traffic to rogue servers. Of course attacks on these secure
  channels are also possible, but out of the scope of this document.

#### Encrypted Transports

##### DoT and DoH

Use of encrypted transports does not reduce the data available in the recursive
resolver and ironically can actually expose more information about users to
operators. As mentioned in (#on-the-wire) use of session based encrypted
transports (TCP/TLS) can expose correlation data about users. Such concerns in
the TCP/TLS layers apply equally to DoT and DoH which both use TLS as
the underlying transport, some examples are:

* fingerprinting based on TLS version and/or cipher suite selection
* user tracking via session resumption in TLS 1.2

##### DoH Specific Considerations

Section 8 of [@RFC8484] highlights some of the privacy consideration differences between
HTTP and DNS. As a deliberate design choice DoH inherits the privacy properties
of the HTTPS stack and as a consequence introduces new privacy concerns when
compared with DNS over UDP, TCP or TLS [@RFC7858]. The rationale for this
decision is that retaining the ability to leverage the full functionality of
the HTTP ecosystem is more important than placing specific constraints on this
new protocol based on privacy considerations (modulo limiting the use of HTTP
cookies).

In analyzing the new issues introduced by DoH it is helpful to recognize that
there exists a natural tension between

* the wide practice in HTTP to use various headers to optimize HTTP
  connections, functionality and behaviour (which can facilitate user
  identification and tracking)

* and the fact that the DNS payload is currently very tightly encoded and
  contains no standardized user identifiers.

DoT, for example, would normally contain no client identifiers above
the TLS layer and a resolver would see only a stream of DNS query payloads
originating within one or more connections from a client IP address. Whereas if
DoH clients commonly include several headers in a DNS message (e.g., user-agent
and accept-language) this could lead to the DoH server being able to identify
the source of individual DNS requests not only to a specific end user device
but to a specific application.

Additionally, depending on the client architecture, isolation of DoH queries
from other HTTP traffic may or may not be feasible or desirable. Depending on
the use case, isolation of DoH queries from other HTTP traffic may or may not
increase privacy.

The picture for privacy considerations and user expectations for DoH with
respect to what additional data may be available to the DoH server compared to
DNS over UDP, TCP or TLS is complex and requires a detailed analysis for each
use case. In particular the choice of HTTPS functionality vs privacy is
specifically made an implementation choice in DoH and users may well have
differing privacy expectations depending on the DoH use case and implementation.

At the extremes, there may be implementations that attempt to achieve parity
with DoT from a privacy perspective at the cost of using no
identifiable headers, there might be others that provide feature rich data flows
where the low-level origin of the DNS query is easily identifiable.

Privacy focused users should be aware of the potential for additional client
identifiers in DoH compared to DoT and may want to only use DoH client
implementations that provide clear guidance on what identifiers they add.

###  In the Authoritative Name Servers

   Unlike what happens for recursive resolvers, observation capabilities of
   authoritative name servers are limited by caching; they see only the requests
   for which the answer was not in the cache. For aggregated statistics ("What
   is the percentage of LOC queries?"), this is sufficient, but it prevents an
   observer from seeing everything. Similarly the increasing deployment of QNAME
   minimisation [@ripe-qname-measurements] reduces the data visible at the
   authoritative name server. Still, the authoritative name servers see a part
   of the traffic, and this subset may be sufficient to violate some privacy
   expectations.

   Also, the end user typically has some legal/contractual link with the
   recursive resolver (he has chosen the IAP, or he has chosen to use a
   given public resolver), while having no control and perhaps no
   awareness of the role of the authoritative name servers and their
   observation abilities.

   As noted before, using a local resolver or a resolver close to the
   machine decreases the attack surface for an on-the-wire eavesdropper.
   But it may decrease privacy against an observer located on an
   authoritative name server.  This authoritative name server will see
   the IP address of the end client instead of the address of a big
   recursive resolver shared by many users.

   This "protection", when using a large resolver with many clients, is
   no longer present if ECS [@RFC7871] is used because, in this case,
   the authoritative name server sees the original IP address (or
   prefix, depending on the setup).

   As of today, all the instances of one root name server, L-root,
   receive together around 50,000 queries per second.  While most of it
   is "junk" (errors on the Top-Level Domain (TLD) name), it gives an
   idea of the amount of big data that pours into name servers.  (And
   even "junk" can leak information; for instance, if there is a typing
   error in the TLD, the user will send data to a TLD that is not the
   usual one.)

   Many domains, including TLDs, are partially hosted by third-party
   servers, sometimes in a different country.  The contracts between the
   domain manager and these servers may or may not take privacy into
   account.  Whatever the contract, the third-party hoster may be honest
   or not but, in any case, it will have to follow its local laws.  So,
   requests to a given ccTLD may go to servers managed by organizations
   outside of the ccTLD's country.  End users may not anticipate that,
   when doing a security analysis.

   Also, it seems (see the survey described in [@aeris-dns]) that there
   is a strong concentration of authoritative name servers among
   "popular" domains (such as the Alexa Top N list).  For instance,
   among the Alexa Top 100K, one DNS provider hosts today 10% of the
   domains.  The ten most important DNS providers host together one
   third of the domains.  With the control (or the ability to sniff the
   traffic) of a few name servers, you can gather a lot of information.


##  Re-identification and Other Inferences

   An observer has access not only to the data he/she directly collects but also
   to the results of various inferences about this data. The term 'observer'
   here is used very generally, it might be one that is passively observing
   cleartext DNS traffic, one in the network that is actively attacking the user
   by re-directing DNS resolution, or it might be a local or remote resolver
   operator.

   For instance, a user can be re-identified via DNS queries.  If the
   adversary knows a user's identity and can watch their DNS queries for
   a period, then that same adversary may be able to re-identify the
   user solely based on their pattern of DNS queries later on regardless
   of the location from which the user makes those queries.  For
   example, one study [@herrmann-reidentification] found that such re-
   identification is possible so that "73.1% of all day-to-day links
   were correctly established, i.e., user u was either re-identified
   unambiguously (1) or the classifier correctly reported that u was not
   present on day t+1 any more (2)."  While that study related to web
   browsing behavior, equally characteristic patterns may be produced
   even in machine-to-machine communications or without a user taking
   specific actions, e.g., at reboot time if a characteristic set of
   services are accessed by the device.

   For instance, one could imagine that an intelligence agency
   identifies people going to a site by putting in a very long DNS name
   and looking for queries of a specific length.  Such traffic analysis
   could weaken some privacy solutions.

   The IAB privacy and security program also have a work in progress
   [@RFC7624] that considers such inference-based attacks in a more
   general framework.

##  More Information

   Useful background information can also be found in [@tor-leak] (about
   the risk of privacy leak through DNS) and in a few academic papers:
   [@yanbin-tsudik], [@castillo-garcia], [@fangming-hori-sakurai], and
   [@federrath-fuchs-herrmann-piosecny].

#  Actual "Attacks"

   A very quick examination of DNS traffic may lead to the false
   conclusion that extracting the needle from the haystack is difficult.
   "Interesting" primary DNS requests are mixed with useless (for the
   eavesdropper) secondary and tertiary requests (see the terminology in
   Section 1).  But, in this time of "big data" processing, powerful
   techniques now exist to get from the raw data to what the
   eavesdropper is actually interested in.

   Many research papers about malware detection use DNS traffic to
   detect "abnormal" behavior that can be traced back to the activity of
   malware on infected machines.  Yes, this research was done for the
   good, but technically it is a privacy attack and it demonstrates the
   power of the observation of DNS traffic.  See [@dns-footprint],
   [@dagon-malware], and [@darkreading-dns].

   Passive DNS systems [@passive-dns] allow reconstruction of the data of
   sometimes an entire zone.  They are used for many reasons -- some
   good, some bad.  Well-known passive DNS systems keep only the DNS
   responses, and not the source IP address of the client, precisely for
   privacy reasons.  Other passive DNS systems may not be so careful.
   And there is still the potential problems with revealing QNAMEs.

   The revelations from the Edward Snowden documents, which were leaked from the
   National Security Agency (NSA) provide evidence of the use of
   the DNS in mass surveillance operations [@morecowbell]. For example the
   MORECOWBELL surveillance program, which uses a dedicated covert monitoring
   infrastructure to actively query DNS servers and perform HTTP requests to
   obtain meta information about services and to check their availability.
   Also the QUANTUMTHEORY project which includes detecting lookups for certain
   addresses and injecting bogus replies is another good example showing that
   the lack of privacy protections in the DNS is actively exploited.


#  Legalities

   To our knowledge, there are no specific privacy laws for DNS data, in any
   country. Interpreting general privacy laws like [@data-protection-directive]
   or [GDPR](https://www.eugdpr.org/the-regulation.html) applicable in the
   European Union in the context of DNS traffic data is not an easy task, and
   we do not know a court precedent here. See an interesting analysis in
   [@sidn-entrada].


#  Security Considerations

   This document is entirely about security, more precisely privacy. It just
   lays out the problem; it does not try to set requirements (with the choices
   and compromises they imply), much less define solutions. Possible solutions
   to the issues described here are discussed in other documents (currently too
   many to all be mentioned); see, for instance, 'Recommendations for DNS
   Privacy Operators' [@I-D.ietf-dprive-bcp-op].

# IANA Considerations

This document makes no requests of the IANA.

# Acknowledgments

   Thanks to Nathalie Boulvard and to the CENTR members for the original work
   that led to this document. Thanks to Ondrej Sury for the interesting
   discussions. Thanks to Mohsen Souissi and John Heidemann for proofreading and
   to Paul Hoffman, Matthijs Mekking, Marcos Sanz, Tim Wicinski, Francis Dupont,
   Allison Mankin, and Warren Kumari for proofreading, providing technical
   remarks, and making many readability improvements. Thanks to Dan York,
   Suzanne Woolf, Tony Finch, Stephen Farrell, Peter Koch, Simon Josefsson, and
   Frank Denis for good written contributions. Thanks to Vittorio Bertola and
   Mohamed Boucadair for a detailed review of the -bis. And thanks to the IESG
   members for the last remarks.

# Changelog

draft-ietf-dprive-rfc7626-bis-02

* Address 2 minor nits (typo and add IANA section)

draft-ietf-dprive-rfc7626-bis-02

* Numerous editorial corrections thanks to Mohamed Boucadair and
  * Minor additions to Scope section
  * New text on cellular network DNS
* Additional text from Vittorio Bertola on blocking and security

draft-ietf-dprive-rfc7626-bis-01

* Re-structure section 3.5 (was 2.5) 
  * Collect considerations for recursive resolvers together
  * Re-work several sections here to clarify their context (e.g., ‘Rogue servers' becomes ‘Active attacks on resolver configuration’)
  * Add discussion of resolver selection
* Update text and old reference on Snowdon revelations.
* Add text on and references to QNAME minimisation RFC and deployment measurements
* Correct outdated references
* Clarify scope by adding a Scope section (was Risks overview)
* Clarify what risks are considered in section 3.4.2

draft-ietf-dprive-rfc7626-bis-00

* Rename after WG adoption
* Use DoT acronym throughout
* Minor updates to status of deployment and other drafts

draft-bortzmeyer-dprive-rfc7626-bis-02

* Update various references and fix some nits.

draft-bortzmeyer-dprive-rfc7626-bis-01

* Update reference for dickinson-bcp-op to draft-dickinson-dprive-bcp-op

draft-borztmeyer-dprive-rfc7626-bis-00:

Initial commit.  Differences to RFC7626:

*  Update many references
*  Add discussions of encrypted transports including DoT and DoH
*  Add section on DNS payload
*  Add section on authentication of servers
*  Add section on blocking of services

<reference anchor="chrome" target="https://blog.chromium.org/2019/09/experimenting-with-same-provider-dns.html">
<front>
<title>Experimenting with same-provider DNS-over-HTTPS upgrade</title>
<author fullname="Kenji Baheux" surname="Baheux"/>
<date month="September" year="2019"/>
</front>
</reference>

<reference anchor="firefox" target="https://blog.mozilla.org/futurereleases/2019/09/06/whats-next-in-making-dns-over-https-the-default/">
<front>
<title>What’s next in making Encrypted DNS-over-HTTPS the Default</title>
<author fullname="Selena Deckelmann" surname="Deckelmann"/>
<date month="September" year="2019"/>
</front>
</reference>

<reference anchor="os-fingerprint" target="http://www.netresec.com/?page=Blog&month=2011-11&post=Passive-OS-Fingerprinting">
<front>
<title>Passive OS Fingerprinting</title>
<author fullname="netresec" surname="netresec"/>
<date/>
</front>
</reference>

<reference anchor="pitfalls-of-dns-encrption" target="https://dl.acm.org/citation.cfm?id=2665959">
<front>
<title>Pretty Bad Privacy:Pitfalls of DNS Encryption</title>
<author fullname="Haya Shulman" surname="Shulman" initials="H"/>
<date/>
</front>
</reference>

<reference anchor="denis-edns-client-subnet" target="https://00f.net/2013/08/07/edns-client-subnet/">
<front>
<title>Security and privacy issues of edns-client-subnet</title>
<author fullname="Frank Denis" surname="Denis" initials="F"/>
<date month="August" year="2013"/>
</front>
</reference>

<reference anchor="dagon-malware" target="https://www.dns-oarc.net/files/workshop-2007/Dagon-Resolution-corruption.pdf">
<front>
<title>Corrupted DNS Resolution Paths: The Rise of a Malicious
Resolution Authority</title>
<author surname="Dagon" initials="D." fullname="David Dagon"/>
<date year="2007"/>
</front>
<seriesInfo name="ISC/OARC" value="Workshop"/>
</reference>

<reference anchor="dns-footprint" target="https://www.dns-oarc.net/files/workshop-201010/OARC-ers-20101012.pdf">
<front>
<title>DNS Footprint of Malware</title>
<author fullname="Ed Stoner" surname="Stoner" initials="E."/>
<date month="October" year="2010"/>
</front>
<seriesInfo name="OARC" value="Workshop"/>
</reference>

<reference anchor="morecowbell"
	   target="https://pdfs.semanticscholar.org/2610/2b99bdd6a258a98740af8217ba8da8a1e4fa.pdf">
<front>
<title>NSA's MORECOWBELL: Knell for DNS</title>
<author fullname="Christian Grothoff" surname="Grothoff" initials="C."/>
<author fullname="Matthias Wachs" surname="Wachs" initials="M."/>
<author fullname="Monika Ermert" surname="Ermert" initials="M."/>
<author fullname="Jacob Appelbaum" surname="Appelbaum" initials="J."/>
<date month="January" year="2015"/>
<abstract>
<t>Detailed technical analysis of the MORECOWBELL program, followed by
opinions about the future of the DNS and the needs for alternate
systems. Stable GNUnet identifier <eref target="gnunet://fs/chk/RSVKSQXNKSHYAD518W1CQ79S2FGRYAR7CM7MMEBFTXJ677DVJQN8HR3TR0K544Y050THXM6KZ0ZV6BP3NM31P90ZDGXYTX21MNV50W8.1XBPZ4MVFQCDY914S1HB7S8VSYDPCXB0XEY50D6ZK0V30C7N39QFKX2AXW8EW9M8HCCPR6EEEN89D9G6Y8NS7DJMV1TPQXW22E9QWHR.968272"/></t>
</abstract>
</front>
<seriesInfo name="GNUnet" value="e.V."/>
</reference>

<reference anchor="darkreading-dns" target="http://www.darkreading.com/analytics/security-monitoring/got-malware-three-signs-revealed-in-dns-traffic/d/d-id/1139680">
<front>
<title>Got Malware? Three Signs Revealed In DNS Traffic</title>
<author fullname="Robert Lemos" surname="Lemos" initials="R."/>
<date month="May" year="2013"/>
<abstract>
<t>Monitoring your network's requests for domain lookups can reveal
network problems and potential malware infections.</t>
</abstract>
</front>
<seriesInfo name="InformationWeek" value="Dark Reading"/>
</reference>

<reference anchor="dnschanger" target="https://en.wikipedia.org/w/index.php?title=DNSChanger&amp;oldid=578749672">
<front>
<title>DNSChanger</title>
<author><organization>Wikipedia</organization></author>
<date month="October" year="2013"/>
</front>
</reference>

<reference anchor="packetq" target="https://github.com/DNS-OARC/PacketQ">
<front>
<title>PacketQ, a simple tool to make SQL-queries against PCAP-files</title>
<author><organization>DNS-OARC</organization></author>
<date year="2011"/>
<abstract><t>A tool that provides a basic SQL-frontend to
PCAP-files. Outputs JSON, CSV and XML and includes a build-in
webserver with JSON-api and a nice looking AJAX GUI.</t></abstract>
</front>
</reference>

<!--Note: URL is being fixed - check before publication-->
<reference anchor="dnsmezzo" target="http://www.dnsmezzo.net/">
<front>
<title>DNSmezzo</title>
<author fullname="Stephane Bortzmeyer" surname="Bortzmeyer" initials="S."/>
<date year="2009"/>
<abstract><t>DNSmezzo is a framework for the capture and analysis of DNS packets. It allows the manager of a DNS name server to get information such as the top N domains requests, the percentage of IPv6 queries, the most talkative clients, etc. It is part of the broader program DNSwitness.</t></abstract>
</front>
</reference>

<reference anchor="prism" target="https://en.wikipedia.org/w/index.php?title=PRISM_(surveillance_program)&amp;oldid=673789455">
<front>
<title>PRISM (surveillance program)</title>
<author><organization>Wikipedia</organization></author>
<date month="July" year="2015"/>
</front>
</reference>

<reference anchor="grangeia.snooping"
	   target="https://www.semanticscholar.org/paper/Cache-Snooping-or-Snooping-the-Cache-for-Fun-and-1-Grangeia/9b22f606e10b3609eafbdcbfc9090b63be8778c3">
  <front>
    <title>DNS Cache Snooping or Snooping the Cache for Fun and
    Profit</title>
    <author fullname="Luis Grangeia" surname="Grangeia"
	    initials="L."/>
    <date  year="2005"/>
  </front>
</reference>
  
<reference anchor="ditl" target="http://www.caida.org/projects/ditl/">
<front>
<title>A Day in the Life of the Internet (DITL)</title>
<author><organization>CAIDA</organization></author>
<date year="2002"/>
<abstract>
<t>CAIDA, ISC, DNS-OARC, and many partnering root nameserver operators
and other organizations to coordinate and conduct large-scale,
simultaneous traffic data collection events with the goal of capturing
datasets of strategic interest to researchers. Over the last several
years, we have come to refer to this project and related activities as
"A Day in the Life of the Internet" (DITL).</t>
</abstract>
</front>
</reference>

<reference anchor="day-at-root"
	   target="http://www.sigcomm.org/sites/default/files/ccr/papers/2008/October/1452335-1452341.pdf">
<front>
<title>A Day at the Root of the Internet</title>
<author fullname="Sebastian Castro" initials="S." surname="Castro"/>
<author fullname="Duane Wessels" initials="D." surname="Wessels"/>
<author fullname="Marina Fomenkov" initials="M." surname="Fomenkov"/>
<author fullname="Kimberly Claffy" initials="K." surname="Claffy"/>
<date month="October" year="2008"/>
</front>
<seriesInfo name='ACM SIGCOMM Computer Communication Review,' value='Vol. 38, Number 5'/>
<seriesInfo name="DOI" value="10.1145/1452335.1452341"/>
</reference>

<reference anchor="ripe-atlas-turkey" target="https://labs.ripe.net/Members/emileaben/a-ripe-atlas-view-of-internet-meddling-in-turkey">
<front>
<title>A RIPE Atlas View of Internet Meddling in Turkey</title>
<author fullname="Emile Aben" initials="E." surname="Aben"><organization>RIPE NCC</organization></author>
<date month="March" year="2014"/>
</front>
</reference>

<reference anchor="ripe-qname-measurements" target="https://labs.ripe.net/Members/wouter_de_vries/make-dns-a-bit-more-private-with-qname-minimisation">
<front>
<title>Making the DNS More Private with QNAME Minimisation</title>
<author fullname="Wouter de Vries " initials="W. de Vries "><organization>University of Twente</organization></author>
<date month="April" year="2019"/>
</front>
</reference>


<reference anchor="data-protection-directive" target="http://eur-lex.europa.eu/LexUriServ/LexUriServ.do?uri=CELEX:31995L0046:EN:HTML">
<front>
<title>Directive 95/46/EC of the European Pariament and of the council on the protection of individuals
with regard to the processing of personal data and on the free
movement of such data</title>
<author><organization>European Parliament</organization></author>
<date month="November" year="1995"/>
</front>
<seriesInfo name='Official Journal L 281,' value='pp. 0031 - 0050' />
</reference>

<reference anchor="passive-dns" target="https://www.first.org/conference/2005/papers/florian-weimer-slides-1.pdf">
<front>
<title>Passive DNS Replication</title>
<author fullname="Florian Weimer" initials="F." surname="Weimer"/>
<date month="April" year="2005"/>
<abstract>
<t>FIRST 17</t>
</abstract>
</front>
</reference>

<reference anchor="tor-leak" target="https://www.torproject.org/docs/faq.html.en#WarningsAboutSOCKSandDNSInformationLeaks">
<front>
<title>DNS leaks in Tor</title>
<author><organization>Tor</organization></author>
<date year="2013"/>
</front>
</reference>

<reference anchor="yanbin-tsudik" target="http://arxiv.org/abs/0910.2472">
<front>
<title>Towards Plugging Privacy Leaks in the Domain Name System</title>
<author fullname="Yanbin Lu" surname="Yanbin" initials="L."/>
<author fullname="Gene Tsudik" surname="Tsudik" initials="G."/>
<date month="October" year="2009"/>
<abstract>
<t>Peer-to-peer computing (p2p), 2010 IEEE tenth
international conference on, IEEE, Piscataway, NJ, USA, 25 August 2010
(2010-08-25), pages 1-10, XP031752227, ISBN: 978-1-4244-7140-9</t>
<t>Actually, it is not about the DNS but about a complete replacement, using DHTs for resolution.</t>
</abstract></front>
</reference>

<reference anchor="castillo-garcia" target="http://deic.uab.es/~joaquin/papers/is08.pdf">
<front>
<title>Anonymous Resolution of DNS Queries</title>
<author initials="S." surname="Castillo-Perez" fullname="S. Castillo-Perez"/>
<author initials="J." surname="Garcia-Alfaro" fullname="J.Garcia-Alfaro"/>
<date year="2008"/>
<abstract>
<t>OTM 2008 Confederated International Conferences, CoopIS, DOA, GADA, IS, and ODBASE 2008, Monterrey, Mexico, November 9-14, 2008, Proceedings</t>
<t>Focus on ENUM privacy risks. A suggested solution is to add gratuitous queries, in order to hide the real ones.</t>
</abstract>
</front>
</reference>

<reference anchor="fangming-hori-sakurai"
	   target="http://dl.acm.org/citation.cfm?id=1262690.1262986">
<front>
<title>Analysis of Privacy Disclosure in DNS Query</title>
<author fullname="Fangming Zhao" surname="Fangming" initials="Z."/>
<author fullname="Yoshiaki Hori" surname="Hori" initials="Y."/>
<author fullname="Kouichi Sakurai" surname="Sakurai" initials="K."/>
<date month="April" year="2007"/>
<abstract>
<t>Not available online.</t>
</abstract>
</front>
<seriesInfo name="2007 International Conference on Multimedia and Ubiquitous Engineering (MUE 2007)," value="Seoul, Korea"/>
<seriesInfo name='ISBN: 0-7695-2777-9,' value='pp. 952-957' />
<seriesInfo name="DOI" value="10.1109/MUE.2007.84"/>
</reference>

<reference anchor="thomas-ditl-tcp"
	   target="https://indico.dns-oarc.net/event/20/session/2/contribution/15/material/slides/1.pdf">
<front>
<title>An Analysis of TCP Traffic in Root Server DITL Data</title>
<author fullname="Matt Thomas" surname="Thomas" initials="M."/>
<author fullname="Duane Wessels" surname="Wessels" initials="D."/>
<date month="October" year="2014"/>
</front>
<seriesInfo name="DNS-OARC" value="2014 Fall Workshop"/>
</reference>

<reference anchor="federrath-fuchs-herrmann-piosecny" target="https://svs.informatik.uni-hamburg.de/publications/2011/2011-09-14_FFHP_PrivacyPreservingDNS_ESORICS2011.pdf">
<front>
<title>Privacy-Preserving DNS: Analysis of Broadcast, Range Queries and Mix-based Protection Methods</title>
<author fullname="Hannes Federrath" surname="Federrath" initials="H."/>
<author fullname="Karl-Peter Fuchs" surname="Fuchs" initials="K.-P."/>
<author fullname="Dominik Herrmann" surname="Herrmann" initials="D."/>
<author fullname="Christopher Piosecny" surname="Piosecny" initials="C."/>
<date year="2011"/>
<abstract>
<t>Privacy is improved by broadcasting of the most common names plus mixes (a Tor-like routing system).</t>
</abstract>
</front>

<seriesInfo name="Computer Security ESORICS 2011," value="Springer"/>
<seriesInfo name="page(s)" value="665-683"/>
<seriesInfo name="ISBN" value="978-3-642-23821-5"/>

</reference>

<reference anchor="aeris-dns" target="https://blog.imirhil.fr/vie-privee-et-le-dns-alors.html">
<front>
<title>Vie privee: et le DNS alors?</title>
<author fullname="Nicolas Vinot" surname="Vinot" initials="N."/>
<date year="2015"/>
<abstract>
<t>A survey of the DNS privacy issues, specifically from the point of
view of the concentration in DNS providers. With data drawn from a DNS
harvest of Alexa Top N's authoritative name servers.
</t>
</abstract>
</front>
<seriesInfo name="(In" value="French)"/>
</reference>

<reference anchor="herrmann-reidentification"
	   target="http://epub.uni-regensburg.de/21103/1/Paper_PUL_nordsec_published.pdf">
  <front>
    <title>Analyzing Characteristic Host Access Patterns for Re-Identification of
    Web User Sessions</title>
    <author fullname="Dominik Herrmann" surname="Herrmann" initials="D."/>
    <author fullname="Christoph Gerber" surname="Gerber" initials="C."/>
    <author fullname="Christian Banse" surname="Banse" initials="C."/>
    <author fullname="Hannes Federrath" surname="Federrath" initials="H."/>
    <date year="2012"/>
    <abstract>
      <t>Abstract. An attacker, who is able to observe a web user over a long
period of time, learns a lot about his interests. It may be difficult to
track users with regularly changing IP addresses, though. We show how
patterns mined from web traffic can be used to re-identify a majority
of users, i. e. link multiple sessions of them. </t>
    </abstract>
  </front>
<seriesInfo name="DOI" value="10.1007/978-3-642-27937-9_10"/>
</reference>

<reference anchor="sidn-entrada" target="https://www.sidnlabs.nl/downloads/yBW6hBoaSZe4m6GJc_0b7w/2211058ab6330c7f3788141ea19d3db7/SIDN_Labs_Privacyraamwerk_Position_Paper_V1.4_ENG.pdf">
<front>
<title>A privacy framework for 'DNS big data' applications</title>
<author fullname="Cristian Hesselman" surname="Hesselman" initials="C."/>
<author fullname="Jelte Jansen" surname="Jansen" initials="J."/>
<author fullname="Maarten Wullink" surname="Wullink" initials="M."/>
<author fullname="Karin Vink" surname="Vink" initials="K."/>
<author fullname="Maarten Simon" surname="Simon" initials="M."/>
<date month="November" year="2014"/>
  <abstract><t>A good analysis of DNS privacy, with quantitative
  measurements showing that, "for the great majority of resolvers, therefore,
the associated IP address is personal data", and a privacy policy for
big data analysis.</t></abstract>
</front>
</reference>

{backmatter}
