# Meta

The canonical, 'up-to-date' version is located at https://github.com/iSECPartners/LibTech-Auditing-Cheatsheet You are encouraged to improve the document and submit pull requests.

The README.md document may be converted to html using ./build_html.py The HTML version contains minor formatting changes not possible in markdown. The Markdown version should be edited and is considered authoritative.  

The Github-styled markdown version of the document is generally sufficient, although formatting in Appendix A is improved in the HTML version.

# Introduction 

This list is intended to be a list of additional or more technical things to look for when auditing extremely high value applications. The applications may involve operational security for involved actors (such as law enforcement research), extremely valuable transactions (such as a Stock Trading Application), societal issues that could open users to physical harassment (such as a Gay Dating Application), or technologies designed to be used by journalists operating inside repressive countries.

It is an **advanced** list - meaning entry level issues such as application logic bypasses, common web vulnerabilities such as XSS and SQLi, or lower level vulnerabilities such as memory corruption are explicitly not covered. It is assumed that the reader is aware of these and similar vulnerabilities and is well trained in their search, exploitation, and remediation.

A good example of the type of analysis to strive for can be shown in Jacob Appelbaum's analysis of UltraSurf: https://media.torproject.org/misc/2012-04-16-ultrasurf-analysis.pdf 

# The Stuff

## Documentation

* **Threat Model**. Has the project documented what they intend to protect themselves from, and what they do not intend to protect themselves from?
    * If not, they probably haven't given much thought to what attacks may be possible to defend against and what attacks are not.  
    * For example: Tor explicitly does not defend against end-to-end correlation: if an attacker can monitor a user (e.g. a user in the US) and the site they are connecting to (e.g. a site hosted at Amazon EC2 East Coast) it's assumed it's game over, and the attacker can de-anonymize the user. No complicated defenses will be taken. For this reason, tagging attacks are also not defended against.
        * Some other example Threat Models:
            * https://svn.torproject.org/svn/projects/design-paper/tor-design.html#subsec:threat-model
            * https://gitweb.torproject.org/obfsproxy.git/blob/HEAD:/doc/obfs2/threat-model.txt
            * https://www.torproject.org/projects/torbrowser/design/
    * Some common threat model questions:
        * Do you intend to protect against forensic analysis of a disk to determine what activities a user has participated in using the software?
        * Do you intend to protect against forensic analysis of a disk to determine if a user had installed the software (and subsequently uninstalled it)?
        * Do you intend to disguise the use of the software to an adversary who can monitor the user's network connection?
             * If they say "Yes" they are almost certainly unable to accomplish this, and you should be able to find a few ways to break this.
        * Do you intend to disguise the activities of a user using the software from an adversary who can monitor the user's network connection?
* Does the application have a **Protocol Specification**?
    * If an application uses a custom protocol, it should be documented to the level that you would feel comfortable producing an interoperating client from _only_ the specification with no reference to the code. Code is not specification. Code comments are not specification.
    * Any deviation from the protocol specification (even if superficial or without security effect) should be noted
    * Anytime the application accepts data that deviates from the specification should probably be noted.
    * Anytime the application does not accept data valid according to the specification should also probably be noted. 
        * These last two are why we have HTML/SSL problems on the Internet: 
        * Web browsers will happily display documents even if they have no opening <html> or <body> tags, <b><i>intermixed</b></i> tags, and <u>dangling tags.  Incredible complexity was introduced in these loose parsers; upgrading them is fraught with furious peril, holding back security fixes.
        * In SSL's case, it states if you receive a version number greater than what you can handle, or an extension you don't recognize, you should be able to handle it gracefully. But many products don't, and thus web browsers perform a fallback to a lesser protocol version, and no extensions to accommodate these products. This allows an attacker to silently downgrade your SSL protocol version!
        * Thus, the application should be able to gracefully handle any way data can be formatted according to the spec; and that it generally should not loosely accept incorrectly formatted data, *especially* when it is the first or major implementation of the protocol.
* TODOs, FIXMEs, HACKs, or XXXs
    * If code contains comments to these effects, the code should be investigated thoroughly (duh) and there should probably be a corresponding issue in the project's bugtracker.
* Is project documentation kept up to date?
* Does the software provide extremely simple, easy-to-understand instructions for use, discouraging bad practices and performing necessary verification checks?
    * Example: https://www.torproject.org/download/download-easy.html.en#warning
* Are risks documented to users? 
    * Does the software take efforts to explain what the product does and doesn't provide, and under what environments (e.g. corporate) the software grants no protection?
        * Examples: Chrome Incognito mode, Tor
* Does the project conduct usability studies about how users actually use the software and whether they put themselves at risk by doing so?

## Service Administration

* Do the administrators of the system enjoy a privileged position in relation to other users of the product or protocol?
    * Are they able to perform additional traffic analysis on users?
    * Do the protocols break down when a member of the protocol is also the service administrator?
    * This position may be enjoyed by attackers who can monitor or subvert the administrative network (internally or externally).
* What systems are in place to restrict privileged individuals...
    * From fully subverting the system?
    * From gaining access to user account information?
    * From gaining access to web server logs?
* With what ease can the system deliver backdoored or malicious code to users?
    * Does the application interpret code and execute it at runtime?
    * Does the application run on the provider's servers?
    * Does the application auto-update?
* What technical and policy-based access control mechanisms are in place to segregate differently-privileged users?
* How is the service hosted, and what additional privileged users are granted access by the choice of hosting?  
    * What do they gain access to and what are they restricted from?
* What is the application 'stack' of the service, including Operating System, language, frameworks, libraries, and modules? Are they publically disclosed? How popular/secure are they?
* What additional services are running on machines that see privileged user information?
* In what jurisdiction is the service hosted?

## Network Fingerprinting

* Any permanent settings unique to a client (or customizable) that persist may be used to track users across networks. 
    * Even in the case where a setting does not uniquely identify a user, it will partition the user into a subset of all users, reducing all users' anonymity.
    * Some examples to illustrate this topic:
        * A user may enable the Do Not Track header. The user visits a website, and the attacker observes they have set the header. When attempting to track this user in the future, they can assume the user will still have the header set.
        * A banner case: IPv6 addresses. In the initial design, the last /64 of your IP address was calculated from your MAC address. MACs are globally unique, and the odds of anyone else having the same /64 were low. Thus, even moving to the other side of the planet and installing a new operating system would allow your laptop to be correlated by a website operator with IP address logs.
        * A client chooses three random servers to talk to for the lifespan of an installation (or a set period of time). These three random servers can identify the client potentially uniquely (at the very least to a subset of users) because an adversary who can observe a client on different networks will see connections to servers A, F, and X only from this (or a subset of) client(s). This is easy for state-level adversaries.
        * SSL Session Resumption may even qualify depending on the threat model. If a server gives a user a ticket on IP address X, and tracks that ticket, and then sees it come from IP address Y - it knows these two IPs belong to the same client.
* Depending on the application's threat model, the application may try to avoid a network operator being able to fingerprint the use of the application
    * This is extremely difficult if not impossible. Usually it's just getting to a 'best case' situation. If you're really interested or need to go deep into this, you can read about Tor bridges and how Tor has tried to avoid censorship in countries such as China, Ethiopia and Iran.
        * http://www.cs.kau.se/philwint/pdf/usenix-login-2012.pdf 
        * https://trac.torproject.org/projects/tor/ticket/7141 
        * https://trac.torproject.org/projects/tor/ticket/6045 
        * https://gitweb.torproject.org/tor.git/commit/5ed73e3807d90dd0a3 
        * In General: https://censorshipwiki.torproject.org
    * Does the application run on non-standard ports or talk to unchanging IP addresses? Are the central communication IPs known and/or enumerable? If so, a network operator can hardcode these IPs and blacklist them.
    * Does the application communicate anything in plaintext, or make plaintext queries *about* the application? 
        * If an application makes a SSL connection, but sends a server certificate with a common name of "Super Secret Anonymity Service" - a network operator can filter on that (plaintext) SSL certificate.
        * If the service makes a DNS request to supersecretanonymityservice.com - even if the rest of the protocol is unfingerprintable, that (plaintext) DNS request gave it away.
        * If the service smuggles a SSL certificate in somehow, but the application makes an OCSP request supersecretanonymityservice.com - that OCSP request is visible in plaintext.
    * Does the application use a nonstandard, unique, or uncommon cryptographic handshake and/or protocol?
        * Unfortunately, any new protocol developed that is unlike anything else would be fingerprintable. Even if it was fully random data with no structure - that itself is rare and fingerprintable.
        * The best case scenario is to disguise a protocol as a normal Web Browser using SSL, perhaps SSH, streaming flash video, Skype, or something similar.
        * This is difficult, but is being actively researched. See: 
            * https://www.torproject.org/projects/obfsproxy 
            * http://cacr.uwaterloo.ca/techreports/2012/cacr2012-08.pdf 
    * Does the application take the standard approach of just using SSL? Is there anything unique about the SSL handshake that can be identified?
        * Unique and Constant set of Ciphersuites and/or extensions?
        * SSL Certificate Hostname
        * Performing a renegotiation immediately after a connection (Tor does this).
        * See also: the four Tor-related links above
* Are the version or features of the application distinguishable to an adversary who can observe network traffic?

## Application Traces

* If a user uses a tool, and uninstalls it - does it leave a trace on the filesystem?
    * This should be mentioned in the threat model explicitly.
    * Directories or Registry Keys left behind?
    * Cached Data or Temporary Files?
    * Most tools do not securely wipe themselves in the uninstall (and indeed cannot do it completely) but depending on the threat model it may be desirable to consider this.
* Does the application log information?
    * How verbose is it by default? Is it necessary?
* Does the application cache sensitive data to disk?
    * Does the application take steps to prevent sensitive data in memory from being swapped to disk?
* Does the application securely zero memory for sensitive data before free()-ing it?
    * Does it use a cleanse function instead of memset, which may be optimized out by the compiler? See http://www.viva64.com/en/b/0178/ 
* What sensitive information is exposed if the user has malware?
    * What information can a keylogger or screengrabber see?
    * Can the malware access sensitive stored data? (All the time? Some of the time?)

## Cryptography - Generic

* If they've written their own protocol there's probably a lot that can be fiddled with. Writing your own protocol is fraught with peril. A non-exhaustive list of things to look at:
    * Replay Attacks
        * Without a challenge/response or timestamp built in, an attacker could replay encrypted & signed messages from one participant to another
        * The randomness of the challenge is of course critical
        * A simple example would be the server sending a signed message "The latest version of the software is 1.0.0, this can be replayed indefinitely to keep a user at an old version.
    * Resource Exhaustion 
        * If a protocol requires n^2 operations for n participants, what happens the number of participants is very large?
    * Denial of Service
        * Does the server/receiving participant perform crypto operations before the client? This is an offset work factor.
        * What if the client leaves a step half completed?
    * How does authentication happen? How does the client know they're talking to who they think they are?
        * Certificate Authorities, DNSSEC, or some other central authority? Pre-shared Keys?  
    * What happens when one or more participants' clocks are off?
        * This could allow an attacker to reply messages with an older date; or accept an expired and compromised SSL certificate. 
    * In an n-way protocol, what happens when 2 or more participants are colluding?
        * In the mathematical sense, this is most applicable in multi-party computation or threshold schemes.
        * But in the general sense, what happens when Trent, the trusted introducer (a Certificate Authority) colludes with Mallory, the attacker (a government).
    * **But really, the mere presence of a custom protocol, without an Academic Paper published, without peer review - that's a huge red flag. They should probably be working actively to fix this or replace it if possible.**
* In general, examining an application up to the layer cryptographic library is insufficient, you must go deeper.
    * If the library is OpenSSL, verify they are using it correctly. This is exceptionally difficult, based on how confusing OpenSSL is.  
        * Resources:
            * https://crypto.stanford.edu/~dabo/pubs/abstracts/ssl-client-bugs.html
            * https://isecpartners.com/news-events/news/2012/october/the-lurking-menace-of-broken-tls-validation.aspx
    * If the library is some other random one like PyCrypto - you should go into the library and make sure the library is doing it right. They often are not.
    * The defense of a library against side channel attacks should also be considered.
        * As an example, libgcrypt defends again Timing attacks, but not all oracle attacks
        * A good resource is http://crypto.junod.info/hashdays10_talk.pdf 
    * **Similarly, re-implementing known algorithms, rather than using a library, should be strongly advised against.**
* Key Rotation should be considered.
    * Encryption Keys should not be used to encrypt an infinite amount of data. (The limits depend on the cipher, block size, type of traffic, and other factors.) But generally speaking, an encryption key in use for a long period of time should have some mechanism to roll over to a new key. Is such a mechanism provided for?
    * How is the new key communicated in a trustworthy fashion to users?
    * If an important key is compromised, how would/does the project handle the revocation?

## Cryptography - Specific

* Any transform applied to plaintext data prior to encryption should be treated as suspect. It will almost certainly leak some data about the plaintext in a theoretical way, and these 'theoretical' leaks often turn out to be exploitable.
    * Consider compression applied before encryption. This leaks the redundancy of the plaintext data being compressed. When part of the data is attacker controlled, this is eminently exploitable. See the recent SSL attack CRIME.
    * Dropbox [used to/still] de-duplicates data prior to encrypting and uploading. This means you can use Dropbox as an oracle to tell if anyone else has uploaded a document, which could lead to subpoenas to de-anonymize a whistleblower.
    * Applying an error correcting code on plaintext prior to encryption will introduce redundancy into the plaintext.  
        * As a simple example, consider applying a CRC to the plaintext, and transmitting the ciphertext and CRC. The CRC, transmitted in plaintext) reveals something about the plaintext. If you knew or learned part of the plaintext (for example the Word file type and associated .doc standard format) you might be able to derive a software version.
* Cryptographic Key Generation should be done carefully
    * Key Generation should generally not be done on device startup, as the device may be in a low or no-entropy state
    * Should use a blocking source of randomness
    * Special care should be taken if it is an embedded device or the quality of randomness is suspect
    * One party should not be able to control a key entirely in a shared-generation scenario
    * Keys should not be mathematically related, but instead derived through pseurandom mixing functions (hash functions)
* Obscure or unfamiliar cryptographic constructs should be examined very closely, and likely referred to other consultants or professional cryptographers for second and third looks. These include:
    * Galois Counter Mode (Particularly Tag Length)
    * CBC-MAC
    * Related Key Derivations
    * Large Block constructions like BEAR or LIONESS
* Does the cryptographic library or operations make use of constant-time algorithms? Do they eliminate data-dependent control flow branches or memory lookups?
    * More guidelines on cryptographic code are available at https://cryptocoding.net/index.php/Coding_rules
* Older, but 'not yet insecure' cryptographic algorithms should be viewed very suspiciously. For example:
    * TDES, IDEA, SHA-1
    * 64 Bit Block Ciphers
    * RSA PKCS #1 V1.5 Padding
* A message must must must be integrity protected in its entirety.  
    * If a message is not protected completely, there's probably something bad that can happen.  
* Be suspicious of bare Hashes sent around. A lot of times these are used for some form of authenticity or integrity, when in reality anyone who can modify something can also recompute the hash.
* The implementation of Block Cipher modes should be examined very closely, as history has shown repeated mistakes here
    * CTR mode nonce generation, synchronization, and incrementation
        * http://www.daemonology.net/blog/2011-01-18-tarsnap-critical-security-bug.html 
    * CBC Mode IV generation and authentication
        * The BEAST attack on SSL
* Is the application vulnerable to tagging attacks?
    * See https://crypto.is/blog/tagging_attacks and https://crypto.is/blog/tagging_attack_on_mixmaster
* See also Appendix B

## SSL

* Any Lib Tech project should always prefer Ephemeral ciphersuites
    * SSL ciphersuites with 'DHE' in their name provide forward secrecy in the event of a private key compromise/factor.
    * http://googleonlinesecurity.blogspot.com/2011/11/protecting-data-for-long-term-with.html 
* If the site uses Client Certificates (or really any other form of SSL Authentication: PSK/etc) - do all third party includes also use that form of authentication? 
    * If not, the authentication is the least secure of all forms of authentication.
* Pinning
    * If they have a website: do they pin certificate authorities in Chrome's preloaded list? See:
        * http://www.chromium.org/sts 
        * https://wiki.mozilla.org/Privacy/Features/HSTS_Preload_List 
    * If they have a thick client or mobile app: do they pin certificates in it?
    * Choice of Certificate Authority comes into play here too.
        * http://ritter.vg/blog-cas_and_pinning.html 	
* Web Site Concerns
    * Mixed Content
        * Javascript, CSS, or Embeds loaded over HTTP on a HTTPS site can result in page rewrites that massively impact the security of the site (e.g. obliterate it.)
        * Images, Fonts, and other resources are also a concern, as they trigger the Mixed Content warning in browsers (not good), and can allow an attacker to observe or modify traffic to impact or reveal the display of the page.
    * Cookies marked Secure
    * Strict-Transport-Security?
        * Is the site in Chrome's preloaded HSTS list? (See above)
* Defense in Depth SSL Practices:
    * DANE
        * Really only effective with DNSSEC
        * https://grepular.com/Understanding_DNSSEC 
        * http://tools.ietf.org/html/rfc6698 
    * CAA
        * DNS record to help prevent CA's from mis-issuing. http://tools.ietf.org/html/draft-ietf-pkix-caa 
    * Must Staple OID
        * No reference on this yet as it doesn't exist quite yet.
    * OCSP Stapling
        * No good reference on this. Only supported in Apache 2.4/Nginx/IIS 7.  Can test for it with wireshark.
* Who has access to the SSL private key?
    * This seems like a no-brainer, but in some instances services will host a blog on squarespace or wordpress, and give them a wildcard SSL certificate that would allow the provider to MITM their entire application. If a SSL private key must reside on third-party infrastructure (EC2, Wordpress, Squarespace, etc) it should be tightly scoped.
    * They do generate their own Private Key, and submit a CSR correct?
    * Is the project hosted on bare metal, or a cloud provider?

## Privacy Development Techniques for Web Apps

* The site should not leak a request to any Third Party if at all possible.
    * Third Party images, css, and javascript
    * OCSP request from the browser
    * Facebook Like buttons, Google +1 buttons
    * Google Analytics
    * Embedded Videos (Youtube, Vimeo)
    * Twitter Feed
    * Adaptive or Two-Factor Authentication (e.g. using RSA, YubiKey, etc)
* The site should not log users actions, or perform the minimum amount of logging feasible
    * Do they log user's IP addresses? Do they have to?
    * How often do they wipe or anonymize the logs? How is the anonymization performed?
        * The Tor Project explains their process here: https://lists.torproject.org/pipermail/tor-dev/2011-October/002981.html 
* Does the site have a public statement explaining what they disclose to whom and under what circumstances?
* _A lot of these come from [Micah Lee's talk at HOPE](https://www.eff.org/sites/default/files/filenode/hope_privacy_tricks.pdf)_
    * _This is really worth reading and referencing as suggestions are given for ways to accomplish the same thing without leaking the data_

## Development Best Practices

* Restrictions on commonly abused functionality, such as preprocessor macros, and over riding variable scope can make it much easier to verify a program's correctness
    * A very restrictive set of programming guidelines (for C) are available from the Jet Propulsion Lab: http://lars-lab.jpl.nasa.gov/JPL_Coding_Standard_C.pdf
* Code that parses files or network protocols must be coded defensively with an abundance of caution - the data should be assumed to be hostile and attacker-controlled (it often is)
    * Any length field should be assumed to be incorrect until validated, incorrectly implemented these often lead to buffer overflows
    * Unsigned data types should be used, as the data being parsed is full bytes, even if it is expected to be ASCII
    * Rob Graham has done an informative, cursory code review of Silent Circle: http://erratasec.blogspot.com/2013/02/silent-circle-and-inexperienced.html
* When code was primarily authored or tested on 32-bit systems, subtle errors are likely to be introduced when compiling or running on 64-bit systems.
    * Magic constants are often assumed, such as sizeof(pointer) == 4
    * Storing pointers in integers will truncate the top 32 bits
    * Bitwise operations may behave differently, especially with sign extension
    * Viva64 has blogged about a long list of potential errors with examples: http://www.viva64.com/en/a/0065/
* Even in the case of strong testing methods such as branch coverage, bugs may hide due to edge cases such as concurrency, inline arithmetic, or lookup tables or array indexing. For more examples, see: http://blog.regehr.org/archives/872
    
## Web Application Defense in Depth

* _These items are occasionally logged as bugs, and it may be appropriate to log them as such in a report; but they should be noted as defense in depth techniques that should be used to make exploitation more difficult._
* DNSSEC
    * Does the site make use of DNSSEC? 
    * If the site does not operate under a signed root, they can register in the DLV: https://www.isc.org/solutions/dlv 
* Content Security Policy
    * http://engineering.twitter.com/2011/03/improving-browser-security-with-csp.html 
    * http://www.w3.org/TR/CSP/ 
* crossdomain.xml and clientaccesspolicy.xml
    * http://code.google.com/p/browsersec/wiki/Part2#Same-origin_policy_for_Flash
    * http://code.google.com/p/browsersec/wiki/Part2#Same-origin_policy_for_Silverlight 
    * These files should either be locked down or not present.  If present, they should be examined closely.
* Cache Control & AutoComplete=OFF
    * http://code.google.com/p/browsersec/wiki/Part2#Document_caching 
* Post-Redirect Pattern
    * http://en.wikipedia.org/wiki/Post/Redirect/Get 
    * This pattern can prevent back-buttons resubmitting sensitive forms such as login
* Strict Transport Security
    * http://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security 
* X-Frame-Options along with frame busting javascript for clients who don't support it
    * https://developer.mozilla.org/en-US/docs/The_X-FRAME-OPTIONS_response_header 
    * http://en.wikipedia.org/wiki/Framekiller 
* X-Content-Type-Options
    * http://blogs.msdn.com/b/ie/archive/2008/09/02/ie8-security-part-vi-beta-2-update.aspx   
* Correct character set specified
    * http://code.google.com/p/doctype-mirror/wiki/ArticleUtf7 
* Prepared Statements for accessing a database, and never string built SQL
* Minimized database user permissions (SELECT but no DELETE, etc)
* Do they provide a mechanism to see other active sessions, a login history, and clear all sessions?  
* Do they have a two factor authentication option? Account lockout? IP whitelisting?
* What is their "Forgot Password" logic like?
    * Simple questions like Mother's Maiden Name and Address on File are easily googleable (ask Sarah Palin.)  A better solution is the email verification.
* Does the site strip the Referer on outgoing links? 
    * There are javascript techniques to do so, including http://blog.kotowicz.net/2011/10/stripping-referrer-for-fun-and-profit.html 

## Mobile Application Defense in Depth

* Does not unnecessarily collect or report on personal information: Contacts, Location, Phone Number, Device Identifiers, or other.
* Uses a unique/non-hardware based identifier to prevent correlation with other apps
* Communicates over SSL with remote servers, and correctly checks validity of SSL certificates
    * If feasible or possible, pins server certificate or CA
* Does not download and run dynamic code from a server
    * The server could be compromised or impersonated to achieve remote code execution.
* Uses all possible device-provided encryption APIs 
    * In general, the application stores data securely, perhaps using SQLCipher https://guardianproject.info/code/sqlcipher/ 
* Allows expiring of authenticated phone sessions from a web site
* Does not unnecessarily cache or store sensitive data on the device
* Does not log sensitive data to the system log
* Android
    * Does the application broadcast intents that can be received from other apps?
    * Does the application store data on the SD card, where it can be read by any other app?

## Binary / Thick Client Defense in Depth

* Does not require administrative permissions during use or install
    * If a client requires administrative permissions during use, an attacker who exploited the program would then have administrative permissions and unchecked ability to compromise the user's machine. Running as administrator is an unacceptable design.
    * If a client requires administrative permissions during install, users without those permissions are prevented from using the software, and it trains users to accept 'Admin Access; for this installer, which would compromise more users if a software distribution point was compromised.
* Does the application use the minimal set of third party libraries? 
    * What are the versions of each?
    * Are they dynamically or statically linked?
    * Do they warn the user/refuse to load if the version is known to be insecure?
* Does the application take efforts to prevent the leak of sensitive information in memory
    * Disallowing core dumps using prctl(PR_SET_DUMPABLE...) on segfaults or SIGKILL signals
    * (Attempting to) Prevent ptrace or other hooking
    * Disabling performance counters on Linux using prctl(PR_TASK_PERF_EVENTS_DISABLE...)
* Does the application pack itself or use code obfuscation techniques that may flag it as a virus?
* Does the application check and warn the user if an Anti-Virus is not present?
    * See: http://stackoverflow.com/questions/1331887/detect-antivirus-on-windows-using-c-sharp
* Windows
    * DEP
    * ASLR for all modules
    * Prevent DLL Hijacking
* Linux
    * Compatible with grSecurity / PaX / SELinux
    * seccomp
    * apparmor
        * A good (but not comprehensive) resource on things to look for is: http://blog.azimuthsecurity.com/2012/09/poking-holes-in-apparmor-profiles.html 
    * Position Independent (PIE/PIC)
    * Is any information shared through an IPC mechanism, such as D-Bus or a shared event loop
* Mac
    * Does the application sandbox itself using the Apple Sandbox?
        * https://romab.com/ironsuite/SBPL.html 
        * http://securityevaluators.com/files/papers/apple-sandbox.pdf 
* Does the application allow itself to be fully proxied, with no network or DNS leaks, for use with Tor? See Appendix A.

## Secure Software Distribution & Install
* Does the application provide safe defaults?
* Does the application prevent the user from being able to proceed or change settings to make them unsafe?
    * Example: HSTS dictates a user is unable to bypass a certificate error
* Is the application signed?
    * There are arguments about how Authenticode is more or less secure than PGP signatures. Does the project use *one* of them? Do they make an effort to encourage or teach people to validate the signature?
* Is the software distributed in operating system package managers?
    * Are the operating systems' distributions up to date?
        * Does the project provide its own source repo users can add to the package manager?
    * Do the OS vendors apply patches that may reduce the security of the application?
* Is the software distributed over HTTPS?
    * Even if the application includes a signature, HTTPS is an easy defense in depth practice
    * For the purposes intended (easy defense in depth), a self-signed certificate is insufficient
* Is the software distributed to mirrors? Does the project have integrity checkers for the mirrors?
* Does the application only allow patches greater than the current version to be applied?
    * This prevents vulnerable-but-validly-signed older versions from being applied.
 


# Appendix A: Examining an Application for Proxy Leaks

This provides methodology to set up your computer to alert on any traffic that doesn't go through tor. This is done by configuring a firewall to block all traffic except to pre-chosen Tor bridge nodes. 

The instrucitons presented are fore shorewall (which is an abstraction over IPTables.) A similar guide for IPTables [is posted by Lunar](https://people.debian.org/~lunar/blog/posts/tor_only_outgoing_firewall/) but it does not explicitly alert on traffic, only block it - you'll need to add the alerting.

* Set up a tor bridge on another host in your network/on the internet
* Boot your client/testing machine from a LiveCD
* Install Tor, have it point to the bridge
* Instructions for shorewall:
    * /etc/shorewall/zones:
        <true_pre>
        fw    firewall
        net    ipv4
        </true_pre>
     * /etc/shorewall/interfaces
        <true_pre>
        net    eth0    detect    dhcp
        </true_pre>
    * /etc/shorewall/policy
        <true_pre>
        fw    net     DROP     warn
        net    fw      DROP    info
        </true_pre>
    * /etc/shorewall/rules
        <true_pre>
        ACCEPT    $FW      bridgeip     tcp    bridgeport
        </true_pre>
* This should prevent anything from leaving your machine that doesn't go to that single port on that single ip over TCP. Tail your logs, and let your machine quiet down. Stop any ntp services, system updates, etc. Get it so your machine is sending no traffic.
* Start up the application, use *every single feature* and make sure it's all being correctly proxied through tor. Anything that shows up in your logs is a leak. Investigate it.

It's worth verifying that this setup correctly stops/logs UDP and ICMP. 

**Very Important**: This will not help you if the application sends de-anonymizing information (like external IP) over the Tor link. 

Other resources from the Tor community:

* https://trac.torproject.org/projects/tor/wiki/doc/DnsResolver
* https://trac.torproject.org/projects/tor/wiki/doc/Preventing_Tor_DNS_Leaks
* https://trac.torproject.org/projects/tor/wiki/doc/PreventingDnsLeaksInTor
* https://trac.torproject.org/projects/tor/wiki/doc/TorifyHOWTO
* https://trac.torproject.org/projects/tor/wiki/doc/TransparentProxyLeaks
 
# Appendix B: Cryptographic Attacks Cheat Sheet

This list was largely derived from a collation done by Rafael Turner.

* ECB
    * Block Swapping
    * Data Leakage
* CBC
    * Watermarking
        * http://en.wikipedia.org/wiki/Watermarking_attack 
    * Data modification leak
    * Malleability via bit flipping
    * Cut & Paste attack
        * http://books.google.com/books?id=UW3SS9P9hdEC&pg=PT99&lpg=PT107&ots=0VG3xbufOG&dq=CBC+%22cut+and+paste+attack%22 
    * Rearranging blocks.
    * Vaudenay's Oracle (BEAST Attack)
* CTR
    * Counter reuse
    * Passki and Ritter's Oracle (CTR/CBC/OFB/CFB)
* RSA
    * Fault Injection & Random Faults
    * Multiplicative property
    * Choosing common modulus N to serve multiple users.
    * Small decryption exponent d
    * Forward Search Attack
    * Coppersmith's Attack
    * Coppersmith's Short Pad Attack
    * Hastad's broadcast attack
    * Bleichenbacher's Attack on PKCS 1
    * Kocher's Timing Attacks
    * Manger's oracle
    * Naive implementations
    * Franklin-Reiter Related Message Attack
* Stream Cipher
    * Correlation Attack
    * Keyreuse
* DH
    * Denial of service Attacks
    * Man in the Middle Attacks
    * Degenerate Message Attacks
    * Simple Exponents
    * Simple Substitution Attacks
    * Message Replay Attacks
    * Message Redirection
    * Attacks on Parameter Authentication
    * Timing Attacks
    * Small subgroup reduction
    * Reusing ephemeral keys
* DSA
    * Fault Attacks
    * Misuse or leakage of per-message secret
* ElGamal
    * Insecurity under a chosen ciphertext attack.
* ECC
    * Fault Attacks
    * Side-Channel
* Hashing
    * Non constant compares


# Acknowledgements

This document was primarily authored by Tom Ritter. It would be impossible to list the dozens of individuals whose teachings were used to create this document.  Peer review of initial versions was provided by Peter Oehlert and Paul Youn of iSEC Partners, as well as David Goulet and Runa Sandvik.  Additional feedback was provided by Philipp Winter and Michael Rogers. Finally, thanks to my employer, iSEC Partners, for sponsoring this work.

# Licensing

This work is licensed under a Creative Commons Attribution-ShareAlike 3.0 Unported License: http://creativecommons.org/licenses/by-sa/3.0/
