# Domain-5 **Identity and Access Management (IAM)**

## 5.1 Control physical and logical access to assets

- Controlling access to assets (assets are anything of value to the organization); tangible assets are things you can touch, and non-tangible assets are things like info and data; controlling access to assets is a central theme of security
- Understand that there is no security without physical security: admin, technical and logical access controls aren't effective without control over the physical env
- Understand what assets you have, and how to protect them
  - **physical security controls**: such as perimeter security and environmental controls
    - control access and the environment
  - **logical access controls**: automated systems that auth or deny access based on verification that identify presented matches that which was previously approved; technical controls used to protect access to information, systems, devices, and applications
    - includes authentication, authorization, and permissions
    - permissions help ensure only authorized entities can access data
    - logical controls restrict access to config settings on systems/networks to only authed individuals
    - applies to on-prem and cloud
- In addition to personnel, assets can be information, systems, devices, facilities, applications or services

- 5.1.1 Information
  - An org’s information includes all of its data, stored in simple files (on servers, computers, and small devices), or in databases

- 5.1.2 Systems
  - An org’s systems include anything that provide one or more services; a web server with a database is a system; permissions assigned to user and system accounts control system access

- 5.1.3 Devices
  - Devices refer to any computing system (e.g. routers & switches, smartphones, laptops, and printers); BYOD has been increasingly adopted, and the data stored on the devices is still an asset to the org

- 5.1.4 Facilities
  - Any physical location, building, rooms, complexes etc; physical security controls are important to help protect facilities

- 5.1.5 Applications
  - Apps provide access to data; permissions are an easy way to restrict logical access to apps

- 5.1.6 Services
  - The point of identity management is to control access to any asset including data, systems, and services; services include a wide range of process functionality such as printing, end-user support, network capacity etc; as above, access control is important to secure these services

## 5.2 Design identification and authentication strategy (e.g., people, devices, and services)

- **Identification**: the process of a subject claiming, or professing an identity
- **Authentication**: verifies the subject’s identity by verifying an identity through knowledge, ownership, or characteristic; comparing one or more factors against a database of valid identities, such as user accounts
  - a core principle with authentication is that all subjects must have unique identities
  - identification and authentication occur together as a single two-step process
  - users identify themselves with usernames and authenticate (or prove their identity) with passwords

- 5.2.1 Groups and Roles
  - **Roles**: set of permissions that correspond to a job function within an org, rather than a group of users; a user is assigned a role, and granted the permissions associated with that role;s
    - another way of saying this is that roles are function-centric, for instance say a helpdesk analyst, level-1, is a specific role that defines the specific permission available
    - roll-based access means that a role with specific permissions is created and then assigned to someone in that role or job
  - **Groups**: a group is a collection of users, and admins can assign permissions to the group instead of assigning permissions to individual users; this makes it easier to manage larger numbers of users
    - groups are user-centric, focusing on the collective identity of that group of users
  - Identity and access management is a collection of processes and technologies that are used to control access to critical assets; it's purpose is the management of access to information, systems, devices, and facilities
  - Identity Management (IdM) implementation techniques generally fall into two categories:
    - **centralized access control**: implies a single entity within a system performs all authorization verification
      - potentially creates a single point of failure
      - small team can manage initially, and can scale to more users
    - **decentralized access control**: (AKA distributed access control) implies several entities located throughout a system perform auth verification
      - requires more individuals or teams to manage, and admin may be spread across numerous locations
      - difficult to maintain consistency
      - changes made to any individual access control point needs to be repeated at others
  - With ubiquitous mobile computing and anywhere, anytime access (to apps & data), identity is the "new perimeter"

- 5.2.2 Authentication, Authorization and Accounting (AAA) (e.g., multi-factor authentication (MFA), password-less authentication)
  - The four key access control services: Identification (assertion of identity), Authentication (verification of identity), Authorization (definition of access), Accountability (responsibility of actions)
    - Note that AAA is the same principles of Authentication, Authorization, and using the word Accounting instead of Accountability (but it's the same principle)
    - and remember that the three factors of authentication that you need to understand is knowledge, ownership, and characteristic (see above)
  - Two important security elements in an access control system are authorization and accountability
    - **Authorization**: subjects are granted access to objects based on proven identities; the level of access defined for the identified and authenticated user or process
    - **Accountability AKA Principle of Access Control**: proper identification, authentication, and authorization that is logged and monitored; users and other subjects can be held accountable for their actions when auditing is implemented; accountability is maintained for individual subjects through the use of auditing; logs record user activities and users can be held accountable for their logged actions; this encourages good user behavior and compliance with the org's security policy; also see definitions/interpolations in Domain 2, and above
  - **Auditing**: tracks subjects and records when they access objects, creating an audit trail in one or more audit logs
  - Auditing provides accountability
  - **Single-factor authentication**: any authentication using only one proof of identity
  - **Two-factor authentication (2FA)**: requires two different proofs of identity
  - **Multifactor authentication (MFA)**: any authentication using two or more factors
    - multifactor auth must use multiple types or factors, such as something you know and something you have
    - note: requiring users to enter a password and a PIN is NOT multifactor (both are something you know)
  - Two-factor methods:
    - **Hash Message Authentication Code (HMAC)**: includes a hash function used by the HMAC-based One-Time Password (HOTP) standard to create onetime passwords
    - **Time-based One-Time Password (TOTP)**: similar to HOTP, but uses a timestamp and remains valid for a certain time frame (e.g. 30 or 60 seconds)
      - e.g. phone-based authenticator app, where your phone is mimicking a hardware TOTP token (combined with userid/password is considered two-factor or two-step authentication)
    - **Email challenge**: popular method, used by websites, sending the user an email with a PIN
    - Short Message Service (SMS): to send users a text with a PIN is another 2-factor method; note that NIST SP 800-63B points out vulnerabilities, and deprecates use of SMS as a two-factor method for federal agencies
  - **Password-less authentication**: a method of verifying a user's identity without requiring them to enter a password; uses alternate verification forms like biometrics, security tokens, or mobile device
    - this is an important topic, because password use (and misuse) provide many security headaches and problems
    - Advantages of password-less auth include:
      - increased security
      - improved user convenience
      - reduction risk of phishing: if attacker gains access to a password, but password-less auth makes it much more difficult for the attacker to access the associated device (say if password-less auth is via mobile device)
    - Disadvantages of password-less auth:
      - dependency on devices (e.g. if via mobile phone, that device is required for access)
      - biometric issues associated with reliability and privacy
      - implementation costs associated with additional hardware devices etc

- 5.2.3 Session management
  - **Session management**: the management of sessions created by successful user identification, authentication, and authorization process; session management help prevent unauthorized access by closing unattended sessions; developers commonly use web frameworks to implement session management, allowing devs to ensure sessions are closed after they become inactive for a period of time
  - Session management is important to use with any type of authentication system to prevent unauthorized access
  - Session termination strategies:
    - schedule limitations: setting hours when a system is available
    - login limitation: preventing simultaneous logins using the same userID
    - time-outs: session expires after a set amount of inactivity
    - screensavers: activated after a period of inactivity, requiring re-authentication
  - Session termination and re-authentication helps to prevent or mitigate session hijacking
  - The Open Web Application Security Project (OWASP) publishes “cheat sheets” that provide app developer’s specific recommendations

- 5.2.4 Registration, proofing, and establishment of identity
  - Within an organization, new employees prove their identity with appropriate documentation during the hiring process
    - in-person identity proofing includes things like passport, DL, birth cert etc
  - Online orgs often use **knowledge-based authentication (KBA)** for identity-proofing of someone new (e.g. a new customer creating a new bank/savings account)
    - example questions include past vehicle purchases, amount of mortgage payment, previous addresses, DL numbers
    - they then query authoritative information (e.g. credit bureaus or gov agencies) for matches
  - **Cognitive Passwords**: security questions that are gathered during account creation, which are later used as questions for authentication (e.g. name of pet, color of first car etc)
    - one of the flaws associated with cognitive passwords is that the information is often available on social media sites or general internet searches

- 5.2.5 Federated Identity Management (FIM)
  - Federated Identity Management (FIM) systems (a form of SSO) are often used by cloud-based apps
  - A federated identity links a user’s identity in one system with multiple identity management systems
  - FIM allows multiple orgs to join a federation or group, agreeing to share identity information
    - users in each org can log in once in their own org, and their credentials are matched with a federated identity
    - users can then use this federated identity to access resources in any other org within the group
    - where each organization decides what resources to share
  - Methods used to implement federated identity management systems include:
    - Security Assertion Markup Language (SAML)
    - OAuth
    - OpenID Connect (OIDC)
  - Cloud-based federation typically uses a third-party service to share federated identities
  - Federated identity management systems can be hosted on-premises, in the cloud, or in a combination of the two as a hybrid system

- 5.2.6 Credential management systems (e.g., Password vault)
  - **Credential management systems**: provide storage space for usernames and passwords
    - these systems help developers easily store usernames/passwords and retrieve them when a user revisits a website, allowing users to log on automatically to a site without entering their credentials again
  - The World Wide Web Consortium (W3C) published the Credential Management Level 1 API as a working draft in January 2019, which many browsers have adopted
  - Some federated identity management solutions use the Credential Management API, allowing web apps to implement SSO using a federated identity provider
    - e.g. using your Google or Facebook account to sign into Zoom
  - **Password vault (AKA password manager)**: system meant to store and manage credentials; credentials are typically kept in an encrypted database protected by a master password or key
    - in modern life we need access to many different systems, and re-using one (or even a few) passwords with many systems means that if an attacker deduces your password, they then have access to many systems (and much of your data)
    - password managers make it much easier to create strong and different passwords for each system, without the need to memorize them
    - the downside of course is that if your master password is compromised, the attacker will have access to all your systems

- 5.2.7 Singe Sign On (SSO)
  - **Single Sign-On (SSO)**: a centralized access control technique allowing a subject to be authenticated once on a system and access multiple resources without authenticating again
  - Advantages of using SSO include:
    - reduces the number of passwords that users need to remember, and they are less likely to write them down
    - eases administration by reducing the number of accounts
  - Disadvantages:
    - once an account is compromised, an attacker gains unrestricted access to all of the authorized resources
  - Within an organization, a central access control system, such as a directory service, is often used for SSO
    - **directory service**: a centralized database that includes information about subjects and objects, including authentication data
    - many directory services are based on the Lightweight Directory Access Protocol (LDAP)

- 5.2.8 Just-In_time (JIT)
  - Federated identity solutions that support just-in-time (JIT) provisioning automatically create the relationship between two entities so that new users can access resources
  - JIT provisioning creates user accounts on third-party sites the first time a user logs into the site; JIT reduces the admin workload
  - A JIT solution creates the connection without any administrative intervention
  - JIT systems commonly use SAML to exchange required data

## 5.3 Federated Identity with a third-party service

- 5.3.1 On-premise
  - Federated identity management can be hosted on-premise, and typically provides an organization with the most control

- 5.3.2 Cloud
  - Cloud-based apps use federated identify management (FIM) systems, which are a form of SSO
  - Cloud-based federation typically uses a third-party service to share federated identities (e.g. training sites use federated SSO systems) commonly matching the user's internal login ID with a federated identify

- 5.3.3 Hybrid
  - A hybrid federation is a combination of a cloud-based solution and an on-premise solution

## 5.4 Implement and manage authorization mechanisms

- Authorization ensures that the requested activity or object access is possible, given the authenticated identity's privileges
  - e.g. ensuring that users with appropriate can access resources
  - common authorization mechanisms include:
    - implicit deny
    - access control lists
    - access control matrixes
    - capability tables
    - constrained interfaces
    - content-dependent controls
    - context-dependent controls

- 5.4.1 Role Based Access Control (RBAC)
  - **Role-Based Access Control (RBAC)**: key characteristic is the use of roles or groups; RBAC models use task-based roles, and users gain privileges when admins place their accounts into a role or group; taking a user out of a role removes the permissions granted through the role membership
  - Instead of assigning permissions directly to users, user accounts are placed in roles and administrators assign privileges to the roles (typically defined by job function)
    - if the user account is in a role, the user has all privileges assigned to the role
  - MS Windows OS uses this model with groups
  - RBAC models can group users into roles based on the org's hierarchy, and it is a non-discretionary access control model; central authority access decisions can use the RBAC model
  - RBAC allows assignment of privileges to users with minimum admin overhead

- 5.4.2 Rule Based access control
  - **Rule-based Access Control**: use a set of rules, restrictions, or filters to determine access; key characteristic is that it applies global rules to all subjects
    - e.g. firewalls access control lists use a list of rules that define what access is allowed and what access is blocked
  - Rules within the rule-based access control model are sometimes referred to as restrictions or filters

- 5.4.3 Mandatory Access Control (MAC)
  - **Mandatory Access Control (MAC)**: access control that requires the system itself to manage access controls in accordance with the org's security policies
  - A key characteristic of the MAC model is the use of labels applied to both subjects and objects; subjects need matching labels to access objects
    - e.g. a label of top secret grants access to top-secret documents
  - When documented in a table, the MAC model sometimes resembles a lattice (i.e. climbing rosebush framework), so it is referred to as a lattice-based model
  - the MAC model enforces the need to know principle and supports a hierarchical environment, a compartmentalized environment, or a combination of both (hybrid environment)

- 5.4.4 Discretionary Access Control (DAC)
  - **Discretionary Access Control (DAC)**: access control model in which the asset or system owner decides who gets access
  - A key characteristic of the DAC model is that every object has an owner, and the owner can grant or deny access to any other subjects
    - e.g. you create a file and are the owner, and can grant permissions to that file
  - All objects have owners, owners can modify permission
  - Each object has an access control list defining permissions (e.g. read and modify files)
  - All other models are non-discretionary models, and admins centrally manage non-discretionary controls
  - New Technology File System (NTFS) used in Windows, uses the DAC model
  - **Non-discretionary Access Control**: somebody other than the asset owner determines access

- 5.4.5 Attribute Based Access Control (ABAC)
  - **Attribute-Based Access Control (ABAC)**: an advanced implementation of a rule-based access model, applying rules based on attributes; an access control paradigm where access rights are granted to users with policies that combine attributes together
  - A key characteristic of the ABAC model is its use of rules that can include multiple attributes about users, the environment, a user's action and the target resource
    - this allows it to be much more flexible than a rule-based access control model that applies the rules to all subjects equally
    - many software-defined networks (SDNs) use the ABAC model
  - ABAC allows administrators to create rules within a policy using plain language statements such as "Allow Managers to access the WAN using a mobile device"
  - ABAC uses XACML (eXtensible Access Control Markup Language) which defines attribute-based  access control policy language, architecture, and a processing model

- 5.4.6 Risk based access control
  - **Risk-based access control**: evaluates the environment and the situation, and makes decisions based on software security policies
    - a model that grants access after evaluating risk; it can control access based on multiple factors such as a user's location, determined by IP addresses, whether the user has logged on with MFA, and the user's device
    - advanced models use machine learning, making predictive conclusions about current activity based on past activity
    - note that a risk-based access control can be used, as an example, to block malicious traffic from an infected IoT device by evaluating the environment and situation, and using that info to block traffic deemed abnormal

- 5.4.7 Access policy enforcement (e.g., policy decision point, policy enforcement point)
  - **Access policy enforcement**: enforcing access control policies within an org to regulate and manage access
  - Policy Decision Point (PDP): the system responsible for making access control decisions based on predefined access policies and rules; a PDP evaluates access requests
  - Policy Enforcement Point (PEP): responsible for enforcing the access control decisions made by the PDP; the PEP acts as a gatekeeper

## 5.5 Manage the identity and access provisioning lifecycle

- 5.5.1 Account access review (e.g., user, system, service)
  - Administrators need to periodically review user, system and service accounts to ensure they meet security policies and that they don’t have excessive privileges
  - Be careful in using the local system account as an application service account; although it allows the app to run without creating a special service account, it usually grants the app more access than it needs
  - You can use scripts to run periodically and check for unused accounts, and check privileged group membership, removing unauthorized accounts
  - Guard against two access control issues:
    - excessive privilege: occurs when users have more privileges than assigned work tasks dictate; these privileges should be revoked
    - creeping privileges (AKA privilege creep): user accounts accumulating additional privileges over time as job roles and assigned tasks change

- 5.5.2 Provisioning and deprovisioning (e.g., on/off boarding and transfers)
  - Identity and access provisioning lifecycle refers to the creation, management, and deletion of accounts
    - this lifecycle is important because without properly defined and maintained user accounts, a system is unable to establish accurate identity, perform authentication, provide authorization, and track accountability
  - Provisioning/Onboarding
    - provisioning ensures that accounts have appropriate privileges based on task requirements and employees receive needed hardware; said another way, includes the creation, maintenance, and removal of user objects from apps, systems, and directories
    - proper user account creation, or provisioning, ensures that personnel follow specific procedures when creating accounts
      - new-user account creation is AKA enrollment or registration
    - **automated provisioning**: information is provided to an app, that then creates the accounts via pre-defined rules (assigning to appropriate groups based on roles)
      - automated provisioning systems create accounts consistently
    - **workflow provisioning**: provisioning that occurs through an established workflow, like an HR process
    - provisioning also includes issuing hardware, tokens, smartcards etc to employees
    - it’s important to keep accurate records when issuing hardware to employees
    - after provisioning, an org can follow up with onboarding processes, including:
      - the employee reads and signs the acceptable use policy (AUP)
      - explaining security best practices (like infected emails)
      - reviewing the mobile device policy
      - ensuring the employee’s computer is operational, and they can log in
      - configure a password manager
      - explaining how to access help desk
      - show how to access, share and save resources
  - Deprovisioning/Offboarding
    - deprovisioning processes disable or delete an account when employees leave, and offboarding processes ensure that employees return all hardware the org issued them
    - deprovisioning/offboarding occurs when an employee leaves the organization or is transferred to a different department
    - **account revocation**: deleting an account is the easiest way to deprovision
      - an employee's account is usually first disabled
      - supervisors can then review the user’s data and determine if anything is needed
      - note: if terminated employee retains access to a user account after the exit interview, the risk for sabotage is very high
    - deprovisioning includes collecting any hardware issued to an employee such as laptops, mobile devices and auth tokens

- 5.5.3 Role definition and transition (e.g., people assigned to new roles)
  - When a new job role is created, it's important to identify privileges needed by someone in that role; this ensures that employees in the new roles do not have excessive privileges
  - Employee responsibilities can change in the form of transfers to a different role, or into a newly created role
    - for new roles, it’s important to define the role and the privileges needed by the employees in that role
  - Roles and associated groups need to be defined in terms of privileges

- 5.5.4 Privilege escalation (e.g., use of sudo, auditing its use)
  - **Privilege escalation**: refers to any situation that gives users more privileges than they should have
  - Attackers use privilege escalation techniques to gain elevated privileges, after exploiting a single system; typically, they try to gain additional privileges on the exploited systems first
  - **Horizontal privilege escalation**: gives an attacker similar privileges as the first compromised user, but from other accounts
  - **Vertical privilege escalation**: provides an attacker with significantly greater privileges
    - e.g. after compromising a regular user’s account an attacker can use vertical privilege escalation techniques to gain administrator privileges on the user’s computer
    - the attacker can then use horizontal privilege escalation techniques to access other computers in the network
    - this horizontal privilege escalation throughout the network is AKA **lateral movement**
  - Limiting privileges given to service accounts reduces the success of some privilege escalation attacks; this should include minimizing the use of the sudo account

- 5.5.5 Service accounts management
  - **Service accounts**: used by applications, services, systems to interact with other resources, services, or databases without human intervention
    - regardless of the fact that these accounts are not primarily used by humans for authentication, doesn't mean they can be ignored; these accounts and the security of these accounts need to reviewed and managed
  - **Service account management**: the process of creating, configuring, monitoring, and maintaining service accounts
    - ensuring service accounts are secured, reducing the risk of unauthorized access or misuse

## 5.6 Implement authentication systems

- **Federated Identity Management (FIM)**: (AKA federated access) one-time authentication to gain access to multiple systems, including those associated with other organizations; FIM systems link user identities in one system with other systems to implement SSO; FIM systems are implemented on-premise (providing the most control), via third-party cloud services, or as hybrid systems; using your Microsoft account to authenticate to a third-party SaaS is an example of FIM
  - FIM trust relationships include: principal/user, identity provider (entity that owns the identity and performs the auth), and relying party (AKA service provider)
  - FIM protocols include SAML, WS-Federation, OpenID (authentication), and OAuth (authorization)
  - Compare FIM with SSO: user authenticates one time using SSO to access multiple systems in one org; a user authenticates one time using FIM to access multiple systems inside and outside an org because of multiple-entity trust relationships
- XML is defined in Domain 8, but essentially Extensible Markup Language is a set of HTML extensions providing for data storage and transport in networked environments; frequently used to integrate web pages with databases; XML is often embedded in the HTML files making up elements of a web page
  - XML does more than describing how to display data, it describes the data itself using tags
- Security Assertion Markup Language (SAML)
  - **Security Assertion Markup Language (SAML)**: an open XML-based standard commonly used to exchange authentication and authorization (AA) information between federated orgs
  - Frequently used to integrate cloud services and provides the ability to make authentication and authorization assertions
  - SAML provides SSO capabilities for browser access
  - Organization for the Advancement of Structure Information Standards (OASIS) maintains it
  - SAML 2.0 is an open XML-based standard
  - SAML 2.0 spec utilizes three entities:
    - **Principal or User Agent**: the principle is the user attempting to use the service
    - **Service Provider (SP) (or relying party)**: providing a service for the user
    - **Identity Provider (IdP)**: a third-party that holds the user authentication and authorization info
  - IdP can send three types of XML messages known as assertions:
    - **Authentication Assertion**: provides proof that the user agent provided the proper credentials, identifies the identification method, and identifies the time the user agent logged on
    - **Authorization Assertion**: indicates whether the user agent is authorized to access the requested service; if denied, includes why
    - **Attribute Assertion**: attributes can be any information about the user agent
- OpenID Connect (OIDC) / Open Authorization (Oauth)
  - **OpenID provides authentication**
  - **OpenID Connect (OIDC)**: an authentication layer using the OAuth 2.0 authorization framework, maintained by the OpenID Foundation (not IETF); OIDC provides both authentication and authorization (by using the OAuth framework)
    - OIDC is a RESTful, JSON (JavaScript Object Notation)-based auth protocol that, when paired with OAuth can provide identity verification and basic profile info; uses JSON Web Tokens (JWT), (AKA ID token)
  - OAuth and OIDC are used with many web-based applications to share information without sharing credentials
    - OAuth provides authorization
    - OIDC uses the OAuth framework for authorization and builds on the OpenID technologies for authentication
  - **OAuth 2.0**: an open authorization framework described in RFC 6749 (maintained by Internet Engineering Task Force (IETF))
    - OAuth exchanges data via APIs
    - OAuth is the most widely used open standard for authorization and delegation of rights for cloud services
    - The most common protocol built on OAuth is OpenID Connect (OIDC); OpenID is used for authentication
    - OAuth 2.0 enables third-party apps to obtain limited access to an HTTP service, either on behalf of a resource owner (by orchestrating an approval interaction), or by allowing third-party applications to obtain access on its own behalf; OAuth provides the ability to access resources from another service
    - OAuth 2.0 is often used for delegated access to applications, e.g. a mobile game that automatically finds your new friends from a social media app is likely using OAuth 2.0
  - Conversely, if you sign into a new mobile game using a social media account (instead of creating a user account just for the game), that process might use OIDC
- Kerberos
  - **Kerberos is the most common SSO method used within orgs**
  - **The primary purpose of Kerberos is authentication**
  - **Kerberos uses symmetric cryptography and tickets to prove identification and provide authentication**
  - **Kerberos relies on NTP (Network Time Protocol) to sync time between server and clients**
  - **Kerberos uses port 88 for auth communications**, clients communicate with KDC servers over the port so that users can effectively access privileged network resources
  - Kerberos is a network authentication protocol widely used in corporate and private networks and found in many LDAP and directory services solutions such as Microsoft Active Directory
  - It provides single sign-on and uses cryptography to strengthen the authentication process and protect logon credentials
  - Ticket authentication is a mechanism that employs a third-party entity to prove identification and provide authentication - Kerberos is a well-known ticket system
  - After users authenticate and prove their identity, Kerberos uses their proven identity to issue tickets, and user accounts present these tickets when accessing resources
  - Kerberos version 5 relies on symmetric-key cryptography (AKA secret-key cryptography) using the Advanced Encryption Standard (AES) symmetric encryption protocol
  - Kerberos provides confidentiality and integrity for authentication traffic using end-to-end security and helps protect against eavesdropping and replay attacks
  - Kerberos uses UDP port 88 by default
  - Kerberos elements:
    - **Key Distribution Center (KDC)**: the trusted third party that provides authentication services
    - **Kerberos Authentication Server**: hosts the functions of the KDC:
      - **ticket-granting service (TGS)**: provides proof that a subject has authenticated through a KDC and is authorized to request tickets to access other objects
        - the ticket for the full ticket-granting service is called a ticket-granting ticket ([TGT](https://learn.microsoft.com/en-us/windows/win32/secauthn/ticket-granting-tickets)); when the client asks the KDC for a ticket to a server, it presents credentials in the form of an authenticator message and a ticket (a TGT) and the ticket-granting service opens the TGT with its master key, extracts the logon session key for this client, and uses the logon session key to encrypt the client's copy of a session key for the server
        - a TGT is encrypted and includes a symmetric key, an expiration time, and user’s IP address
        - subjects present the TGT when requesting tickets to access objects
      - **authentication service (AS)**: verifies or rejects the authenticity and timeliness of tickets; often referred to as the KDC
    - **Ticket (AKA service ticket (ST))**: an encrypted message that provides proof that a subject is authorized to access an object
    - **Kerberos Principal**: typically a user but can be any entity that can request a ticket
    - **Kerberos realm**: a logical area (such as a domain or network) ruled by Kerberos
  - Kerberos login process:
    1) user provides authentication credentials (types a username/password into the client)
    2) client/TGS key generated
        - client encrypts the username with AES for transmission to the KDC
        - the KDC verifies the username against a db of known credentials
        - the KDC generates a symmetric key that will be used by the client and the Kerberos server
        - it encrypts this with a hash of the user’s password
    3) TGT generated - the KDC generates an encrypted timestamped TGT
    4) client/server ticket generated
        - the KDC then transmits the encrypted symmetric key and the encrypted timestamped TGT to the client
        - the client installs the TGT for use until it expires
        - the client also decrypts the symmetric key using a hash of the user’s password
        - NOTE: the client’s password is never transmitted over the network, but it is verified
            - the server encrypts a symmetric key using a hash of the user’s password, and it can only be decrypted with a hash of the user’s password
    5) user accesses requested service
  - When a client wants to access an object (like a hosted resource), it must request a ticket through the Kerberos server, in the following steps:
    - the client sends its TGT back to the KDC with a request for access to the resource
    - the KDC verifies that the TGT is valid, and checks its access control matrix to verify user privileges for the requested resource
    - the KDC generates a service ticket and sends it to the client
    - the client sends the ticket to the server or service hosting the resource
    - the server or service hosting the resource verifies the validity of the ticket with the KDC
    - once identity and authorization are verified, Kerberos activity is complete
      - the server or service host then opens a session with the client and begins communication or data transmission
- Remote Authentication Dial-in User Service (RADIUS) / Terminal Access Controller Access Control System Plus (TACACS+)
  - Several protocols provide centralized authentication, authorization, and accounting services; network (or remote) access systems use AAA protocols
  - **Remote Authentication Dial-in User Service (RADIUS)**: centralizes authentication for remote access connections, such as VPNs or dial-up access
    - a user can connect to any network access server, which then passes on the user’s credentials to the RADIUS server to verify authentication and authorization and to track accounting
    - in this context, the network access server is the RADIUS client, and a RADIUS server acts as an authentication server
    - the RADIUS server also provides AAA services for multiple remote access servers
    - RADIUS uses the User Datagram Protocol (UDP) by default and encrypts only the password’s exchange
    - RADIUS using Transport Layer Security (TLS) over TCP (port 2083) is defined by RFC 6614
    - RADIUS uses UDP port 1812 for RADIUS messages and UDP port 1813 for RADIUS Accounting messages
    - RADIUS encrypts only the password’s exchange by default
    - it is possible to use RADIUS/TLS to encrypt the entire session
  - Cisco developed **Terminal Access Control Access Control System Plus (TACACS+)** and released it as an open standard
    - provides improvements over the earlier version and over RADIUS, it separates authentication, authorization, and accounting into separate processes, which can be hosted on three different servers
    - additionally, TACACS+ encrypts all of the authentication information, not just the password, as RADIUS does
    - TACACS+ uses TCP port 49, providing a higher level of reliability for the packet transmissions
  - **Diameter AAA protocol**: an advanced system designed to address the limitations of the older RADIUS protocol (diameter is twice the radius!); Diameter improves on RADIUS by providing enhanced security (uses IPsec or TLS instead of MD5 hashing), supports more extensive attribute sets (suitable for large, complex networks), and can handle complex sessions
    - Diameter is based on RADIUS and improves many of its weaknesses, but Diameter is not compatible with RADIUS
  