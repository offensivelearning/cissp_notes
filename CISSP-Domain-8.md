# Domain-8 **Software Development Security**

## 8.1 Understand and integrate security in the Software Development Life Cycle (SDLC)

- 8.1.1 Development methodologies (e.g., Agile, Waterfall, DevOps, DevSecOps, Scaled Agile Framework)
  - **Agile methodology**: a project management approach to development that involves breaking the project into phases and emphasizes continuous collaboration and improvement; teams follow a cycle of planning, executing, and evaluating; focus is on iterative development and frequent feedback, collab between small self-organizing cross-functional teams; in a very simplified sense, you can say agile is waterfall done in sprints
    - Agile development emphasizes:
      - the delivery of working software in short iterations, helping to get the software to market faster
      - reduced risk by frequently testing and providing feedback, helping to identify and resolve issues earlier in the development process
    - Agile was started by 17 pioneers in 2001, producing the "Manifesto for Agile Software Development" ([agilemanifesto.org](https://agilemanifesto.org)) that lays out the core philosophy of the Agile approach:
      - **individuals and interactions** over processes and tools
      - **working software** over comprehensive documentation
      - **customer collaboration** over contract negotiation
      - **responding to change** over following a plan
    - Agile Manifesto also defines 12 principles:
      - the highest priority is to satisfy the customer through early and continuous delivery of valuable software
      - welcome changing requirements, even late in development; Agile processes harness change for the customer’s competitive advantage
      - deliver working software frequently, from a couple of weeks to a couple of months, with a preference for the shorter timescale
      - business people and developers must work together daily throughout the project
      - build projects around motivated individuals; give them the environment, support, and tools and trust them to build
      - emphasizing face-to-face conversation
      - working software is the primary measure of progress
      - agile processes promote sustainable development; the them should be able to maintain a constant pace indefinitely
      - continuous attention to technical excellence and good design enhances agility
      - simplicity, or the art of maximizing the amount of work not done, is essential
      - the best architectures, requirements, and designs emerge from self-organizing teams
      - at regular intervals, the team reviews their effective and adjusts for improvement
    - Several methodologies have emerged that take these Agile principles and define specific processes around them:
      - **Scrum**: a management framework that teams use to self-organize and work towards a common goal; it describes a set of meetings, tools, and roles for efficient project delivery, allowing teams to self-manage, learn from experience, and adapt to change; named from the daily team meetings, called scrums; development focuses on short sprints that deliver finished products; integrated product teams (IPTs) were an early effort of this approach
      - **Kanban**: a visual system used to manage and keep track of work as it moves through a process; the word kanban is Japanese for "card you can see"; Kanban teams focus on reducing the time a project (or user story) takes from start to finish, using a kanban board and continuously improving their flow of work
      - **Rapid Application Development (RAD)**: an agile software development approach that focuses more on ongoing software projects and user feedback and less on following a strict plan, emphasizing rapid prototyping over planning; RAD uses four phases: requirements planning, user design, construction, and cutover
      - **Rational Unified Process (RUP)**: an agile software development methodology that splits the project life cycle into four phases:
        - inception: which defines the scope of the project and develop business case
        - elaboration: Plan project, specify features, and baseline the architecture
        - construction: Building the product
        - transition: providing the product to its users
        - during each of the phases, all six core development disciplines take place: business modeling, requirements, analysis and design, implementation, testing, and deployment
      - **Agile Unified Process (AUP)**: a simplified version of the rational unified process, it describes a simple, easy to understand approach to developing business application software using agile techniques and concepts yet still remaining true to the RUP
      - **Dynamic Systems Development Model (DSDM)**: an agile project delivery framework, initially used as a software development method; key principles:
        - focus on the business need: DSDM teams establish a valid business case and ensure organizational support throughout the project
        - deliver on time: work should be time-boxed and predictable, to build confidence in the development team
      - **Extreme Programming (XP)**: an Agile project management methodology that targets speed and simplicity with short development cycles, [using five guiding values, and five rules](http://www.extremeprogramming.org); the goal of the rigid structure, focused sprints and continuous integrations is higher quality product
      - **Scaled Agile Framework® (SAFe)**: a set of org and workflow patterns for implementing agile practices at an enterprise scale; the framework is a body of knowledge that includes structured guidance on roles and responsibilities, how to plan and manage the work, and values to uphold
  - **Scaled Agile Framework**: agile methodology applied to large orgs; allows large organizations with multiple teams to coordinate, collaborate, and deliver products
  - **Waterfall**:
    - A linear approach to development, where each phase needs to be completed fully before the next one begins (e.g. water only flows downhill or in one direction); developed by Winston Royce in 1970, the waterfall model uses a linear sequential life-cycle approach; all project requirements are gathered up front, and there is no formal way to integrate changes as more information becomes available
    - Traditional model has 7 stages, as each stage is completed, the project moves into the next phase; the iterative waterfall model does allow development to return to the previous phase to correct defects
      - System requirements
      - Software requirements
      - Preliminary design
      - Detailed design
      - Code and debug
      - Testing
      - Operations and maintenance
    - A major criticism of this model is that it's very rigid, and not ideal for most complex projects which often contain many variables that affect the scope throughout the project's lifecycle
  - **Spiral model**: improved waterfall dev process providing for a cycle of Plan, Do, Check, Act (PDCA) sub-stages at each phase of the SDLC; a risk-driven development process that follows an iterative model while also including waterfall elements
    - following defined phases to completion and then repeats the process, resembling a spiral
    - the spiral model provides a solution to the major criticism of the waterfall model in that it allows devs to return to planning stages as technical demands and customer requirements iterate
  - **DevOps (Development and Operations)**: an approach to software development, quality assurance, and technology operations that unites siloed staff, and bring the three functions together in a single operational model; DevOps goal is to shorten the systems development lifecycle and provide continuous delivery
    - closely aligned with lean and the Agile development approach, DevOps aims to dramatically decrease the time required to develop, test, and deploy software changes
    - using the DevOps model, and continuous integration/continuous delivery (CI/CD), orgs strive to roll out code dozens or even hundreds of times per day
    - this requires a high degree of automation, including integrating code repositories, the software configuration management process, and the movement of code between development, testing and production environments
    - the tight integration of development and operations also calls for the simultaneous integration of security controls
    - security must be tightly integrated and move with the same agility
  - **DevSecOps**: refers to the integration of development, security, and operations; extends DevOps by integrating security practices
    - provides for a merger of phased review (as in the waterfall SDLC) with the DevOps method, to incorporate the needs for security, safety, resilience or other emerging properties in the final system, at each turn of the cycle of development
    - DevSecOps supports the concept of software-defined security, where security controls are actively managed into the CI/CD pipeline

- 8.1.2 Maturity models (e.g., Capability Maturity Model (CMM), Software Assurance Maturity Model (SAMM))
  - Maturity models help software organizations improve the maturity and quality of their software processes by implementing an evolutionary path from ad hoc, chaotic processes to mature, disciplined processes
  - NOTE: be able to describe the SW-CMM, IDEAL, and SAMM models
  - Software Engineering Institute (SEI) (Carnegie Mellon University) created the Capability Maturity Model for Software (AKA Software Capability Maturity Model, abbreviated SW-CMM, CMM, or SCMM)
    - **SW-CMM**: a management process to foster the ongoing and continuous improvement of an org's processes and workflows for developing, maintaining and using software
    - all software development moves through a set of maturity phases in sequential fashion, and CMM describes the principles and practices underlying software process maturity, intended to help improve the maturity and quality of software processes
    - note that CMM doesn't explicitly address security
    - stages of the CMM:
      - **Level 1: Initial**: process is disorganized; usually little or no defined software development process
        - no KPIs
        - processes are ad-hoc, and immature
        - no basis for predicting project quality, time to completion etc
        - limited project management
        - limited software dev tools or automation
        - highly dependent on individual's skills and knowledge
      - **Level 2: Repeatable**: in this phase, basic lifecycle management processes are introduced
        - focus on establishing basic project management policies
        - project planning
        - configuration management
        - requirements management
        - sub-contract management
        - software quality assurance
      - **Level 3: Defined**: in this phase, software devs operate according to a set of formal, documented software development processes; marked by the presence of basic lifecycle management processes and reuse of code; includes the use of requirements management, software project planning, quality assurance, and configuration management
        - documentation of standard guidelines and procedures takes place
        - peer reviews
        - intergroup coordination
        - org process definition
        - org process focus
        - training programs
      - **Level 4: Managed**: in this phase, there is better management of the software process; characterized by the use of quantitative software development measures
        - quantitative goals are set for software products and process
        - software quality management
        - quantitative management
      - **Level 5: Optimizing**: in this phase continuous improvement occurs
        - process change management
        - technology change management
        - defect prevention
  - **Software Assurance Maturity Model (SAMM)**: an open source project maintained by the Open Web Application Security Project (OWASP)
    - provides a framework for integrating security into the software development and maintenance processes and provides orgs with the ability to assess their maturity
    - SAMM associates software development with 5 business functions:
      - Governance: the activities needed to manage software development processes
        - this function includes practices for:
          - strategy
          - metrics
          - policy
          - compliance
          - education
          - guidance
      - Design: process used to define software requirements and develop software
        - this function includes practices for:
          - threat modeling
          - threat assessment
          - security requirements
          - security architecture
      - Implementation: process of building and deploying software components and managing flaws
        - this function includes:
          - secure build
          - secure deployment
          - defect management practices
      - Verification: activities undertaken to confirm code meets business and security requirements
        - this function includes:
          - architecture assessment
          - requirements-driven testing
          - security testing
      - Operations: actions taken to maintain security throughout the software lifecycle after code is released
        - function includes:
          - incident management
          - environment management
          - operational management
  - **IDEAL Model**: developed by SEI, a model for software development that uses many of the SW-CMM attributes, using 5 phases:
    - Initiating: business reasons for the change are outlined, support is built, and applicable infrastructure is allocated
    - Diagnosing: in this phase, engineers analyze the current state of the org and make general recommendations for change
    - Establishing: development of a specific plan of action based on the diagnosing phase recommendations
    - Acting: in this phase, the org develops solutions and then tests, refines, and implements them
    - Learning: continuously analyze efforts to achieve these goals, and propose new actions as required

  - IDEAL vs SW-CMM:

    | IDEAL | SW-CMM |
    |----------------|---------------|
    | Initiating|Initial|
    | Diagnosing  | Repeatable|
    | Establishing | Defined|
    | Acting  | Managed|
    | Learning| Optimizing|

- 8.1.3 Operations and maintenance
  - Once delivered to the production environment, software devs must make any additional changes to accommodate unexpected bugs, vulnerabilities, or interoperability issues
  - They must also keep pace with changing business processes, and work closely with the operations team (typically IT), to ensure reliable operations
    - together, ops and development transition a new system to production and management of the system's config
  - The dev team must continually provide hotfixes, patches, and new releases to address discovered security issues and identified coding errors

- 8.1.4 Change management
  - Change management (AKA control management) plays an important role when monitoring systems in a controlled environment, and has 3 basic components:
    - **Request Control**: process that provides an organized framework within which users can request modifications, managers can conduct cost/benefit analysis, and developers can prioritize tasks
    - **Change Control**: the process of controlling specific changes that need to take place during the life cycle of a system, serving to document the necessary change-related activities; or the process of providing an organized framework within which multiple devs can create and test a solution prior to rolling it out in a production environment
      - where change management is the project manager’s responsibility for the overarching process, change control is what devs do to ensure the software or environment doesn’t break when changed
      - change control is basically the process used by devs to re-create a situation encountered by a user and analyze the appropriate changes; it provides a framework where multiple devs can create and test a solution prior to rolling it out into a prod environment
    - **Release Control**: once changes are finalized, they must be approved for release through the release control procedure
      - one of the responsibilities of release control is ensuring that the process includes acceptance testing, confirming that any alterations to end-user work tasks are understood and functional prior to code release

- 8.1.5 Integrated Product Team (IPT)
  - **Integrated Product Team (IPT)**: Introduced by the US Department of Defense (DoD) as an approach to bring together multifunctional teams with a single goal of delivering a product or developing a process or policy, and fostering parallel, rather than sequential, decisions
  - Essentially, IPT is used to ensure that all aspects of a product, process, or policy are considered during the development process

## 8.2 Identify and apply security controls in development ecosystems

- Applications, including custom systems, can present significant risks and vulnerabilities, and to protect against these it's important to introduce security controls into the entire system’s development lifecycle

- 8.2.1 Programming languages
  - Computers understand 1s and 0s (binary), and each CPU has its own (machine) language
  - **Assembly language**: a way of using mnemonics to represent the basic instruction set of a CPU
  - **Assemblers**: tools that convert assembly language source code into machine code
  - Third-generation programming languages, such as C/C++, Java, and Python, are known as high-level languages
    - high-level languages allow developers to write instructions that better approximate human communication
  - **Compiled language**: converts source code into machine-executable format
    - compiled code is generally less prone to manipulation by a third party, however easier to embed backdoors or other security flaws without detection
  - **Decompilers**: convert binary executable back into source code
  - **Disassemblers**: convert back into machine-readable assembly language (an intermediate step during the compilation process)
  - **Interpreted language**: uses an interpreter to execute; sourcecode is viewable; e.g. Python, R, JavaScript, VBScript
  - **Object-oriented programming (OOP)**: defines an object to be set of a software that offers one or more methods, internal to the object, that software external to that object can request to access; each method may require specific inputs and resources and may produce a specified set of outputs; focuses on the objects involved in an interaction
    - OOP languages include C++, Java, and .NET
    - think of OOP as a group of objects that can be requested to perform certain operations or exhibit certain behaviors, working together to provide a system’s functionality or capabilities
    - OOP has the potential to be more reliable and to reduce the propagation of program change errors, and is better suited to modeling or mimicking the real world
    - each object in the OOP model has methods that correspond to specific actions that can be taken on the object
    - objects can also be subclasses of other objects and inherit methods from their parent class; the subclasses can use all the methods of the parent class and have additional class-specific methods
    - from a security standpoint, object-oriented programming provides a black-box approach to abstraction
    - OOP terms:
      - **message**: a communication to or input of an object
      - **method**: internal code that defines the actions of an object
      - **behavior**: results or output exhibited by an object
        - behaviors are the results of a message being processed through a method
      - **class**: a collection of the common methods, from a set of objects that defines the behavior of those objects
      - **instance**: objects are instances of or examples of classes that contain their methods
      - **inheritance**: occurs when the methods from a class (parent or superclass) are inherited by another subclass (child) or object
      - **delegation**: the forwarding of a request by an object to another object or delegate
      - **polymorphism**: the characteristic of an object that allows it to respond with different behaviors to the same message or method because of changes in external conditions
      - **cohesion**: describes the strength of the relationship between the purposes of the methods within the same class
        - if all methods have similar purposes, there is high cohesion, and a sign of good design
      - **coupling**: the level of interaction between objects
        - lower coupling: means less interaction
        - lower coupling provides better software design because objects are more independent, and code is easier to troubleshoot and update

- 8.2.2 Libraries
  - **Software library**: a pre-written collection of components (classes, procedures, scripts etc) that do specific tasks, useful to other components (e.g. software libraries for encryption algorithms, managing network connections, or displaying graphics)
  - Shared software libraries contain reusable code, improving developer's efficiency, and reducing the need to write well-known algorithms from scratch; often available as open source
    - shared libraries can also include many security issues (e.g. Heartbleed), and devs should be aware of the origins of the shared code that they use, and keep informed about any security vulns that might be discovered in these libraries

- 8.2.3 Tool sets
  - Forcing all devs to use the same toolset can reduce productivity and job satisfaction; however letting every dev choose their own tools and environment widens an organization's attack surface
    - a better approach is to use a change advisory board to validate developer tool requirements, assess associated risks; if approved, the sec team monitors controls
  - Developers use a variety of tools, and one of the most important is the IDE (defined below)

- 8.2.4 Integrated Development Environment
  - **Integrated Development Environment (IDE)**: software applications, their control procedures, supporting databases, libraries and toolsets that provide a programmer or team what they need to specify, code, compile, test, and integrate code; IDEs provide developers with a single environment where they can write their code, test and debug, and compile it

- 8.2.5 Runtime
  - **RunTime Environments (RTE)**: allows the portable execution of code across different operating systems or platforms without recompiling (e.g. Java Virtual Manager (JVM))
    - this is known as portable code, which needs translation between each environment, the role of the RTE

- 8.2.6 Continuous Integration and Continuous Delivery (CI/CD)
  - **Continuous Integration and Continuous Delivery**: workflow automation processes and tools that attempt to reduce, if not eliminate, the need for manual communication and coordination between the steps of a software development process
  - **Continuous integration (CI)**: all new code is integrated into the rest of the system as soon as the developer writes it, merging it into a shared repo
    - this merge triggers a batch of unit tests
    - if it merges without error, it's subjected to integration tests
    - CI improves software development efficiency by identifying errors early and often
    - CI also allows the practice of continuous delivery (CD)
  - **Continuous Delivery (CD)**: incrementally building a software product that can be released at any time; because all processes and tests are automated, code can be released to production daily or more often
  - CI/CD relies on automation and often third-party tools which can have vulnerabilities or be compromised
  - Secure practices such as threat modeling, least privilege, defense in depth, and zero trust can help reduce possible threats to these tools and systems

- 8.2.7 Software Configuration Management
  - **Software Configuration Management (SCM)**: a product that identifies the attributes of software at various points in time and performs methodical change control for the purpose of maintaining software integrity and traceability throughout the SDLC
    - SCM tracks config changes, and verifies that the delivered software includes all approved changes
    - SCM systems manage and track revisions made by multiple people against a single master software repository, providing concurrency management, versioning, and synchronization
    - auditing and logging of software changes mitigates risk to the organization by:
      - providing a detailed record of all modifications made to software applications
      - allowing security teams to identify suspicious activity
      - quickly detect unauthorized changes and investigate potential security breaches
      - and take corrective actions, ultimately protecting the integrity and confidentiality of the org's data and systems

- 8.2.8 Code repositories
  - Software development is a collaborative effort, and larger projects require teams of devs working simultaneously on different parts
  - Code repositories support collaborations, acting as a central storage point for source code
    - github, bitbucket, and sourceforge are examples of systems that provide version control, bug tracking, web hosting, release management, and communications functionality

- 8.2.9 Application security testing (e.g., static application security testing (SAST), dynamic application security testing (DAST), software composition analysis, Interactive Application Security Test (IAST))
  - **Static Application Security Testing (SAST)**: AKA static analysis, tools and technique to help identify software defects (e.g. data type errors, loop/structure bounds violations, unreachable code) or security policy violations and is carried out by examining the code without executing the program (or before the program is compiled)
    - the term SAST is generally reserved for automated tools that assist analysts and developers, whereas manual inspection by humans is generally referred to as code review
    - SAST allows devs to scan source code for flaws and vulns; it also provides a scalable method of security code review and ensuring that devs are following secure coding policies
  - **Dynamic Application Security Testing (DAST)**: AKA dynamic analysis, is the evaluation of a program while running in real time
    - tools that execute the software unit, application or system under test, in ways that attempt to drive it to reveal a potentially exploitable vulnerability
    - DAST is usually performed once a program has cleared SAST and basic code flaws have been fixed
    - DAST enables devs to trace subtle logical errors that are likely to cause security problems, without the need to create artificial error-inducing scenarios
    - dynamic analysis is also effective for compatibility testing, detecting memory leakages, identifying dependencies, and analyzing software without accessing the software’s actual source code
  - **Interactive Application Security Testing (IAST)**: the combination of SAST and DAST such application testing is done on the running system (DAST), with access to source code (SAST)

## 8.3 Assess the effectiveness of software security

- 8.3.1 Auditing and logging of changes
  - Applications should be configured to log details of errors and other security events to a centralized log repository
  - The Open Web Application Security Project (OWASP) Secure Coding Practices suggest logging the following events:
    - input validation failures
    - authentication attempts, especially failures
    - access control failures
    - tampering attempts
    - use of invalid or expired session tokens
    - exceptions raised by the OS or applications
    - use of admin privileges
    - Transport Layer Security (TLS) failures
    - cryptographic errors

- 8.3.2 Risk analysis and mitigation
  - Risk management is at the center of secure software development, in particular regarding the mapping of identified risks and implemented controls
    - this is a difficult part of secure software dev, especially related to auditing
  - Threat modeling is important to dev teams, and particularly in DevSecOps
  - Assessors are also interested in the linkages between the software dev and risk management programs
    - software projects should be tracked in the org’s risk matrix, to ensure the dev team is connected to the broader risk management efforts, and not working in isolation

## 8.4 Assess security impact of acquired software

- 8.4.1 Commercial-off-the-shelf (COTS)
  - **Commercial Off-the-Shelf (COTS)**: software elements, usually apps, that are provided as finished products (not intended for alteration by or for the end-user)
  - Most widely used commercial-off-the-shelf (COTS) software products have been security researcher (both benign and malicious) tested
    - researching discovered vulnerabilities and exploits can help us understand how seriously the vendor takes security
    - for niche products, you should research vendor certifications, such as ISO/IEC 27034 Application Security
    - other than secure coding certification, you can look for overall information security management system (ISMS) certifications such as ISO/IEC 27001 and FedRAMP (which are difficult to obtain, and show that the vendor is serious about security)
  - If you can talk with a vendor, look for processes like defensive programming, which is a software development best practice that means as code is developed or reviewed, they are constantly looking for opportunities for things to go badly
    - e.g. treating all input routines as untrusted until proven otherwise

- 8.4.2 Open source
  - Open source is typically released with licensing allowing code access and inspection so devs can look for security issues
    - typically, however, this means that there is no service or support that comes with the software and requires in-house support for configuration, and security testing
    - it also means that both open-source devs as well as adversaries are able to review the code for vulns
    - the greatest risk of open-source software is relying on outdated versions -- especially true of shared libraries
    - an org should develop processes to ensure that all open-source software is periodically updated, likely in a way that differs from the process for updating COTS

- 8.4.3 Third-party
  - **Third-party software**: (AKA outsourced software) is software made specifically for an org by a third party
    - third-party software is not considered COTS, since the software is custom or customized
    - third-party software may rely on open-source software, but since it's customized, it may have different or additional vulns
    - it's best practice to use a third-party to do an external audit and security assessment; this should be built into the vendor's contract, with passing the audit conditional for finalizing software purchase

- 8.4.4 Managed services (e.g., enterprise applications)
  - **Managed services**: can include services and assets that are available from on-premises resources (e.g. within the organization) or cloud-based; as organizations move more functionality to the cloud, they reap cloud-based conveniences (e.g. pay only for on-demand resource use, easy scalability etc.) but lose a degree of control since a portion of cloud-based resources are outside the org's control
  
- 8.4.5 Cloud services (e.g., Software as a Service (SaaS), Infrastructure as a Service (IaaS), Platform as a Service (PaaS))
  - As orgs continue to migrate to the cloud (SaaS, IaaS, PaaS), they should increase the security assessment of those services
  - The top reasons for cloud breaches continues to be misconfigurations, lack of visibility into access settings, and poor access controls
    - cloud service providers have tools to help mitigate these issues, and orgs should consider bringing in third-party experts to help if they don't have the internal expertise
  - **Anything as a Service (XaaS)**: catchall term referring to any type of computing service that provides value to customers via a cloud solution

## 8.5 Define and apply secure coding guidelines and standards

- **Secure Coding Guidelines and Standards**: best practices identified by a variety of software and security professionals, that when used correctly can dramatically reduce the number of exploitable vulnerabilities introduced during development

- 8.5.1 Security weaknesses and vulnerabilities at the source-code level
  - A source code vulnerability is a code defect providing a threat actor with an opportunity to compromise the security of a software system
    - source code vulns are caused by design or implementation flaws
    - **design flaw**: if dev did everything correctly, there would still be a vulnerability
    - **implementation flaw**: dev incorrectly implemented part of a good design
  - the OWASP top 10 vulnerabilities for 2024:
    - Broken access control
    - Cryptographic failures
    - Injection
    - Insecure design
    - Security misconfiguration
    - Vulnerable and outdated components
    - Identification and authentication failures
    - Software and data integrity failures
    - Security logging and monitoring failures
    - Server Side Request Forgery (SSRF)

- 8.5.2 Security of Application Programming Interfaces (APIs)
  - **Application Programming Interface (API)**: specifies the manner in which a software component interacts with other components
    - API's reduce the effort of providing secure component interactions by providing easy implementation for security controls
    - API's reduce code maintenance by encouraging software reuse, and keeping the location of changes in one place
    - **Parameter validation**: ensuring that any API parameter is checked against being malformed, invalid, or malicious helps ensure API secure use; validation confirms that the parameter values being received by an app are within defined limits before they are processed by the system

- 8.5.3 Security coding practices
  - Secure coding practices can be summarized as standards and guidelines
    - **standards**: mandatory activities, actions, or rules
    - **guidelines**: recommended actions or ops guidelines that provide flexibility for unforeseen circumstances
    - orgs greatly reduce source code vulns by enforcing secure coding standards and maintaining coding guidelines that reflect best practices
  - To be considered a standard, coding practice must meet the following:
    - reduces the risk of a particular type of vuln
    - enforceable across all of an org's software development efforts
    - verifiably implemented
  - Note: secure coding standards, rigorously applied, is the best way to reduce source code vulns; coding standards ensures devs always do certain things in a certain way, while avoiding others
  - Secure coding guidelines are recommended practices that tend to be less specific than standards
    - e.g. consistently formatted code comments, or keeping code functions short/tight

- 8.5.4 Software-defined security
  - **Software-defined security (SDS or SDSec)**: a security model in which security functions such as firewalling, IDS/IPS, and network segmentation are implemented in software within an SDN environment
    - one of the advantages of this approach is that sensors (for systems like IDS/IPS) can be dynamically repositioned depending on the threat
    - SDS provides a decoupling from physical devices, because it abstracts security functions into software that can run on any compatible physical or virtual infrastructure, critical for supporting cloud services dynamic scaling and virtualized data centers
  - DevSecOps supports the concept of software-defined security, where security controls are actively managed into the CI/CD pipeline
