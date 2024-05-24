# XML External Entities (XXE) Injection and Protection

This project, undertaken as part of the Cybersecurity course, aimed to demonstrate vulnerabilities and protection mechanisms against XML XXE injections.

## Objective
The primary objective was to develop a secure distributed file system while exploring vulnerabilities associated with XML XXE injections. Additionally, the project aimed to evaluate the implemented code using various static code analysis tools.

## Implementation Details
### User Interface
- The user interface was designed using HTML and CSS to provide a seamless experience for users.
- Features included login and signup functionalities, with session management incorporated for enhanced security.

### Vulnerable API
- An API was developed to simulate vulnerabilities associated with XML XXE injections.
- Vulnerabilities included the billion laughs attack and the ability to parse external references such as reading from files or the network.
- The vulnerable API served as a demonstration platform for understanding the impact of XXE vulnerabilities.

### Secure API
- Another API was developed with robust security measures to mitigate XML XXE injection attacks.
- Security measures included input validation, sanitization, and access controls to prevent unauthorized access and malicious injections.
- The secure API served as a model for implementing best practices in safeguarding against XXE vulnerabilities.

### Static Code Analysis
- Static code analysis tools such as Bandit, Protector, Rough-Auditing-Tool-for-Security, and PYT were employed to evaluate the codebase.
- The analysis aimed to identify potential vulnerabilities and adherence to best practices in code development.

## Evaluation
The project underwent thorough evaluation to assess its effectiveness in demonstrating vulnerabilities and protection mechanisms against XML XXE injections. The evaluation included:
- Functional testing of the APIs to verify their behavior under different scenarios.
- Analysis of static code analysis reports to identify and address potential vulnerabilities.
- Review of the user interface for usability and security considerations.

## Conclusion
The project successfully demonstrated the importance of addressing XML XXE vulnerabilities in software development. By implementing both vulnerable and secure APIs, participants gained valuable insights into the techniques used to exploit and mitigate XXE injection attacks. The use of static code analysis tools provided additional validation of the codebase's security posture.

For detailed insights into the project's implementation, refer to the code repository on GitHub.


## How to Run

### Commands to run this program
#### Run flask without pipenv
- pip install flask flask-sqlalchemy flask-marshmallow marshmallow-sqlalchemy dicttoxml lxml
- pip install Jinja2
- python db_create.py (if db.sqlite does not exist)
- python app.py

#### Run flask with pipenv
- pip install pipenv
- pipenv shell
- pipenv install (PipFile contains the packages needed)
- python db_create.py (if db.sqlite does not exist)
- python app.py
