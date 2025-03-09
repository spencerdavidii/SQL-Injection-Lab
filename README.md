# SQL-Injection-Lab


## Objective
[Brief Objective - Remove this afterwards]

The Sql injection lab from LetsDefend helped me enhance my practical skills in identifying and mitigating SQL injection attacks within web applications. For this lab,I searched for vulnerabiltiites within web apachi logs.I discovered the exploitation phase of when the SQL injection attack occured,identified the type of SQL injection attack, and uncovered the IP address of the attacker who performed the attack. This hands on experience was designed to deepen my understanding of web application security. 


### Skills Learned
[Bullet Points - Remove this afterwards]

- Web Server Log Analysis – Reviewed Apache access/error logs to detect SQL injection attempts and other web-based attacks.
- Incident Response & Forensics – Investigated SQLi attacks, documented findings, and provided remediation steps.
- Mitigation & Defense Strategie- Implentmented input validation to prevent SQL attacks in the future. 
- Secure Coding Awareness – Gained knowledge of secure web development practices to prevent injection vulnerabilities.
- Followed structured offensive security methodologies (e.g., OWASP Top 10, PTES) to identify and exploit SQLi vulnerabilities.

### What is a SQL injection attack?
![image](https://github.com/user-attachments/assets/ec6fde7a-d68d-4a69-9e1c-e35676c119a7)
A SQL injection is a type of cyber attack where a hacker tricks a website into giving them unauthorized access to its database.
 
### How Does SQL injections attack work?
SQL injections attacks occur when hackers take advantage of weak spots in websites that store and manage information. They sneak in harmful code through text boxes like login screens or search bars. If the website isn’t set up to block this, the database follows the hacker’s commands. This can lead to the hacker breaking into accounts without a password, change or delete important information, and take control of the database system.

### LETSDEFEND LAB 
Now since I have elaborated on what is a SQL injection attack. I will now walk through the lab identifying when were the Apache access logs invaded. I utilized Letsdefend sandbox virtual machine to complete this process as well. 
![SQL Injection finder](https://github.com/user-attachments/assets/c676df15-14ac-4326-8e9f-a78cbcce972e)
 " APACHE ACCESS LOGS SCREENSHOT " 
 
My first step was inserting = command in the finder tool. This operator is used for comparisons in SQl queries which allowed me to see changes in input values passed to the web application logs.I analyzed the input values "id=2&Submit=Submit and "id=%27&Submit=Submit" displayed two different requests."In the input value "id=%27&Submit=Submit"; 27% represents a URL-encoded single quote ('), a known SQL Injection attack indicator.If an attacker modifies the input value to compare a normal request (id=2) with a malicious request (id=%27),this can signal tampering. Furthmore; apostrophes ('), dashes (-), and special characters are malicious values commonly used in SQL attacks. 

After detecting the malicious value 27%, I concluded the attack began March 1st, 2022 08:35:14 on log 147 as seen in the screenshot below.Although, the = operator was found on logs 145 and 146 as well. Their input values were normal SQL queries, so that is why the attack didnt start there. 
![SQL Injection finder highlighted Pinpoint ](https://github.com/user-attachments/assets/02b7726e-6c99-4f97-b5ac-c610b3e0fb62)
"The green highlights the attack date and the blue circles the input values signaling different requests"







## Steps
drag & drop screenshots here or use imgur and reference them using imgsrc

Every screenshot should have some text explaining what the screenshot is about.

Example below.

*Ref 1: Network Diagram*
