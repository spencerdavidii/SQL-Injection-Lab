# SQL-Injection-Lab




The Sql injection lab from LetsDefend helped me enhance my practical skills in identifying and mitigating SQL injection attacks within web applications. For this lab,I searched for vulnerabiltiites within Apachi access logs.I discovered the exploitation phase of when the SQL injection attack occured,identified the type of SQL injection attack, and uncovered the IP address of the attacker who performed the attack. This hands on experience was designed to deepen my understanding of web application security. 


### Skills Learned

- Web Server Log Analysis – Reviewed Apache access/error logs to detect SQL injection attempts and other web-based attacks.
- Incident Response & Forensics – Investigated SQLi attacks, documented findings, and provided remediation steps.
- Secure Coding Awareness – Gained knowledge of secure web development practices to prevent injection vulnerabilities.
- Followed structured offensive security methodologies (e.g., OWASP Top 10, PTES) to identify and exploit SQLi vulnerabilities.
### Objectives 
- Understand the fundamentals of SQL injection.
- Perform ethical SQL injection attacks in a controlled environment.
- Learn best practices for securing web applications.

### How Does SQL injections Attacks Work?
A SQL injection is a type of cyber attack where a hacker tricks a website into giving them unauthorized access to its database.By sneaking in special commands where the site expects normal text, they can steal, change, or even erase important data. This happens when the website doesn’t properly check what users type in, making it easier for hackers to break in.
![image](https://github.com/user-attachments/assets/ec6fde7a-d68d-4a69-9e1c-e35676c119a7)

### LETSDEFEND LAB: Identify The Initial Start Of The Attack
I will now walk through the lab identifying when were the Apache access logs invaded. I utilized Letsdefend sandbox virtual machine to complete this process as well. The screenshot belows shows log file from a web server, showing requests made by an attacker. Each line represents a request to a webpage, and some of these requests contain SQL Injection attempts.


![SQL Injection finder](https://github.com/user-attachments/assets/c676df15-14ac-4326-8e9f-a78cbcce972e)
 **The Apache Access Logs Invaded In The Virtual Machine**
 
My first step was inserting = command in the finder tool. This operator is used for comparisons in SQl queries which allowed me to see changes in input values passed to the web application logs.I analyzed the input values "*id=2&Submit=Submit*  and "*id=%27&Submit=Submit*" displayed two different requests."In the input value "id=%27&Submit=Submit"; 27% represents a URL-encoded single quote ('), a known SQL Injection attack indicator.If an attacker modifies the input value to compare a normal request (id=2) with a malicious request (id=%27),this can signal tampering.
Additionally; apostrophes ('), dashes (-), and special characters are malicious values commonly used in SQL attacks. 

After detecting the malicious value 27%, I concluded the attack began March 1st, 2022 08:35:14 on log 147 as seen in the screenshot below.Although, the = operator was found on logs 145 and 146 as well. Their input values were normal SQL queries, so that is why the attack didnt start there. 
![SQL Injection finder highlighted Pinpoint ](https://github.com/user-attachments/assets/02b7726e-6c99-4f97-b5ac-c610b3e0fb62)
**The Input Values Signaling Different Requests**

### LETSDEFEND LAB: Which IP address was utilized for the SQL injection attack? 
IP addresses play an important role in cyberattacks, as attackers use them to find targets and intentionally change or steal data.
In the logs, multiple requests stem from 192.168.31.167.Seeing the same IP address repeatedly testing different SQLi payloads confirmed bad intentions. 
Proved that this was not accidental but a deliberate SQL Injection attack.
![SQL Injection finder highlighted IP address](https://github.com/user-attachments/assets/2ec21b6e-478b-4c8d-a451-6dc23f213e5d)
**The IP Address detected For The Initial Attack**
### LETSDEFEND LAB:Did The Attacker Execute The SQL Injection Attack Succcesfully?
The SQL Injection attack was likely successful because the attacker started with simple tests and then moved to more advanced commands. At 08:35:14, they tested by adding a single quote ('), which is a common way to check if a website is vulnerable. Later, at 08:37:10 and 08:38:16, they used more complex commands like "OR 1=1" and "UNION SELECT", which are often used to steal data from a database.![SQL Injection finder highlighted union commands](https://github.com/user-attachments/assets/b2071f5c-53cc-4540-b7a9-70d4c2778fe2)
**Complex Commands Utilized For The SQl injection Attack**


 The server responded with 200 status codes, meaning it processed the request without an error, suggesting that the attack worked. However, if the attacker had received an error (like 500 or 403), it would mean the attack failed. Since the attacker kept trying different commands, it looks like they were able to get some useful information from the database.
![SQL Injection finder highlighted IP address](https://github.com/user-attachments/assets/697e01f9-e108-42f9-9ecf-cd08698522d8)
**The Status Code Analyzed In The Attack**

### LETSDEFEND LAB: The Importance Of Status Codes While Detecting Web Application Attacks. 
Also, knowing status codes helped anaylze the logs for SQL injection attacks.In the infected logs, the HTTP request return to 200 continues to showcase. 
![SQL Injection finder highlighted http status codes](https://github.com/user-attachments/assets/31d3ce7c-b359-4368-a379-b6f20ab61795)
 **Status Code 200**
This indicates that the SQL injection attack was successful, aiding the attacker in receiving useful information from the database. 
By monitoring these responses, cybersecurity professionals can detect threats early, mitigate security risks, and prevent systems from being hacked.
I listed a few status codes to remember while dealing with web attacks. 
200, 201, 204 → Attack may have worked (SQLi/XSS succeeded).
403, 401, 405 → Attack was blocked (WAF or security settings)
 500, 502, 504 → Attack caused errors (possible SQLi or DoS attempt)

### LETSDEFEND LAB: The Type of SQl Injection Attack That Occurred
The SQl Injection that occurred in this lab was an in-band attack formeely known as classic.
I realized the hacker followed a step-by-step process to break into the website by manipulating the database through a web form. When the hacker began at 08:35:14 timestamp, The attacker sent a request with "Id=527&submit=submit" to get a response. The hacker checked if the website would give an error. Since the 200 error code occurred, The attacker knows the website is vulernable to attack. 
![Identifying the attack screenshot ](https://github.com/user-attachments/assets/192239b5-befa-44be-bf4b-2424aaf56811)
**08:35:14 Timestamp**
The atacker started his second sql injection attempt at 08:37:10. In this sequence , the atacker changed the request to id=%27+OR+1%3D1+--+&Submit=Submit. In the same input value, or 1=1 was added to trick the website into allowing access without a real password. 
![SQL Injection attack escalation ](https://github.com/user-attachments/assets/11f2363c-7220-4a95-a69a-043a13eb579a)
**08:37:10 Timestamp**

Once the hacker received the password, they are digging deeper to learn more about the system at 08:38:16 timestamp. They completed this step by insertng "id=%27+OR+1%3D1+UNION+SELECT+null%2C+version%28%29+--+"
into the web logs, the malicious input value helped them confirm the website is vulnerable which could lead to executing bigger attacks. 
![SQL 0836 timestamp](https://github.com/user-attachments/assets/14c4e294-48b0-45da-b2ad-7f302a953031)
**08:38:16 Timestamp**


**Summmarization of SQL Injection Attacks**
In this LetsDefend lab, I learned how attackers can trick a website into giving them access to hidden information by entering special commands in places like login forms. This helped me understand how important it is to properly secure websites so that they don’t accidentally expose sensitive data. I also gained hands-on experience in identifying weak points in a system and how hackers might try to take advantage of them. Most importantly, I would suggest using safer security tools to protect database or web application logs. 

**Safety Measures to Prevent SQL Injections Attacks**

For instance, I would have impletmented a web application firewall (WAF) to protect the Apache web application logs. A web application firewall acts as a security shield between users and a web application. WAF can identify and block sql injection attempts before they invade the web application. This helps add another layer of protection. 
Additionally, I would have selected implementing input validation. Essentially, input validation is like a security guard for a web application. Input validation checks everything users type into a form. This includes usernames, passwords, and  emails—to make sure it's correct and safe before letting it through. This helps stop hackers from sneaking in harmful commands, keeps the system from breaking, and makes sure the data stays clean and accurate. By using input validation, websites can protect user information, prevent errors, and make the experience smoother for everyone.


