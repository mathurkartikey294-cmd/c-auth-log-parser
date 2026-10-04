# C Auth Log Parser
First EHAX Project
A simple cybersecurity-focused authentication log parser written in **C**.
This project reads authentication logs, extracts useful information, detects suspicious login activity, and generates a security report.
## Features
* Parse authentication logs
* Extract:
  * Username
  * IP address
  * Login status
* Detect failed login attempts
* Detect suspicious users
* Detect suspicious IP addresses
* Generate authentication statistics
* Use dynamic memory allocation
* Search users from parsed logs
* Export security data to JSON
* Command-line log file input
## Suspicious Activity Detection
A user is considered suspicious when they have **3 or more failed login attempts inside a time frame of 10seconds**.
An IP address is considered suspicious when it has **3 or more failed login attempts inside a time frame of 10 seconds **.
Example:
Failed login → rahul → 192.168.1.10
Failed login → rahul → 192.168.1.10
Failed login → rahul → 192.168.1.10
OUTPUT:-
Suspicious User: rahul
Suspicious IP: 192.168.1.10
## Log Format
The project works with authentication logs similar to:
Oct 2 08:01:12 ubuntu-server sshd[1201]: Accepted password for rahul from 192.168.1.10 port 52344 ssh2
The parser extracts relevant authentication information from these entries.
## Technologies Used
* C
* File Handling
* Structures
* Pointers
* Dynamic Memory Allocation
* String Manipulation
* Command-Line Arguments
* JSON
## JSON Output
Like
   json
{
    "username": "rahul",
    "ip": "192.168.1.10",
    "status": "success"
}

## Project Structure
C-Log-Parser/
 1.main.c
 2.auth.log
 3.final_output.json 
 4.README.md
 5..gitignore
## Author
**Kartikey Mathur**
Cybersecurity / C Programming Project
> Built as a learning project to understand authentication logs, C programming, memory management, and basic security analysis.
