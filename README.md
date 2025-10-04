# GVM-Utilities
GVM Python Utility Scripts
## Authentication
Add the env var GVM_USER and GVM_PASS to your shell config file (ie. .zshrc or .zsh_profile)
Example:
```sh
export GVM_USER=<user>
export GVM_PASS=<pass>

source ~/.zshrc
```
## actionTask.py 
Start, Stop, Pause, Resume a task
## createTask.py 
Creates and starts a new task (scan) 
## checkTaskStatus.py
Check the status of all task or a single task. Also, gives you the ability to list the vulns found excluding logging events (though this can be enabled by editing the script severity filter inside the code). 
## nmapLikeOutput.py
Displays vulns like you would expect an nmap scan to display (kinda). Takes a task id for an argurment. 
## downloadReport.py 
Download a report that is AttackForge friendly. Supply the script a task id which can be gathered from  `checkTaskStatus.py --mode status` 

<img width="943" height="338" alt="image" src="https://github.com/user-attachments/assets/9a054088-e740-44c2-b555-2b65fa60143e" />
