# GVM-Utilities
GVM Python Utility Scripts
## Authentication
Add the GVM_USER and GVM_PASS to your shell config file (ie. .zshrc or .zsh_profile)
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

