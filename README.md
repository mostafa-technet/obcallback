# Anti Signed Exe Degrade

## Introduction
`Anti Signed Exe Degrade` is a security driver designed to enhance the integrity of process creation on Windows systems. It is a part of a comprehensive anti-ransomware suite that prevents unsigned executables from creating signed processes, thereby mitigating the risk of system compromise through process manipulation.

## Features
•  [**Process Creation Validation**]: Ensures that only signed executables can create new signed processes.

•  [**Callback Registration**]: Utilizes control callbacks for process protection, registered at system startup.

•  [**Command Line Scrutiny**]: Examines the command line of a process creation request to determine its legitimacy.

•  [**Access Right Restrictions**]: Uses callbacks to restrict access rights during an open process action, preventing unauthorized modifications.


## Design and Operation
The driver employs two key routines for its operation:
•  `ObRegisterCallbacks`: Restricts requested access rights during an open process action.

•  `PsSetCreateProcessNotifyRoutineEx`: Rejects process creation based on command line analysis.


## Getting Started
To integrate `Anti Signed Exe Degrade` into your system, clone the repository and follow the build instructions:

```bash
git clone https://github.com/mostafa-technet/AntiSignedExeDegrade.git

Prerequisites
•  Windows operating system with support for driver installation

•  Development environment with Windows Driver Kit (WDK)

Installation
Build the driver using the WDK and install it on the target system following the provided installation guide.

Usage
Once installed, the driver will automatically start with the system and begin monitoring process creation events.

Contributing
Contributions to Anti Signed Exe Degrade are welcome. Please read the contributing guidelines for more information on how to submit pull requests or report issues.

License
This project is licensed under the MIT License - see the LICENSE file for details.

Acknowledgments
•  The cybersecurity community for their insights into process protection

•  Contributors who have helped refine the driver's capabilities
