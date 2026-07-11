# Security policy

Report vulnerabilities to **security@seclave.se**, or privately via GitHub's
"Report a vulnerability" on this repository. Please do not open a public
issue for a security problem.

This is a host-side tool. The Seclave device's own screen-and-joystick
confirmation is the security boundary for secrets; issues in this app
matter most where they could undermine that model (for example, sending
input the device mishandles) or expose secrets on the host beyond what the
README documents.
