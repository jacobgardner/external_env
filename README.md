External Env Variable Viewer
============================

This package was developed to assist in viewing the environment variables of other processes by PID in a cross-platform, cross-architecture API.

Current State
-------------

 * Most of my work thus far has been in accessing the environment variables of processes under windows.  
 	Currently it has been tested on Windows 7 x64 using 32-bit python.  You cannot view the environment variables of processes that you cannot 
 	access through OpenProcess.  These are usually programs executed with elevated privileges or under another user.  Programs like ProcessHacker 
 	have a kernel-mode driver that can access the memory of these programs.