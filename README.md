## Overview

**emotet-loader** is a small but practical tool to successfully execute Emotet modules in isolation. It allocates the required data structures, invokes the custom entry point, while allowing customization of the execution environment. It easily allows dynamic analysis without depending on the core module potentially infecting the system, thereby enabling security research tasks such as debugging, IoC extraction, or analysis of the resulting network activity (critical when analyzing Emotet modules that are able to propagate laterally). To further simplify analysis at scale, emotet-loader offers an option to embed the module and the loader together into a standalone executable, making it the perfect candidate for automated submissions to standard sandboxes.  

## What is Emotet?

Emotet is one of the most prominent multi-component threats in recent years. Besides the core component, which is often attached to a spam email or downloaded from a malicious URL, Emotet is known to retrieve from its C2 infrastructure additional modules; these modules can be either designed to propel its own operations by, for example, stealing email credentials to be used in future spam waves, or, when the attack is more targeted, engineered to be more a destructive artifact, like ransomware provided by an affiliated group. 

These additional components are meant to be executed by the core module directly from memory, and they are never dropped on disk. Even when payload extraction using dynamic analysis techniques succeeds, loading the extracted modules in isolation inexorably fails as the existence of a custom entry point requires specially crafted data structures to be allocated in memory. These data structures are normally allocated by the core module for various purposes, with only a portion being required by the loaded module. 

## Try it out

### Prerequisites

* Visual Studio 2022 and higher (including the Community Edition, which is free to use).

### Build

How to build the tool:
1. Download [Visual Studio](https://visualstudio.microsoft.com/downloads/).
2. Open emotet-loader.vcxproj in Visual Studio.
3. Go to menu `Build` -> `Build Solution` or press Ctrl+Shift+B.
4. The resulting emotet-loader64.exe will appear in `x64\Debug` or `x64\Release` folder.

### Run

Usage: 
`emotet-loader64.exe -d ${dll_path} -e ${epoch} [-c ${computer_name}] [-s ${root_serial}] [-o ${output_path}]`

Where:
* `${dll_path}` is the path to the Emotet module the be loaded (mandatory parameter). 
* `${epoch}` is the identifier of the epoch (i.e., a specific Emotet botnet) that the module belongs to; only identifiers to currently online botnets are supported, i.e., either 4 or 5 (mandatory parameter).
* `${computer_name}` specifies the computer name; the tool generates a random computer name if this parameter is not specified. 
* `${root_serial}` specifies the C: volume serial number, which is a 32-bit hexadecimal number; the tool will generate a random serial number if this parameter is not specified. 
* `${output_path}` is the output file path when using the “-o” option; this option builds a standalone executable containing the module rather than loading the module. 

Specifying computer name and root serial allows for the customization of the execution environment; while we have not seen any modules blacklisting specific computer names and root serials, Emotet modules contacting the botnet are known to get blacklisted based on specific values corresponding to known sandboxes. 

Example of a command loading an Emotet module (coming from the epoch 5 botnet) with computer name WIN-1234 and C: volume serial number 0x123ABC: 
`emotet-loader64.exe -d C:\path\to\emotet-module.dll -e 5 -c WIN-1234 -s 0x123ABC`

Example of a command embedding an Emotet module (coming from the epoch 5 botnet) into a standalone executable, with random computer name and random C: volume serial number: 
`emotet-loader64.exe -d C:\path\to\emotet-module.dll -e 5 -o emotet-standalone-module.exe`

The executable emotet-standalone-module.exe, requiring no parameters, will drop the original emotet-module.dll on disk and then load it into memory; the computer name and the C: volume serial number will be generated automatically at each execution (unless specified when running emotet-loader64.exe). 

### Examples

Let's perform a quick analysis of two Emotet modules:
1. Thunderbird Email Client account stealer from epoch 5 with SHA1 `0a610c6de3419ce165d05d770637c8084d584ffd`.
2. Outlook Email Client account stealer from epoch 4 with SHA1 `a7bfaf7bc8528013bd460bef2a56adc7c5daf0ae`.

The Hybrid Analysis sandbox [shows](https://www.hybrid-analysis.com/sample/58d9d7c2d4a4140bbdc16c9b6ab1b56244ebc8b1c3eaa1fc63386bbce7acdb4c/63722b5c17290b68447e9951) that the Thunderbird account stealer tries to open the `%APPDATA%\THUNDERBIRD\PROFILES` folder, where Thunderbird saves personal information such as messages, passwords and user preferences. The sandbox detects this behavior as `Tries to steal browser sensitive information (file access)`.

The Intezer sandbox [shows](https://analyze.intezer.com/analyses/d2aa6c12-c50d-4f2b-a7f2-b0a6803a97ba/behavior) that the Outlook account stealer reads `HKEY_LOCAL_MACHINE\SOFTWARE\Clients\Mail\Microsoft Outlook\DLLPathEx`, where the path to msmapi32.dll is stored. This library can be used to access the Outlook's sensitive information such as messages, passwords and user preferences.

## Contributing

The emotet-loader project team welcomes contributions from the community. Before you start working with emotet-loader, please
read our [Developer Certificate of Origin](https://cla.vmware.com/dco). All contributions to this repository must be
signed as described on that page. Your signature certifies that you wrote the patch or have the right to pass it on
as an open-source patch. For more detailed information, refer to [CONTRIBUTING.md](CONTRIBUTING.md).

