# drvscanner
Scan for potentially vulnerable drivers from every .sys on the target machine.

## Usage
- Drag exported .efu file from "Everything" onto the drvscanner program.
- Edit the target imports in the "targetImports" vector in main.cpp.
- By default "IoCreateDevice" is always added even if not specified in the targetImports.
