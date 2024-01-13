# AngryGhidra

<p align="center"><img src="./images/angryGhidraIcon.png" width="360" height="250">

The plugin allows you to use [angr](https://github.com/angr/angr) for binary analysis and symbolic execution in Ghidra interface.

Solving [CTF challenge from SecurityFest 2016 "fairlight"](https://github.com/angr/angr-doc/blob/master/examples/securityfest_fairlight/fairlight) with AngryGhidra plugin:

![AngryGhidra Plugin](./images/AngryGhidraPlugin.gif)

# Screenshots

![AngryGhidraView](./images/AngryGhidraView.png)

Apply patched bytes to write them to the memory of angr project:

![ApplyPatchedBytes](./images/ApplyPatchedBytes.png)

# Hotkeys

##### Set:  
`Z` – address to **find** (destination address that you want angr should run to)  
`X` – **start** address  
`J` – **avoid** address (multiple choice)  

##### Reset: 
`K` – address to **find**  
`T` – **start** address  
`P` – **avoid** address 

##### Apply bytes:
`U` – apply patched bytes to angr project memory

# Installation
  
1) `pip3 install angr`
2) Make sure `python3` directory is added to the `PATH` (required, `Python 3` only)
3) Download the release version of the plugin and install it in Ghidra `File → Install Extensions...` 
4) Use Gradle to build the plugin: `GHIDRA_INSTALL_DIR=${GHIDRA_HOME} gradle` and use Ghidra to install it: `File → Install Extensions...` 
5) Check the box in the "New Plugins Found" window to apply AngryGhidra plugin to your project
