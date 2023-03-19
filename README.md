# AngryGhidra

<p align="center"><img src="./images/angryGhidraIcon.png" width="360" height="250">

The plugin allows you to use [angr](https://github.com/angr/angr) for binary analysis and symbolic execution from Ghidra interface.

Solving [CTF challenge from SecurityFest 2016 "fairlight"](https://github.com/angr/angr-doc/blob/master/examples/securityfest_fairlight/fairlight) with AngryGhidra plugin:

![AngryGhidra Plugin](./images/AngryGhidraPlugin.gif)

# Screenshots

![AngryGhidraView](./images/AngryGhidraView.png)

Apply patched bytes to write them to the memory of angr project:

![ApplyPatchedBytes](./images/ApplyPatchedBytes.png)

# Installation
  
- `pip3 install angr` at first
- Make sure that python3 directory added to the `PATH` (required, `python3` only)
- Download Release version of extension and install it in Ghidra `File → Install Extensions...` 
- Use gradle to build extension: `GHIDRA_INSTALL_DIR=${GHIDRA_HOME} gradle` and use Ghidra to install it: `File → Install Extensions...` 








