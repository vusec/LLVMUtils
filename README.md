# LLVM Utilities Library

This repository contains a number of generic LLVM utility functions that can be used in different
LLVM passes or tools. Some functionalities may/will overlap with utilities available in the
official LLVM code-base. The utilities can either be included in their entirity, or as their
header and the available dynamic shared library.

## Extensions

These utility functions are mostly based on specific behaviours I needed in my own projects --
be they personal or professional -- but are not strictly specific to that project. A large number
of these functions are based on LLVM version 13, as that is what I needed to use in the project I
was working on while writing many of these utilities. Some, as such, have already been incorporated
into the main LLVM code-base and could thus be considered redundant.
