# f______ simple configuration management

This library was written to avoid having to use Ansible. It aids common
configuration management tasks by offering a basic set of quickly usable Pythonic 
tools required for system management. Remote execution is enabled by an optional
dependency on `mitogen`.

It is in use by me and currently under a good deal of change.

## Goals/non-goals

- allows writing fully-featured configuration management in Python
- easy to use without precluding granular execution options and change logging
- targets Unix systems only
