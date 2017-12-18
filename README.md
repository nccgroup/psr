# Pointer Sequence Reverser

Designed to help a reverse engineer easily see how a Windows C++ application is accessing a particular data member or object.

Given the memory address of a data member or object, this tool will set a memory breakpoint at that address and then produce traces of the instructions executed prior to reading from or writing to that address. Some processing will be performed on the trace to highlight relevant instructions, make the output more readable, identify vtable pointers, etc.

To build, you'll want to download and build Capstone from its "next" branch. Then, configure the PSR solution to look inside the necessary Capstone directories for the .h and .lib files. 