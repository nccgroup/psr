/*
Copyright 2017 NCC Group

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#include "stdafx.h"
#include <iostream>
#include <Windows.h>
#include "debugger.h"
#include <memory>


int main()
{
	DWORD target_pid;
	LPVOID target_address;

	std::cout << "Enter PID of target process: " << std::endl;
	std::cin >> target_pid;

	std::cout << "Enter address of interest in hexadecimal (without 0x): " << std::endl;
	std::cin >> std::hex >> target_address;

	std::unique_ptr<Debugger> debugger(new Debugger);
	debugger->SetTargetPID(target_pid);
	debugger->SetTargetAddress(target_address);

	debugger->Attach();

	// get each thread debug message
		// make a new record trace object for each thread
		// set trap flag on each thread

	// then set memory breakpoint

	// then wait for it to be hit
		// then pull run trace for that thread

	//while (TRUE)
	//{
		/*
		lets try dumber approach of setting mem bp and recording
		just do a sanity check that the last instruction recorded actually
		hits the mem bp


		*/
		debugger->StartRecordingRegisterModifications();
		debugger->SetMemoryBreakpoint(target_address);
		std::cout << "waiting for memory access..." << std::endl;
		if (!debugger->WaitForMemoryBreakpoint())
		{
			std::cout << "Error in WaitForMemoryBreakpoint()" << std::endl;
		}

		//debugger->PrintRegisterChanges();
		//debugger->AnalyzeRunTrace();
	//}

    return 0;
}
