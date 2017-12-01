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
