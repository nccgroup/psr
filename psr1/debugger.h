/*
Copyright 2017 NCC Group

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

#pragma once
#include <Windows.h>
#include <map>
#include <vector>
#include <string>
#include <memory>
#include "capstone.h"
#include "Tracer.h"


class Debugger
{
public:
	Debugger();
	~Debugger();

	int SetTargetPID(DWORD target_pid);
	int SetTargetAddress(LPVOID target_address);
	int Attach();
	int SetMemoryBreakpoint(LPVOID target_address);
	int RemoveMemoryBreakpoint();
	int WaitForMemoryBreakpoint();
	int SetSoftBreakpoint(LPVOID target_address);
	int StartRecordingRegisterModifications();
	int CleanUpAndExit();
	//int PrintRegisterChanges(DWORD thread_id);

private:
	DWORD target_pid;
	LPVOID target_address;
	HANDLE target_handle = NULL;
	std::map<LPVOID, char> soft_breakpoint_list;
	LPVOID instruction_address;
	//CONTEXT saved_thread_context;
	std::vector<DWORD> target_thread_IDs;

	std::map<DWORD, HANDLE> thread_handles;

	// Tracer: csh cs_handle = NULL;

	// Not needed: std::map<DWORD, std::vector<std::map<std::string, DWORD>>> all_threads_register_changes;

	// Tracer: std::map<DWORD, CONTEXT> all_threads_saved_contexts;

	// map<thead ID, list of instructions for that thread>
	// vector<instruction info>
	// tuple<instruction address, asm code, register changes>
	// map<modified register, new value>
	// Tracer: std::map<DWORD, std::vector<std::tuple<DWORD, cs_insn, std::map<std::string, DWORD>>>> all_threads_saved_instructions;

	size_t MAX_TRACE_LENGTH = 50;
	size_t max_insn_size = 15;
	DWORD orig_protect;

	//std::map<unsigned int, std::vector<cs_insn>>

	BOOL IsMemoryBreakpointHit(const DEBUG_EVENT& debug_event);
	LPVOID GetInstructionPointer(const DEBUG_EVENT& debug_event);
	int SetTrapFlag(DWORD thread_id);
	int GetCurrentThreadContext(DWORD thread_id, CONTEXT &thread_context);
	//int SaveRegisterChanges(DWORD thread_id, const CONTEXT &thread_context);
	BOOL ListProcessThreads(DWORD dwOwnerPID);
	//int SaveInstructionInfo(DWORD thread_id, const CONTEXT& thread_context);
	//int PrintRunTrace(DWORD thread_id);
	//int AnalyzeRunTrace(DWORD offending_thread_ID, CONTEXT thread_context, uint16_t register_ID, uint8_t read_count);
	//int PrintAnalysis(DWORD offending_thread_ID, unsigned int analysis_ID);

	std::unique_ptr<Tracer> tracer = NULL;
};

