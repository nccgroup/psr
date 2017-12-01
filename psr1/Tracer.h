#pragma once
#include "capstone.h"
#include <Windows.h>
#include <map>
#include <vector>
#include <list>
#include <deque>
#include <array>
#include <string>
#include <iostream>
#include <tuple>
#include <algorithm>
#include <iterator>
#include "Tracer.h"
#include <Windows.h>

#define MAX_INSN_LENGTH 16

class Tracer
{
public:
	Tracer(HANDLE target_handle);
	~Tracer();

	int SaveInstruction(uint8_t* instruction_buffer, DWORD thread_id, const CONTEXT& thread_context);
	//int SaveInstructionInfo(uint8_t* instruction_buffer, size_t max_insn_size, DWORD thread_id, const CONTEXT& thread_context);
	int AnalyzeRunTrace(DWORD thread_id, EXCEPTION_RECORD exception_record);

	csh cs_handle;

private:
	int InitializeCapstone(); // maybe just put this in constructor? also set options for details

	DWORD GetValueOfRegisterForInstruction(DWORD thread_id, std::string reg_name, cs_insn insn, bool& found, const size_t start_trace_pos);
	size_t FindEarliestOccurenceOfValueInTrace(DWORD thread_id, DWORD value);
	size_t FindMostRecentOccurenceOfValueInTrace(DWORD thread_id, DWORD value, size_t start_trace_pos);
	std::string GetRegisterReadFrom(DWORD thread_id, cs_insn insn, const size_t trace_pos);
	std::string GetRegisterWrittenTo(DWORD thread_id, cs_insn insn, const size_t trace_pos);
	bool IsStaticAddress(DWORD value);
	DWORD GetVTableIfThereIsOne(DWORD value);
	cs_insn GetCsInsnFromBytes(std::array<uint8_t, MAX_INSN_LENGTH> insn_bytes, DWORD address);
	int PrintRunTrace(std::list<std::tuple<cs_insn, DWORD, DWORD>> relevant_instructions);
	int ReduceRunTrace(std::list<std::tuple<cs_insn, DWORD, DWORD>> &relevant_instructions);

	typedef DWORD instruction_address;
	typedef std::array<uint8_t, MAX_INSN_LENGTH> instruction_bytes;
	typedef std::map<std::string, DWORD> register_modifications;

	typedef std::tuple<instruction_address, instruction_bytes, register_modifications> instruction_info;
	typedef std::deque<instruction_info> run_trace_vec;

	std::map<DWORD, run_trace_vec> all_threads_saved_instructions;
	std::map<DWORD, CONTEXT> all_threads_saved_contexts;
	//const size_t x86_MAX_INSTRUCTION_LENGTH = 15;
	const size_t max_trace_length = 25000;
	const size_t max_instruction_length = 15;
	HANDLE target_handle;
};

