#include "stdafx.h"
#include "Tracer.h"
#include "debugger.h"
#include <iomanip>
#include <vector>
#include <list>
#include <algorithm>
#include <tuple>

#define MAX_INSN_LENGTH 16


Tracer::Tracer(HANDLE target_handle)
	: cs_handle(NULL), target_handle(target_handle)
{
	InitializeCapstone();
}

int Tracer::InitializeCapstone()
{
	if (cs_open(CS_ARCH_X86, CS_MODE_32, &cs_handle) != CS_ERR_OK) std::cout << "Error in cs_open()" << std::endl;
	cs_option(cs_handle, CS_OPT_DETAIL, CS_OPT_ON);

	return 1;
}


Tracer::~Tracer()
{}

int Tracer::SaveInstruction(uint8_t* instruction_buffer, DWORD thread_id, const CONTEXT& thread_context)
{
	DWORD previous_eip = 0,
		current_eip = thread_context.Eip;

	if (!all_threads_saved_instructions[thread_id].empty())
	{
		// get<0> since eip (i.e., address) for an instruction is first element of instrution tuple
		previous_eip = std::get<0>(all_threads_saved_instructions[thread_id].back());
	}

	// check that prev eip and current eip dont match, or else mem bp triggering instructions will get added twice
	if (previous_eip != current_eip)
	{
		//std::tuple<DWORD, std::array<uint8_t, MAX_INSN_LENGTH>, std::map<std::string, DWORD>> instruction;
		std::map<std::string, DWORD> modifications;

		//if (thread_context.Eip != all_threads_saved_contexts[thread_id].Eip) modifications["Eip"] = thread_context.Eip;
		if (thread_context.Eax != all_threads_saved_contexts[thread_id].Eax) modifications["Eax"] = thread_context.Eax;
		if (thread_context.Ebx != all_threads_saved_contexts[thread_id].Ebx) modifications["Ebx"] = thread_context.Ebx;
		if (thread_context.Ecx != all_threads_saved_contexts[thread_id].Ecx) modifications["Ecx"] = thread_context.Ecx;
		if (thread_context.Edx != all_threads_saved_contexts[thread_id].Edx) modifications["Edx"] = thread_context.Edx;
		if (thread_context.Edi != all_threads_saved_contexts[thread_id].Edi) modifications["Edi"] = thread_context.Edi;
		if (thread_context.Esi != all_threads_saved_contexts[thread_id].Esi) modifications["Esi"] = thread_context.Esi;

		all_threads_saved_contexts[thread_id] = thread_context;

		std::array<uint8_t, MAX_INSN_LENGTH> insn_buffer = { 0 };

		for (unsigned int i = 0; i < MAX_INSN_LENGTH; i++)
		{
			insn_buffer[i] = instruction_buffer[i];
		}

		auto instruction = std::make_tuple(thread_context.Eip, insn_buffer, modifications);

		if (all_threads_saved_instructions[thread_id].size() >= max_trace_length)
		{
			all_threads_saved_instructions[thread_id].erase(all_threads_saved_instructions[thread_id].begin());
		}

		all_threads_saved_instructions[thread_id].push_back(instruction);
	}

	return 1;
}

cs_insn Tracer::GetCsInsnFromBytes(std::array<uint8_t, MAX_INSN_LENGTH> insn_bytes, DWORD address)
{
	uint8_t insn_buf[MAX_INSN_LENGTH] = { 0 };
	size_t count = 0;
	cs_insn insn;
	cs_insn *insnp;

	for (size_t i = 0; i < MAX_INSN_LENGTH; i++)
	{
		insn_buf[i] = insn_bytes[i];
	}

	count = cs_disasm(cs_handle, insn_buf, MAX_INSN_LENGTH, address, count, &insnp);
	insn = insnp[0];

	return insn;
}

int Tracer::AnalyzeRunTrace(DWORD thread_id, EXCEPTION_RECORD exception_record)
{
	std::string reg_name;
	bool found = false;
	cs_insn insn;
	DWORD address;
	run_trace_vec run_trace = all_threads_saved_instructions[thread_id];

	std::array<uint8_t, MAX_INSN_LENGTH> raw_insn = std::get<1>(run_trace.back());
	address = std::get<0>(run_trace.back());

	insn = GetCsInsnFromBytes(raw_insn, address);

	size_t trace_pos = run_trace.end() - run_trace.begin() - 1;
	size_t last_trace_pos = 0;

	if (exception_record.ExceptionInformation[0] == 0) // true when the memory access violation was a read
	{
		std::cout << "Memory access violation was a read, starting trace analysis" << std::endl;
		reg_name = GetRegisterReadFrom(thread_id, insn, trace_pos);
	}
	else
	{
		// reg_name = GetRegisterWrittenTo(thread_id, insn, trace_pos);
		// maybe give an option to the user to manually choose register written to
		std::cout << "Memory access violation was a write, skipping trace analysis" << std::endl << std::endl;
		return 0;
	}

	DWORD value = 0, vtable = 0;
	uint64_t last_insn_address = 0;
	std::list<std::tuple<cs_insn, DWORD, DWORD>> relevant_instructions;

	while (true)
	{
		value = GetValueOfRegisterForInstruction(thread_id, reg_name, insn, found, trace_pos);
		if (!found) break;
		found = false;

		vtable = GetVTableIfThereIsOne(value);

		relevant_instructions.push_back(std::make_tuple(insn, value, vtable));

		//trace_pos = FindEarliestOccurenceOfValueInTrace(thread_id, value); // returns instruction position in trace
		trace_pos = FindMostRecentOccurenceOfValueInTrace(thread_id, value, trace_pos);
		if (trace_pos == 0) break;

		raw_insn = std::get<1>(run_trace.at(trace_pos));
		address = std::get<0>(run_trace.at(trace_pos));

		insn = GetCsInsnFromBytes(raw_insn, address);

		if (trace_pos == last_trace_pos) break;
		last_trace_pos = trace_pos;

		reg_name = GetRegisterReadFrom(thread_id, insn, trace_pos);
		if (reg_name == "No registers read")
		{
			relevant_instructions.push_back(std::make_tuple(insn, value, vtable));
			break;
		}

		if (GetAsyncKeyState(0x51)) break;
	}

	PrintRunTrace(relevant_instructions);

	// do this if not verbose
	ReduceRunTrace(relevant_instructions);

	PrintRunTrace(relevant_instructions);

	return 1;
}

int Tracer::ReduceRunTrace(std::list<std::tuple<cs_insn, DWORD, DWORD>> &relevant_instructions)
{
	DWORD value;

	if (relevant_instructions.size() <= 1) return 0;

	for (auto ins = relevant_instructions.begin(); ins != relevant_instructions.end(); ins++)
	{
		auto rel_insn = *ins;
		value = std::get<1>(rel_insn);

		auto last_occurence = ins;

		for (auto jns = ins; jns != relevant_instructions.end(); jns++)
		{
			auto rel_jnsn = *jns;
			DWORD current_value = std::get<1>(rel_jnsn);

			if (current_value == value) last_occurence = jns;
		}

		if (std::next(last_occurence, 1) == relevant_instructions.end()) continue;

		relevant_instructions.erase(std::next(ins, 1), std::next(last_occurence, 1));
	}
}

int Tracer::PrintRunTrace(std::list<std::tuple<cs_insn, DWORD, DWORD>> relevant_instructions)
{
	std::string full_insn_string;
	std::string mnemonic;
	std::string op_str;
	uint64_t eip;
	DWORD value, vtable;

	std::cout << "-- Trace analysis completed --" << std::endl;
	std::cout << std::left << std::setfill(' ') << std::setw(12) << "EIP";
	std::cout << std::setw(32) << "Instruction";
	std::cout << std::setw(11) << "Value";
	std::cout << std::setw(10) << "VTable" << std::endl;

	for (auto ins = relevant_instructions.rbegin(); ins != relevant_instructions.rend(); ins++)
	{
		auto rel_insn = *ins;
		eip = std::get<0>(rel_insn).address;
		mnemonic = std::get<0>(rel_insn).mnemonic;
		op_str = std::get<0>(rel_insn).op_str;
		value = std::get<1>(rel_insn);
		vtable = std::get<2>(rel_insn);

		full_insn_string = mnemonic + " " + op_str;

		std::cout << std::internal << "0x" << std::setfill('0') << std::setw(8) << eip << std::setfill(' ');
		std::cout << "  " << std::left << std::setw(32) << full_insn_string;

		if (value != 0)
		{
			std::cout << std::internal << "0x" << std::setfill('0') << std::setw(8) << std::hex << value;
		}

		if (vtable != 0)
		{
			std::cout << " " << std::internal << "0x" << std::setfill('0') << std::setw(8) << std::hex << vtable;
		}

		std::cout << std::endl;
	}

	std::cout << "-------- End of trace --------" << std::endl << std::endl;

	return 1;
}

bool Tracer::IsStaticAddress(DWORD value)
{
	if (value >= 0x400000 && value <= 0xA3D000) return true;

	return false;
}

DWORD Tracer::GetVTableIfThereIsOne(DWORD value)
{
	unsigned int potential_vtable_ptr = 0, potential_vtable = 0;
	MEMORY_BASIC_INFORMATION mem_info1 = { 0 }, mem_info2 = { 0 };

	// 4 is x86 specific
	if (!ReadProcessMemory(target_handle, (LPCVOID)value, &potential_vtable_ptr, 4, NULL)) return 0;

	if (!VirtualQueryEx(target_handle, (LPCVOID)potential_vtable_ptr, &mem_info1, sizeof(MEMORY_BASIC_INFORMATION))) return 0;

	if (mem_info1.Protect != PAGE_READONLY) return 0;

	if (!ReadProcessMemory(target_handle, (LPCVOID)potential_vtable_ptr, &potential_vtable, 4, NULL)) return 0;

	if (!VirtualQueryEx(target_handle, (LPCVOID)potential_vtable, &mem_info2, sizeof(MEMORY_BASIC_INFORMATION))) return 0;

	unsigned int code_protection = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_READONLY;

	if (!(mem_info2.Protect & code_protection)) return 0;

	return potential_vtable_ptr;
}

std::string Tracer::GetRegisterReadFrom(DWORD thread_id, cs_insn insn, const size_t trace_pos)
{
	std::string reg_name = "No registers read", temp_reg_name, op_str = insn.op_str;
	cs_regs regs_read, regs_write;
	uint8_t read_count, write_count;
	unsigned int reg_count = 0;

	std::vector<std::string> my_regs_read;
	
	cs_regs_access(cs_handle, &insn, regs_read, &read_count, regs_write, &write_count);

	if (read_count > 0)
	{
		bool found = false;

		// figure out what to do about instructions like "mov eax, [ecx + edx * 4]"
		// probably want to guess that register with higher value contains useful address
		DWORD this_value = 0, last_value = 0;

		for (int i = 0; i < read_count; i++)
		{
			temp_reg_name = cs_reg_name(cs_handle, regs_read[i]);
			temp_reg_name[0] = toupper(temp_reg_name[0]);

			this_value = GetValueOfRegisterForInstruction(thread_id, temp_reg_name.c_str(), insn, found, trace_pos);

			if (this_value >= last_value)
			{
				reg_name = temp_reg_name;
				last_value = this_value;
			}
		}
	}

	reg_name[0] = toupper(reg_name[0]);

	return reg_name;
}

std::string Tracer::GetRegisterWrittenTo(DWORD thread_id, cs_insn insn, const size_t trace_pos)
{
	std::string reg_name = "No registers written", temp_reg_name, op_str = insn.op_str;
	cs_regs regs_read, regs_write;
	uint8_t read_count, write_count;
	unsigned int reg_count = 0;

	std::vector<std::string> my_regs_read;

	cs_regs_access(cs_handle, &insn, regs_read, &read_count, regs_write, &write_count);

	if (write_count > 0)
	{
		bool found = false;

		// figure out what to do about instructions like "mov eax, [ecx + edx * 4]"
		// probably want to guess that register with higher value contains useful address
		DWORD this_value = 0, last_value = 0;

		for (int i = 0; i < write_count; i++)
		{
			temp_reg_name = cs_reg_name(cs_handle, regs_write[i]);
			temp_reg_name[0] = toupper(temp_reg_name[0]);

			this_value = GetValueOfRegisterForInstruction(thread_id, temp_reg_name.c_str(), insn, found, trace_pos);

			if (this_value >= last_value)
			{
				reg_name = temp_reg_name;
				last_value = this_value;
			}
		}
	}

	reg_name[0] = toupper(reg_name[0]);

	return reg_name;
}

DWORD Tracer::GetValueOfRegisterForInstruction(DWORD thread_id, std::string reg_name, cs_insn insn, bool& found, const size_t start_trace_pos)
{
	uint64_t address_of_instruction = insn.address;
	//auto run_trace = all_threads_saved_instructions[thread_id];
	std::map<std::string, DWORD> modifications;
	run_trace_vec run_trace = all_threads_saved_instructions[thread_id];

	//std::reverse_iterator<std::vector<instruction_info>::iterator> trace_it = run_trace.rend() - start_trace_pos;

	for (size_t trace_pos = start_trace_pos; trace_pos > 0; trace_pos--)
	{
		instruction_info insn_info = run_trace.at(trace_pos);
		modifications = std::get<2>(insn_info);

		auto modification = modifications.find(reg_name.c_str());

		if (modification != modifications.end())
		{
			found = true;
			return modification->second;
		}
	}

	found = false;
	return 0;
}

size_t Tracer::FindEarliestOccurenceOfValueInTrace(DWORD thread_id, DWORD value)
{
	run_trace_vec run_trace = all_threads_saved_instructions[thread_id];
	cs_insn *insnp;
	DWORD address;
	std::array<uint8_t, MAX_INSN_LENGTH> raw_insn;
	size_t count = 0;
	std::map<std::string, DWORD> modifications;
	uint8_t raw_insn_buf[MAX_INSN_LENGTH] = { 0 };
	size_t trace_pos = 0;

	for (size_t trace_pos = 0; trace_pos < run_trace.size(); trace_pos++)
	{
		instruction_info insn_info = run_trace.at(trace_pos);
		modifications = std::get<2>(insn_info);

		for (auto mod = modifications.begin(); mod != modifications.end(); mod++)
		{
			if (mod->second == value && trace_pos != 0)
			{
				// just decrement ins iterator and grab prev instruction
				size_t prev_trace_pos = trace_pos - 1;
				instruction_info prev_insn_info = run_trace.at(prev_trace_pos);
				/*
				address = std::get<0>(prev_insn_info);
				raw_insn = std::get<1>(prev_insn_info);

				for (size_t i = 0; i < MAX_INSN_LENGTH; i++)
				{
					raw_insn_buf[i] = raw_insn[i];
				}

				count = cs_disasm(cs_handle, raw_insn_buf, MAX_INSN_LENGTH, address, count, &insnp);
				*/
				return prev_trace_pos;
			}
		}
	}

	// should do something about error condition
	return 0;
}

size_t Tracer::FindMostRecentOccurenceOfValueInTrace(DWORD thread_id, DWORD value, size_t start_trace_pos)
{
	run_trace_vec run_trace = all_threads_saved_instructions[thread_id];
	std::map<std::string, DWORD> modifications;
	DWORD address;
	std::array<uint8_t, MAX_INSN_LENGTH> raw_insn;
	uint8_t raw_insn_buf[MAX_INSN_LENGTH] = { 0 };
	size_t count = 0;
	cs_insn *insnp;
	cs_insn insn;
	cs_regs regs_read, regs_write;
	uint8_t read_count, write_count;
	std::string reg_read;
	bool reg_read_is_stack_reg = true;
	size_t rel_trace_pos = 0;

	for (size_t trace_pos = start_trace_pos; trace_pos > 0; trace_pos--)
	{
		instruction_info insn_info = run_trace.at(trace_pos);
		modifications = std::get<2>(insn_info);

		for (auto mod = modifications.begin(); mod != modifications.end(); mod++)
		{
			if (mod->second == value && trace_pos != 0)
			{
				// just decrement ins iterator and grab prev instruction
				size_t prev_trace_pos = trace_pos - 1;
				instruction_info prev_insn_info = run_trace.at(prev_trace_pos);
				
				address = std::get<0>(prev_insn_info);
				raw_insn = std::get<1>(prev_insn_info);

				for (size_t i = 0; i < MAX_INSN_LENGTH; i++) raw_insn_buf[i] = raw_insn[i];

				count = cs_disasm(cs_handle, raw_insn_buf, MAX_INSN_LENGTH, address, count, &insnp);
				insn = insnp[0];

				if (count > 0)
				{
					reg_read = GetRegisterReadFrom(thread_id, insn, prev_trace_pos);

					if (reg_read == "Esp" || reg_read == "Ebp")
					{
						reg_read_is_stack_reg = true;
					}
					else
					{
						reg_read_is_stack_reg = false;
						rel_trace_pos = prev_trace_pos;
					}
				}

				break; // maybe break only if reg read is good
			}
		}

		if (!reg_read_is_stack_reg) return rel_trace_pos;
	}

	return rel_trace_pos;
}