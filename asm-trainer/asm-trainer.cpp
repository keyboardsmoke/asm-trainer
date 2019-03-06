#include "pch.h"

#include "cxxopts.hpp"
#include "unicorn/unicorn.h"
#include "keystone/keystone.h"

#include "allocator.h"

#include "emu.h"
#include "aarch64emu.h"
#include "aarch32emu.h"
#include "x64emu.h"
#include "x86emu.h"

#include "assembler.h"
#include "aarch64asm.h"
#include "aarch32asm.h"
#include "x64asm.h"
#include "x86asm.h"

cxxopts::Options options("asm-trainer", "Assembly Trainer");

bool parse_options(int& argc, char**& argv, std::string& engine, std::string& filename, std::string& output_filename, int& stack_size)
{
	try
	{
		options.add_options()
			("e,engine", "Assembly engine to use (aarch32, aarch64)", cxxopts::value<std::string>())
			("f,file", "File to assemble and run the emulator against", cxxopts::value<std::string>())
			("o,output", "Optional parameter to output assembled bytes into a file", cxxopts::value<std::string>())
			("s,stack-size", "Optional parameter to specify the amount of bytes in stack space you require", cxxopts::value<int>());

		auto result = options.parse(argc, argv);
		
		if (result.count("e") == 0 ||
			result.count("f") == 0)
		{
			return false;
		}

		engine = result["e"].as<std::string>();
		filename = result["f"].as<std::string>();

		if (result.count("o"))
		{
			output_filename = result["o"].as<std::string>();
		}

		if (result.count("s"))
		{
			stack_size = result["s"].as<int>();
		}
		else
		{
			stack_size = 4096;
		}

		return true;
	}
	catch (std::exception& e)
	{
		std::cout << "EXCEPTION [" << e.what() << "]" << std::endl;

		return false;
	}
}

bool read_file(std::string& filename, std::string& file_content)
{
	std::ifstream file(filename);
	
	if (file.good() == false)
	{
		return false;
	}

	file_content = std::string((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

	return true;
}

bool write_binary_file(std::string& filename, std::vector<uint8_t>& binary_content)
{
	std::ofstream file(filename, std::ios::out | std::ios::binary);
	
	if (file.good() == false)
	{
		return false;
	}

	file.write((char *) binary_content.data(), binary_content.size());
	file.close();

	return true;
}

int main(int argc, char** argv, char** envp)
{
	int stackSize = 0;
	std::string engine, filename, output_filename;
	if (!parse_options(argc, argv, engine, filename, output_filename, stackSize))
	{
		std::cout << "Failed to parse program options." << std::endl << std::endl;
		std::cout << options.help();
		return -1;
	}

	std::string file_content;
	if (!read_file(filename, file_content))
	{
		std::cout << "The file provided [" << filename << "] could not be read." << std::endl;
		return -1;
	}

	// Need to assemble the file

	// Need to emulate the result
	int status = -1;

	std::vector<uint8_t> assembled_code;

	Emulator* emu = nullptr;
	Assembler* assembler = nullptr;

	if (engine == "aarch64")
	{
		emu = new ARM64Emulator(stackSize);
		assembler = new ARM64Assembler;

		std::cout << ">>> Using aarch64 emulator and assembler engines." << std::endl;
	}
	else if (engine == "aarch32")
	{
		emu = new ARM32Emulator(stackSize);
		assembler = new ARM32Assembler;

		std::cout << ">>> Using aarch32 emulator and assembler engines." << std::endl;
	}
    else if (engine == "x64") 
    {
		emu = new X64Emulator(stackSize);
        assembler = new X64Assembler;
    }
    else if (engine == "x86")
    {
		emu = new X86Emulator(stackSize);
        assembler = new X86Assembler;
    }
	else
	{
		std::cerr << ">>> Engine \"" << engine << "\" is not supported." << std::endl;
		goto end;
	}

	if (!assembler->Initialize())
	{
		std::cout << ">>> Failed to initialize the assembler engine." << std::endl;
		goto end;
	}

	if (!assembler->Assemble(file_content, assembled_code))
	{
		std::cout << ">>> Failed to assemble provided file." << std::endl;
		goto end;
	}

	std::cout << ">>> Assembled code is " << assembled_code.size() << " bytes." << std::endl;

	if (!output_filename.empty())
	{
		std::cout << ">>> Writing assembled output to " << output_filename << std::endl;

		if (!write_binary_file(output_filename, assembled_code))
		{
			std::cerr << ">>> Unable to write output file " << output_filename << std::endl;
			goto end;
		}
	}

	if (!emu->Initialize((void *) assembled_code.data(), assembled_code.size()))
	{
		std::cout << "Failed to initialize emulation engine." << std::endl;
		goto end;
	}

	std::cout << ">>> Entering emulation state" << std::endl;
	std::cout << "============================" << std::endl;

	if (!emu->Emulate())
	{
		std::cout << ">>> Failed to emulate code." << std::endl;
		goto end;
	}

	std::cout << "============================" << std::endl;

	emu->PrintContext(std::cout);

	emu->Close();

	status = 0;

end:
	delete emu;
	delete assembler;

	return status;
}