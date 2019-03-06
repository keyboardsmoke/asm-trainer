#pragma once

namespace emuutil
{
	static bool ReadStringFromMemory(uc_engine* uc, uint64_t addr, std::string& output)
	{
		for (char c = -1; c != 0; ++addr)
		{
			uc_err err = uc_mem_read(uc, addr, &c, sizeof(char));

			if (err != UC_ERR_OK)
			{
				return false;
			}

			output.push_back(c);
		}

		output.push_back(0);

		return true;
	}
}