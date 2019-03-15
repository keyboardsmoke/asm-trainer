#pragma once

namespace emuutil
{
	static bool ReadStringFromMemory(uc_engine* uc, uint64_t addr, std::string& output)
	{
        while (true)
        {
            char c = 0;
            const uc_err err = uc_mem_read(uc, addr, &c, sizeof(char));

            if (err != UC_ERR_OK)
            {
                return false;
            }

            output.push_back(c);

            if (c == 0)
            {
                break;
            }

            ++addr;
        }

		return true;
	}
}