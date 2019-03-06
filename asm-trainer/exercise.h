#pragma once

class Emulator;

class Exercise
{
public:
    Exercise() = delete;
    Exercise(Emulator* emu) : m_emu(emu) {}

    virtual bool InitializeEngineState() = 0;
    virtual bool Evaluate() = 0;

protected:
    Emulator* m_emu;
};