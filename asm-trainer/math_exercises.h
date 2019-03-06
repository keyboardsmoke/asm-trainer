#pragma once

class SimpleXorExercise : public Exercise
{
public:
    SimpleXorExercise(Emulator* emu) : Exercise(emu) {}

    bool InitializeEngineState() override;
    bool Evaluate() override;
};