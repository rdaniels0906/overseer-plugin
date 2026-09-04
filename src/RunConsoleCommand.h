#pragma once

#include <string>


namespace Companion
{
    struct RunConsoleCommandResult
    {
        bool success = false;

        std::string output;
        std::string error;
    };


    RunConsoleCommandResult RunConsoleCommand(
        const std::string& command
    );
}
