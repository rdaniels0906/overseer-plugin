#include "RunConsoleCommand.h"

#include "LocalRconClient.h"


namespace Companion
{
    RunConsoleCommandResult RunConsoleCommand(
        const std::string& command
    )
    {
        RunConsoleCommandResult result;


        const auto rcon =
            ExecuteLocalRcon(
                command
            );


        result.success =
            rcon.success;


        result.output =
            rcon.output;


        result.error =
            rcon.error;


        return result;
    }
}
