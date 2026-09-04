#pragma once

#include <functional>
#include <string>


namespace Companion
{
    struct LocalRconResult
    {
        bool success = false;

        std::string output;
        std::string error;
    };


    bool StartLocalRcon();

    void StopLocalRcon();


    LocalRconResult ExecuteLocalRcon(
        const std::string& command
    );


    void ExecuteLocalRconAsync(
        const std::string& command,
        std::function<void(LocalRconResult)> callback
    );
}
