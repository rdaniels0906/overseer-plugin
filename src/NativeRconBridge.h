#pragma once

#include <string>


namespace Companion
{
    struct NativeRconResult
    {
        bool success = false;
        std::string output;
        std::string error;
    };


    void InstallNativeRconHooks();

    void UninstallNativeRconHooks();


    bool HasNativeRconConnection();


    NativeRconResult ExecuteNativeRcon(
        const std::string& command
    );
}
