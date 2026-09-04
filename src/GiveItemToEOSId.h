#pragma once

#include <string>


namespace Companion
{
    struct GiveItemResult
    {
        bool success;
        std::string error;
    };


    GiveItemResult GiveItemToEOSId(
        const std::string& eos_id,
        const std::string& blueprint,
        int quantity,
        float quality,
        bool force_blueprint
    );
}
