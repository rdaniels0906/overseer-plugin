#include "GiveItemToEOSId.h"

#include "API/ARK/Ark.h"


namespace
{
    AShooterPlayerController*
    FindPlayerByEOSId(
        const std::string& target_eos)
    {
        auto* world =
            AsaApi::GetApiUtils().GetWorld();


        if (!world)
        {
            return nullptr;
        }


        const FString wanted(
            target_eos.c_str()
        );


        auto& controllers =
            world->PlayerControllerListField();


        for (
            auto& weak_controller :
            controllers
        )
        {
            APlayerController* controller =
                weak_controller.Get();


            if (!controller)
            {
                continue;
            }


            auto* shooter =
                static_cast<
                    AShooterPlayerController*
                >(
                    controller
                );


            if (!shooter)
            {
                continue;
            }


            const FString eos =
                AsaApi::IApiUtils::
                    GetEOSIDFromController(
                        shooter
                    );


            if (
                eos.Equals(
                    wanted,
                    ESearchCase::IgnoreCase
                )
            )
            {
                return shooter;
            }
        }


        return nullptr;
    }
}


namespace Companion
{
    GiveItemResult GiveItemToEOSId(
        const std::string& eos_id,
        const std::string& blueprint,
        int quantity,
        float quality,
        bool force_blueprint)
    {
        if (
            eos_id.empty()
        )
        {
            return {
                false,
                "EOS ID is empty."
            };
        }


        if (
            blueprint.empty()
        )
        {
            return {
                false,
                "Blueprint is empty."
            };
        }


        if (
            quantity <= 0
        )
        {
            return {
                false,
                "Quantity must be greater than zero."
            };
        }


        AShooterPlayerController* player =
            FindPlayerByEOSId(
                eos_id
            );


        if (!player)
        {
            return {
                false,
                "Player is not online on this server."
            };
        }


        FString blueprint_path(
            blueprint.c_str()
        );


        const bool success =
            player->GiveItem(
                &blueprint_path,
                quantity,
                quality,
                force_blueprint,
                false,
                0.0f
            );


        if (!success)
        {
            return {
                false,
                "ASA GiveItem returned false."
            };
        }


        return {
            true,
            ""
        };
    }
}
