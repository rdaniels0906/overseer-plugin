#include "API/ARK/Ark.h"

#include <ixwebsocket/IXNetSystem.h>

#include "CompanionClient.h"
#include "LocalRconClient.h"


DECLARE_HOOK(
    AShooterGameMode_BeginPlay,
    void,
    AShooterGameMode*
);


DECLARE_HOOK(
    AShooterPlayerController_ServerSendChatMessage_Implementation,
    void,
    AShooterPlayerController*,
    const FString*,
    EChatSendMode::Type,
    int
);


void Hook_AShooterGameMode_BeginPlay(
    AShooterGameMode* game_mode)
{
    AShooterGameMode_BeginPlay_original(
        game_mode
    );


    Companion::Start();
}




void Hook_AShooterPlayerController_ServerSendChatMessage_Implementation(
    AShooterPlayerController* player,
    const FString* message,
    EChatSendMode::Type send_mode,
    int sender_platform
)
{
    /*
     * Preserve normal ASA chat behavior first.
     *
     * Overseer chat is additive. If the backend is unavailable,
     * normal local/global/tribe chat continues to work.
     */
    AShooterPlayerController_ServerSendChatMessage_Implementation_original(
        player,
        message,
        send_mode,
        sender_platform
    );


    if (
        !player ||
        !message ||
        message->IsEmpty()
    )
    {
        return;
    }


    Companion::PublishChatMessage(
        player,
        message,
        send_mode,
        sender_platform
    );
}


extern "C" __declspec(dllexport)
void Plugin_Init()
{
    Log::Get().Init(
        "PixelPurgeCompanion"
    );


    Log::GetLog()->info(
        "PixelPurge Companion loading..."
    );


    ix::initNetSystem();

    Companion::StartLocalRcon();


    AsaApi::GetHooks().SetHook(
        "AShooterGameMode.BeginPlay()",
        Hook_AShooterGameMode_BeginPlay,
        &AShooterGameMode_BeginPlay_original
    );


    AsaApi::GetHooks().SetHook(
        "AShooterPlayerController.ServerSendChatMessage_Implementation(FString&,EChatSendMode::Type,int)",
        Hook_AShooterPlayerController_ServerSendChatMessage_Implementation,
        &AShooterPlayerController_ServerSendChatMessage_Implementation_original
    );


    /*
     * WebSocket callbacks run on another thread.
     * This callback runs on ASA's game thread and
     * safely processes queued game operations.
     */
    AsaApi::GetCommands()
        .AddOnTimerCallback(
            L"PixelPurgeCompanion.ProcessRequests",
            []()
            {
                Companion::
                    ProcessPendingRequests();
            }
        );


    if (
        AsaApi::GetApiUtils().GetStatus() ==
        AsaApi::ServerStatus::Ready
    )
    {
        Companion::Start();
    }


    Log::GetLog()->info(
        "PixelPurge Companion loaded"
    );
}


extern "C" __declspec(dllexport)
void Plugin_Unload()
{
    Companion::Stop();

    Companion::StopLocalRcon();


    AsaApi::GetCommands()
        .RemoveOnTimerCallback(
            L"PixelPurgeCompanion.ProcessRequests"
        );


    AsaApi::GetHooks().DisableHook(
        "AShooterPlayerController.ServerSendChatMessage_Implementation(FString&,EChatSendMode::Type,int)",
        Hook_AShooterPlayerController_ServerSendChatMessage_Implementation
    );


    AsaApi::GetHooks().DisableHook(
        "AShooterGameMode.BeginPlay()",
        Hook_AShooterGameMode_BeginPlay
    );


    ix::uninitNetSystem();


    Log::GetLog()->info(
        "PixelPurge Companion unloaded"
    );
}
