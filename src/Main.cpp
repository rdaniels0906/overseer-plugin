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
    AShooterGameMode_PostLogin,
    void,
    AShooterGameMode*,
    APlayerController*
);


DECLARE_HOOK(
    AShooterGameMode_Logout,
    void,
    AShooterGameMode*,
    AController*
);


DECLARE_HOOK(
    AShooterPlayerState_BroadcastDeath_Implementation,
    void,
    AShooterPlayerState*,
    AShooterPlayerState*,
    UDamageType*,
    AShooterPlayerState*
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


void Hook_AShooterGameMode_PostLogin(
    AShooterGameMode* game_mode,
    APlayerController* new_player
)
{
    AShooterGameMode_PostLogin_original(
        game_mode,
        new_player
    );


    Companion::PublishPlayerJoined(
        new_player
    );
}


void Hook_AShooterGameMode_Logout(
    AShooterGameMode* game_mode,
    AController* exiting
)
{
    /*
     * Capture identity while the player/controller state still exists.
     */
    Companion::PublishPlayerLeft(
        exiting
    );


    AShooterGameMode_Logout_original(
        game_mode,
        exiting
    );
}


void Hook_AShooterPlayerState_BroadcastDeath_Implementation(
    AShooterPlayerState* self,
    AShooterPlayerState* killer_player_state,
    UDamageType* killer_damage_type,
    AShooterPlayerState* killed_player_state
)
{
    AShooterPlayerState_BroadcastDeath_Implementation_original(
        self,
        killer_player_state,
        killer_damage_type,
        killed_player_state
    );


    Companion::PublishPlayerDeath(
        killer_player_state,
        killer_damage_type,
        killed_player_state
    );
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
        "AShooterGameMode.PostLogin(APlayerController*)",
        Hook_AShooterGameMode_PostLogin,
        &AShooterGameMode_PostLogin_original
    );


    AsaApi::GetHooks().SetHook(
        "AShooterGameMode.Logout(AController*)",
        Hook_AShooterGameMode_Logout,
        &AShooterGameMode_Logout_original
    );


    AsaApi::GetHooks().SetHook(
        "AShooterPlayerState.BroadcastDeath_Implementation(AShooterPlayerState*,UDamageType*,AShooterPlayerState*)",
        Hook_AShooterPlayerState_BroadcastDeath_Implementation,
        &AShooterPlayerState_BroadcastDeath_Implementation_original
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
        "AShooterPlayerState.BroadcastDeath_Implementation(AShooterPlayerState*,UDamageType*,AShooterPlayerState*)",
        Hook_AShooterPlayerState_BroadcastDeath_Implementation
    );


    AsaApi::GetHooks().DisableHook(
        "AShooterGameMode.Logout(AController*)",
        Hook_AShooterGameMode_Logout
    );


    AsaApi::GetHooks().DisableHook(
        "AShooterGameMode.PostLogin(APlayerController*)",
        Hook_AShooterGameMode_PostLogin
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