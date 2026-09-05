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
    AShooterPlayerState_ServerRequestCreateNewTribe_Implementation,
    void,
    AShooterPlayerState*,
    const FString*,
    FTribeGovernment
);


DECLARE_HOOK(
    AShooterPlayerState_ServerRequestRenameTribe_Implementation,
    void,
    AShooterPlayerState*,
    const FString*
);


DECLARE_HOOK(
    AShooterPlayerState_NotifyPlayerJoinedTribe_Implementation,
    void,
    AShooterPlayerState*,
    const FString*,
    const FString*,
    bool
);


DECLARE_HOOK(
    AShooterPlayerState_NotifyPlayerLeftTribe_Implementation,
    void,
    AShooterPlayerState*,
    const FString*,
    const FString*,
    bool
);


DECLARE_HOOK(
    APrimalDinoCharacter_TameDino,
    void,
    APrimalDinoCharacter*,
    AShooterPlayerController*,
    bool,
    int,
    bool,
    bool,
    bool
);


DECLARE_HOOK(
    APrimalDinoCharacter_UntameDino,
    void,
    APrimalDinoCharacter*,
    float
);


DECLARE_HOOK(
    APrimalDinoCharacter_UnclaimDino,
    void,
    APrimalDinoCharacter*,
    bool
);


DECLARE_HOOK(
    APrimalDinoCharacter_Die,
    bool,
    APrimalDinoCharacter*,
    float,
    const FDamageEvent*,
    AController*,
    AActor*
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


void Hook_AShooterPlayerState_ServerRequestCreateNewTribe_Implementation(
    AShooterPlayerState* player_state,
    const FString* tribe_name,
    FTribeGovernment tribe_government
)
{
    AShooterPlayerState_ServerRequestCreateNewTribe_Implementation_original(
        player_state,
        tribe_name,
        tribe_government
    );


    Companion::PublishTribeCreated(
        player_state,
        tribe_name
    );
}


void Hook_AShooterPlayerState_ServerRequestRenameTribe_Implementation(
    AShooterPlayerState* player_state,
    const FString* tribe_name
)
{
    AShooterPlayerState_ServerRequestRenameTribe_Implementation_original(
        player_state,
        tribe_name
    );


    Companion::PublishTribeRenamed(
        player_state,
        tribe_name
    );
}


void Hook_AShooterPlayerState_NotifyPlayerJoinedTribe_Implementation(
    AShooterPlayerState* player_state,
    const FString* player_name,
    const FString* tribe_name,
    bool joinee
)
{
    AShooterPlayerState_NotifyPlayerJoinedTribe_Implementation_original(
        player_state,
        player_name,
        tribe_name,
        joinee
    );


    Companion::PublishTribeJoined(
        player_state,
        player_name,
        tribe_name,
        joinee
    );
}


void Hook_AShooterPlayerState_NotifyPlayerLeftTribe_Implementation(
    AShooterPlayerState* player_state,
    const FString* player_name,
    const FString* tribe_name,
    bool joinee
)
{
    /*
     * Publish before the original call so tribe state is still
     * available if ASA clears membership as part of the notification.
     */
    Companion::PublishTribeLeft(
        player_state,
        player_name,
        tribe_name,
        joinee
    );


    AShooterPlayerState_NotifyPlayerLeftTribe_Implementation_original(
        player_state,
        player_name,
        tribe_name,
        joinee
    );
}


void Hook_APrimalDinoCharacter_TameDino(
    APrimalDinoCharacter* dino,
    AShooterPlayerController* player,
    bool ignore_max_tame_limit,
    int override_taming_team_id,
    bool prevent_name_dialog,
    bool skip_adding_tamed_levels,
    bool suppress_notifications
)
{
    APrimalDinoCharacter_TameDino_original(
        dino,
        player,
        ignore_max_tame_limit,
        override_taming_team_id,
        prevent_name_dialog,
        skip_adding_tamed_levels,
        suppress_notifications
    );


    Companion::PublishTamed(
        dino,
        player
    );
}


void Hook_APrimalDinoCharacter_UntameDino(
    APrimalDinoCharacter* dino,
    float taming_affinity_limit
)
{
    /*
     * Capture ownership while it still exists.
     */
    Companion::PublishUntamed(
        dino
    );


    APrimalDinoCharacter_UntameDino_original(
        dino,
        taming_affinity_limit
    );
}


void Hook_APrimalDinoCharacter_UnclaimDino(
    APrimalDinoCharacter* dino,
    bool destroy_ai
)
{
    /*
     * Capture ownership while it still exists.
     */
    Companion::PublishUnclaimed(
        dino
    );


    APrimalDinoCharacter_UnclaimDino_original(
        dino,
        destroy_ai
    );
}


bool Hook_APrimalDinoCharacter_Die(
    APrimalDinoCharacter* dino,
    float killing_damage,
    const FDamageEvent* damage_event,
    AController* killer,
    AActor* damage_causer
)
{
    Companion::PublishTameDeath(
        dino,
        killing_damage
    );


    return
        APrimalDinoCharacter_Die_original(
            dino,
            killing_damage,
            damage_event,
            killer,
            damage_causer
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
        "AShooterPlayerState.ServerRequestCreateNewTribe_Implementation(FString&,FTribeGovernment)",
        Hook_AShooterPlayerState_ServerRequestCreateNewTribe_Implementation,
        &AShooterPlayerState_ServerRequestCreateNewTribe_Implementation_original
    );


    AsaApi::GetHooks().SetHook(
        "AShooterPlayerState.ServerRequestRenameTribe_Implementation(FString&)",
        Hook_AShooterPlayerState_ServerRequestRenameTribe_Implementation,
        &AShooterPlayerState_ServerRequestRenameTribe_Implementation_original
    );


    AsaApi::GetHooks().SetHook(
        "AShooterPlayerState.NotifyPlayerJoinedTribe_Implementation(FString&,FString&,bool)",
        Hook_AShooterPlayerState_NotifyPlayerJoinedTribe_Implementation,
        &AShooterPlayerState_NotifyPlayerJoinedTribe_Implementation_original
    );


    AsaApi::GetHooks().SetHook(
        "AShooterPlayerState.NotifyPlayerLeftTribe_Implementation(FString&,FString&,bool)",
        Hook_AShooterPlayerState_NotifyPlayerLeftTribe_Implementation,
        &AShooterPlayerState_NotifyPlayerLeftTribe_Implementation_original
    );


    AsaApi::GetHooks().SetHook(
        "APrimalDinoCharacter.TameDino(AShooterPlayerController*,bool,int,bool,bool,bool)",
        Hook_APrimalDinoCharacter_TameDino,
        &APrimalDinoCharacter_TameDino_original
    );


    AsaApi::GetHooks().SetHook(
        "APrimalDinoCharacter.UntameDino(float)",
        Hook_APrimalDinoCharacter_UntameDino,
        &APrimalDinoCharacter_UntameDino_original
    );


    AsaApi::GetHooks().SetHook(
        "APrimalDinoCharacter.UnclaimDino(bool)",
        Hook_APrimalDinoCharacter_UnclaimDino,
        &APrimalDinoCharacter_UnclaimDino_original
    );


    AsaApi::GetHooks().SetHook(
        "APrimalDinoCharacter.Die(float,FDamageEvent&,AController*,AActor*)",
        Hook_APrimalDinoCharacter_Die,
        &APrimalDinoCharacter_Die_original
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
        "APrimalDinoCharacter.UnclaimDino(bool)",
        Hook_APrimalDinoCharacter_UnclaimDino
    );


    AsaApi::GetHooks().DisableHook(
        "APrimalDinoCharacter.UntameDino(float)",
        Hook_APrimalDinoCharacter_UntameDino
    );


    AsaApi::GetHooks().DisableHook(
        "APrimalDinoCharacter.TameDino(AShooterPlayerController*,bool,int,bool,bool,bool)",
        Hook_APrimalDinoCharacter_TameDino
    );


    AsaApi::GetHooks().DisableHook(
        "AShooterPlayerState.NotifyPlayerLeftTribe_Implementation(FString&,FString&,bool)",
        Hook_AShooterPlayerState_NotifyPlayerLeftTribe_Implementation
    );


    AsaApi::GetHooks().DisableHook(
        "AShooterPlayerState.NotifyPlayerJoinedTribe_Implementation(FString&,FString&,bool)",
        Hook_AShooterPlayerState_NotifyPlayerJoinedTribe_Implementation
    );


    AsaApi::GetHooks().DisableHook(
        "AShooterPlayerState.ServerRequestRenameTribe_Implementation(FString&)",
        Hook_AShooterPlayerState_ServerRequestRenameTribe_Implementation
    );


    AsaApi::GetHooks().DisableHook(
        "AShooterPlayerState.ServerRequestCreateNewTribe_Implementation(FString&,FTribeGovernment)",
        Hook_AShooterPlayerState_ServerRequestCreateNewTribe_Implementation
    );


    AsaApi::GetHooks().DisableHook(
        "APrimalDinoCharacter.Die(float,FDamageEvent&,AController*,AActor*)",
        Hook_APrimalDinoCharacter_Die
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