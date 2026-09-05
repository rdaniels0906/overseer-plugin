#pragma once

#include "API/ARK/Ark.h"


namespace Companion
{
    void Start();

    void Stop();

    void ProcessPendingRequests();


    void PublishChatMessage(
        AShooterPlayerController* player,
        const FString* message,
        EChatSendMode::Type send_mode,
        int sender_platform
    );


    void PublishPlayerJoined(
        APlayerController* player
    );


    void PublishPlayerLeft(
        AController* player
    );


    void PublishPlayerDeath(
        AShooterPlayerState* killer_player_state,
        UDamageType* killer_damage_type,
        AShooterPlayerState* killed_player_state
    );
}