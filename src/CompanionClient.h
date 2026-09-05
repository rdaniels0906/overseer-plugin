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


    void PublishTribeCreated(
        AShooterPlayerState* player_state,
        const FString* tribe_name
    );


    void PublishTribeRenamed(
        AShooterPlayerState* player_state,
        const FString* tribe_name
    );


    void PublishTribeJoined(
        AShooterPlayerState* player_state,
        const FString* player_name,
        const FString* tribe_name,
        bool joinee
    );


    void PublishTribeLeft(
        AShooterPlayerState* player_state,
        const FString* player_name,
        const FString* tribe_name,
        bool joinee
    );


    void PublishTamed(
        APrimalDinoCharacter* dino,
        AShooterPlayerController* player
    );


    void PublishUntamed(
        APrimalDinoCharacter* dino
    );


    void PublishUnclaimed(
        APrimalDinoCharacter* dino
    );


    void PublishTameDeath(
        APrimalDinoCharacter* dino,
        float killing_damage
    );
}