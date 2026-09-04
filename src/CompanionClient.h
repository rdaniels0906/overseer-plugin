#pragma once

#include "API/ARK/Ark.h"


namespace Companion
{
    void Start();

    void Stop();

    void ProcessPendingRequests();


    /*
     * Publishes a player-originated ASA chat message to Overseer.
     *
     * This is called from the ASA chat hook on the game thread.
     */
    void PublishChatMessage(
        AShooterPlayerController* player,
        const FString* message,
        EChatSendMode::Type send_mode,
        int sender_platform
    );
}
