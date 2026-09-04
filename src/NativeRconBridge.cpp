#include "NativeRconBridge.h"

#include "API/ARK/Ark.h"

#include <atomic>
#include <mutex>
#include <string>


namespace
{
    RCONClientConnection* g_connection =
        nullptr;


    std::mutex g_mutex;


    int g_next_packet_id =
        700000000;


    int g_pending_packet_id =
        -1;


    FString g_pending_output;


    bool g_pending_response =
        false;
}


DECLARE_HOOK(
    Companion_RCON_SendMessage,
    void,
    RCONClientConnection*,
    int,
    int,
    FString*
);


DECLARE_HOOK(
    Companion_RCON_Close,
    void,
    RCONClientConnection*
);


void Hook_Companion_RCON_SendMessage(
    RCONClientConnection* connection,
    int id,
    int type,
    FString* outgoing_message
)
{
    /*
     * Any authenticated connection that successfully
     * sends a packet is a valid native RCON context.
     */
    if (
        connection &&
        connection->IsAuthenticatedField()
    )
    {
        g_connection =
            connection;
    }


    /*
     * This response belongs to a packet injected by
     * PixelPurgeCompanion.
     *
     * Capture it instead of sending it to the real
     * remote RCON client.
     */
    if (
        connection &&
        connection == g_connection &&
        id == g_pending_packet_id
    )
    {
        if (outgoing_message)
        {
            if (!g_pending_output.IsEmpty())
            {
                g_pending_output +=
                    L"\n";
            }

            g_pending_output +=
                *outgoing_message;
        }


        g_pending_response =
            true;


        return;
    }


    Companion_RCON_SendMessage_original(
        connection,
        id,
        type,
        outgoing_message
    );
}


void Hook_Companion_RCON_Close(
    RCONClientConnection* connection
)
{
    if (
        connection &&
        connection == g_connection
    )
    {
        g_connection =
            nullptr;


        Log::GetLog()->info(
            "Native RCON connection released"
        );
    }


    Companion_RCON_Close_original(
        connection
    );
}


namespace Companion
{
    void InstallNativeRconHooks()
    {
        AsaApi::GetHooks().SetHook(
            "RCONClientConnection.SendMessage(int,int,FString&)",
            Hook_Companion_RCON_SendMessage,
            &Companion_RCON_SendMessage_original
        );


        AsaApi::GetHooks().SetHook(
            "RCONClientConnection.Close()",
            Hook_Companion_RCON_Close,
            &Companion_RCON_Close_original
        );


        Log::GetLog()->info(
            "Native RCON bridge hooks installed"
        );
    }


    void UninstallNativeRconHooks()
    {
        AsaApi::GetHooks().DisableHook(
            "RCONClientConnection.SendMessage(int,int,FString&)",
            Hook_Companion_RCON_SendMessage
        );


        AsaApi::GetHooks().DisableHook(
            "RCONClientConnection.Close()",
            Hook_Companion_RCON_Close
        );


        g_connection =
            nullptr;


        Log::GetLog()->info(
            "Native RCON bridge hooks removed"
        );
    }


    bool HasNativeRconConnection()
    {
        return
            g_connection != nullptr;
    }


    NativeRconResult ExecuteNativeRcon(
        const std::string& command
    )
    {
        NativeRconResult result;


        if (command.empty())
        {
            result.error =
                "Command cannot be empty.";

            return result;
        }


        std::lock_guard<std::mutex>
            lock(
                g_mutex
            );


        RCONClientConnection* connection =
            g_connection;


        if (!connection)
        {
            result.error =
                "No authenticated native RCON connection is available.";

            return result;
        }


        if (
            connection->IsClosedField() ||
            !connection->IsAuthenticatedField()
        )
        {
            g_connection =
                nullptr;


            result.error =
                "Native RCON connection is no longer valid.";

            return result;
        }


        UWorld* world =
            AsaApi::GetApiUtils()
                .GetWorld();


        if (!world)
        {
            result.error =
                "World is not available.";

            return result;
        }


        ++g_next_packet_id;


        if (
            g_next_packet_id >
            799999999
        )
        {
            g_next_packet_id =
                700000000;
        }


        g_pending_packet_id =
            g_next_packet_id;


        g_pending_output.Empty();


        g_pending_response =
            false;


        RCONPacket packet{};


        packet.Id =
            g_pending_packet_id;


        /*
         * Source RCON command packet.
         */
        packet.Type =
            2;


        packet.Body =
            FString(
                command
            );


        packet.Length =
            0;


        Log::GetLog()->info(
            "Native RCON executing: {}",
            command
        );


        connection->ProcessRCONPacket(
            &packet,
            world
        );


        if (!g_pending_output.IsEmpty())
        {
            result.output =
                g_pending_output.ToString();
        }


        /*
         * Some valid commands return no text at all.
         * Reaching this point means the native handler
         * returned normally.
         */
        result.success =
            true;


        Log::GetLog()->info(
            "Native RCON completed: {}",
            command
        );


        if (!result.output.empty())
        {
            Log::GetLog()->info(
                "Native RCON output: {}",
                result.output
            );
        }
        else
        {
            Log::GetLog()->info(
                "Native RCON returned no text"
            );
        }


        g_pending_packet_id =
            -1;


        g_pending_output.Empty();


        g_pending_response =
            false;


        return result;
    }
}
