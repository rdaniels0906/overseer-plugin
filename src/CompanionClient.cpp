#include "CompanionClient.h"

#include "API/ARK/Ark.h"
#include "GiveItemToEOSId.h"
#include "RunConsoleCommand.h"
#include "LocalRconClient.h"

#include <ixwebsocket/IXWebSocket.h>
#include <ixwebsocket/IXHttpClient.h>
#include <ixwebsocket/IXSocketTLSOptions.h>

#include <nlohmann/json.hpp>

#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <chrono>
#include <Logger/spdlog/sinks/stdout_sinks.h>
#include <iostream>
#include <atomic>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <mutex>
#include <optional>
#include <queue>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#pragma comment(lib, "bcrypt.lib")


namespace
{
    using json =
        nlohmann::json;


    constexpr const char*
        PLUGIN_VERSION =
            "0.3.0";


    struct CompanionConfig
    {
        bool enabled =
            false;

        std::string url;

        std::string companion_guid;

        std::string companion_secret;
        std::string discovery_key;
        bool auto_update = true;
        std::string update_channel = "Production";

        bool paired =
            false;
    };


    struct CompanionMetadata
    {
        std::string server_id;

        std::string cluster_id;

        std::string session_name;
    };


    struct PendingRequest
    {
        std::string request_id;

        std::string action;

        json payload;
    };


    ix::WebSocket websocket;


    std::atomic<bool>
        started =
            false;


    std::atomic<bool>
        authenticated =
            false;


    std::atomic<bool>
        update_check_started =
            false;


    CompanionConfig
        config;


    CompanionMetadata
        metadata;


    std::string
        pairing_code;


    std::mutex
        queue_mutex;


    std::queue<PendingRequest>
        pending_requests;


    std::chrono::steady_clock::time_point
        last_heartbeat_sent{};


    std::chrono::steady_clock::time_point
        last_player_snapshot_sent{};



    extern "C"
    IMAGE_DOS_HEADER
        __ImageBase;


    /*
     * UPDATER FORWARD DECLARATIONS
     */
    std::filesystem::path
    GetPluginPath();


    std::filesystem::path
    GetPluginDirectory();


    std::string
    BytesToHex(
        const unsigned char* data,
        std::size_t length
    );


    std::string
    ToLowerCopy(
        std::string value
    )
    {
        std::transform(
            value.begin(),
            value.end(),
            value.begin(),
            [](
                unsigned char character
            )
            {
                return static_cast<char>(
                    std::tolower(
                        character
                    )
                );
            }
        );

        return value;
    }


    std::vector<int>
    ParseVersion(
        const std::string& version
    )
    {
        std::string clean =
            version;

        if (
            !clean.empty() &&
            (
                clean[0] == 'v' ||
                clean[0] == 'V'
            )
        )
        {
            clean.erase(
                clean.begin()
            );
        }

        /*
         * Pre-release suffixes are intentionally ignored for
         * numeric ordering here. Dev/Production are separate
         * channels, so a channel only needs monotonically
         * increasing numeric versions.
         */
        const auto suffix =
            clean.find_first_of(
                "-+"
            );

        if (
            suffix !=
            std::string::npos
        )
        {
            clean =
                clean.substr(
                    0,
                    suffix
                );
        }

        std::vector<int>
            parts;

        std::stringstream
            stream(
                clean
            );

        std::string
            token;

        while (
            std::getline(
                stream,
                token,
                '.'
            )
        )
        {
            if (
                token.empty()
            )
            {
                throw std::runtime_error(
                    "Invalid plugin version."
                );
            }

            for (
                const unsigned char character :
                token
            )
            {
                if (
                    !std::isdigit(
                        character
                    )
                )
                {
                    throw std::runtime_error(
                        "Invalid plugin version."
                    );
                }
            }

            parts.push_back(
                std::stoi(
                    token
                )
            );
        }

        if (
            parts.empty()
        )
        {
            throw std::runtime_error(
                "Invalid plugin version."
            );
        }

        return parts;
    }


    bool
    IsVersionNewer(
        const std::string& candidate,
        const std::string& current
    )
    {
        auto candidate_parts =
            ParseVersion(
                candidate
            );

        auto current_parts =
            ParseVersion(
                current
            );

        const std::size_t count =
            (std::max)(
                candidate_parts.size(),
                current_parts.size()
            );

        candidate_parts.resize(
            count,
            0
        );

        current_parts.resize(
            count,
            0
        );

        for (
            std::size_t index = 0;
            index < count;
            ++index
        )
        {
            if (
                candidate_parts[index] >
                current_parts[index]
            )
            {
                return true;
            }

            if (
                candidate_parts[index] <
                current_parts[index]
            )
            {
                return false;
            }
        }

        return false;
    }


    std::string
    GetUpdateApiBaseUrl()
    {
        std::string base =
            config.url;

        constexpr const char*
            WSS_PREFIX =
                "wss://";

        if (
            base.rfind(
                WSS_PREFIX,
                0
            ) != 0
        )
        {
            throw std::runtime_error(
                "Cannot derive update API URL from non-WSS companion URL."
            );
        }

        base.replace(
            0,
            6,
            "https://"
        );

        const auto path_start =
            base.find(
                '/',
                8
            );

        if (
            path_start !=
            std::string::npos
        )
        {
            base =
                base.substr(
                    0,
                    path_start
                );
        }

        return base;
    }


    std::string
    Sha256(
        const std::string& data
    )
    {
        BCRYPT_ALG_HANDLE algorithm =
            nullptr;

        BCRYPT_HASH_HANDLE hash =
            nullptr;

        DWORD object_length =
            0;

        DWORD hash_length =
            0;

        DWORD bytes_returned =
            0;

        std::vector<unsigned char>
            object_buffer;

        std::vector<unsigned char>
            hash_buffer;

        auto cleanup =
            [&]()
            {
                if (
                    hash !=
                    nullptr
                )
                {
                    BCryptDestroyHash(
                        hash
                    );
                }

                if (
                    algorithm !=
                    nullptr
                )
                {
                    BCryptCloseAlgorithmProvider(
                        algorithm,
                        0
                    );
                }
            };

        NTSTATUS status =
            BCryptOpenAlgorithmProvider(
                &algorithm,
                BCRYPT_SHA256_ALGORITHM,
                nullptr,
                0
            );

        if (
            status < 0
        )
        {
            throw std::runtime_error(
                "BCryptOpenAlgorithmProvider SHA256 failed."
            );
        }

        status =
            BCryptGetProperty(
                algorithm,
                BCRYPT_OBJECT_LENGTH,
                reinterpret_cast<PUCHAR>(
                    &object_length
                ),
                sizeof(
                    object_length
                ),
                &bytes_returned,
                0
            );

        if (
            status < 0
        )
        {
            cleanup();

            throw std::runtime_error(
                "BCryptGetProperty OBJECT_LENGTH failed."
            );
        }

        status =
            BCryptGetProperty(
                algorithm,
                BCRYPT_HASH_LENGTH,
                reinterpret_cast<PUCHAR>(
                    &hash_length
                ),
                sizeof(
                    hash_length
                ),
                &bytes_returned,
                0
            );

        if (
            status < 0
        )
        {
            cleanup();

            throw std::runtime_error(
                "BCryptGetProperty HASH_LENGTH failed."
            );
        }

        object_buffer.resize(
            object_length
        );

        hash_buffer.resize(
            hash_length
        );

        status =
            BCryptCreateHash(
                algorithm,
                &hash,
                object_buffer.data(),
                static_cast<ULONG>(
                    object_buffer.size()
                ),
                nullptr,
                0,
                0
            );

        if (
            status < 0
        )
        {
            cleanup();

            throw std::runtime_error(
                "BCryptCreateHash failed."
            );
        }

        status =
            BCryptHashData(
                hash,
                reinterpret_cast<PUCHAR>(
                    const_cast<char*>(
                        data.data()
                    )
                ),
                static_cast<ULONG>(
                    data.size()
                ),
                0
            );

        if (
            status < 0
        )
        {
            cleanup();

            throw std::runtime_error(
                "BCryptHashData failed."
            );
        }

        status =
            BCryptFinishHash(
                hash,
                hash_buffer.data(),
                static_cast<ULONG>(
                    hash_buffer.size()
                ),
                0
            );

        if (
            status < 0
        )
        {
            cleanup();

            throw std::runtime_error(
                "BCryptFinishHash failed."
            );
        }

        cleanup();

        return
            BytesToHex(
                hash_buffer.data(),
                hash_buffer.size()
            );
    }


    void
    CheckForPluginUpdate()
    {
        if (
            !config.auto_update
        )
        {
            Log::GetLog()->info(
                "Plugin auto-update is disabled"
            );

            return;
        }

        try
        {
            const std::string channel =
                config.update_channel;

            const std::string manifest_url =
                GetUpdateApiBaseUrl() +
                "/api/plugin/releases/" +
                channel +
                "/latest";

            Log::GetLog()->info(
                "Checking {} Plugin channel for updates; current version {}",
                channel,
                PLUGIN_VERSION
            );


            ix::HttpClient client(
                false
            );

            ix::SocketTLSOptions tls_options;

            tls_options.caFile =
                "SYSTEM";

            tls_options.disable_hostname_validation =
                false;

            client.setTLSOptions(
                tls_options
            );


            auto request =
                client.createRequest(
                    manifest_url,
                    ix::HttpClient::kGet
                );

            request->connectTimeout =
                10;

            request->transferTimeout =
                30;

            request->followRedirects =
                true;

            request->maxRedirects =
                3;

            request->compress =
                false;


            const auto response =
                client.get(
                    manifest_url,
                    request
                );

            if (
                !response
            )
            {
                throw std::runtime_error(
                    "Update manifest request returned no response."
                );
            }

            if (
                response->errorCode !=
                ix::HttpErrorCode::Ok
            )
            {
                throw std::runtime_error(
                    "Update manifest HTTP error: " +
                    response->errorMsg
                );
            }

            if (
                response->statusCode !=
                200
            )
            {
                throw std::runtime_error(
                    "Update manifest returned HTTP " +
                    std::to_string(
                        response->statusCode
                    )
                );
            }


            const json manifest =
                json::parse(
                    response->body
                );

            const std::string version =
                manifest.value(
                    "version",
                    ""
                );

            const std::string download_url =
                manifest.value(
                    "downloadUrl",
                    ""
                );

            const std::string expected_sha256 =
                ToLowerCopy(
                    manifest.value(
                        "sha256",
                        ""
                    )
                );


            if (
                version.empty() ||
                download_url.empty() ||
                expected_sha256.size() !=
                    64
            )
            {
                throw std::runtime_error(
                    "Update manifest is invalid."
                );
            }


            if (
                download_url.rfind(
                    "https://",
                    0
                ) != 0
            )
            {
                throw std::runtime_error(
                    "Update download URL is not HTTPS."
                );
            }


            if (
                !IsVersionNewer(
                    version,
                    PLUGIN_VERSION
                )
            )
            {
                Log::GetLog()->info(
                    "Plugin is up to date on {}: {}",
                    channel,
                    PLUGIN_VERSION
                );

                return;
            }


            Log::GetLog()->info(
                "Plugin update available: {} -> {} ({})",
                PLUGIN_VERSION,
                version,
                channel
            );


            auto download_request =
                client.createRequest(
                    download_url,
                    ix::HttpClient::kGet
                );

            download_request->connectTimeout =
                10;

            download_request->transferTimeout =
                120;

            download_request->followRedirects =
                true;

            download_request->maxRedirects =
                3;

            download_request->compress =
                false;


            const auto download_response =
                client.get(
                    download_url,
                    download_request
                );

            if (
                !download_response
            )
            {
                throw std::runtime_error(
                    "Plugin update download returned no response."
                );
            }

            if (
                download_response->errorCode !=
                ix::HttpErrorCode::Ok
            )
            {
                throw std::runtime_error(
                    "Plugin update download failed: " +
                    download_response->errorMsg
                );
            }

            if (
                download_response->statusCode !=
                200
            )
            {
                throw std::runtime_error(
                    "Plugin update download returned HTTP " +
                    std::to_string(
                        download_response->statusCode
                    )
                );
            }


            const std::string actual_sha256 =
                ToLowerCopy(
                    Sha256(
                        download_response->body
                    )
                );


            if (
                actual_sha256 !=
                expected_sha256
            )
            {
                throw std::runtime_error(
                    "Plugin update SHA-256 verification failed."
                );
            }


            const auto plugin_path =
                GetPluginPath();


            auto staging_path =
                plugin_path;

            staging_path +=
                L".update";


            auto temp_path =
                plugin_path;

            temp_path +=
                L".update.tmp";


            {
                std::ofstream file(
                    temp_path,
                    std::ios::binary |
                    std::ios::trunc
                );

                if (
                    !file
                )
                {
                    throw std::runtime_error(
                        "Could not create staged Plugin update."
                    );
                }

                file.write(
                    download_response->body.data(),
                    static_cast<std::streamsize>(
                        download_response->body.size()
                    )
                );

                if (
                    !file
                )
                {
                    throw std::runtime_error(
                        "Could not write staged Plugin update."
                    );
                }
            }


            std::error_code error;

            std::filesystem::remove(
                staging_path,
                error
            );

            error.clear();

            std::filesystem::rename(
                temp_path,
                staging_path,
                error
            );

            if (
                error
            )
            {
                std::filesystem::remove(
                    temp_path,
                    error
                );

                throw std::runtime_error(
                    "Could not finalize staged Plugin update."
                );
            }


            json pending =
            {
                {
                    "version",
                    version
                },
                {
                    "channel",
                    channel
                },
                {
                    "sha256",
                    actual_sha256
                }
            };


            const auto pending_path =
                GetPluginDirectory() /
                "plugin-update.json";


            std::ofstream pending_file(
                pending_path,
                std::ios::trunc
            );

            if (
                !pending_file
            )
            {
                throw std::runtime_error(
                    "Could not write Plugin update metadata."
                );
            }

            pending_file
                << pending.dump(
                    4
                )
                << std::endl;


            Log::GetLog()->info(
                "Plugin update {} downloaded and verified; installation pending next server restart",
                version
            );
        }
        catch (
            const std::exception& error
        )
        {
            Log::GetLog()->warn(
                "Plugin update check failed: {}",
                error.what()
            );
        }
    }


    void
    StartPluginUpdateCheck()
    {
        if (
            update_check_started.exchange(
                true
            )
        )
        {
            return;
        }

        std::thread(
            []()
            {
                CheckForPluginUpdate();
            }
        ).detach();
    }


    std::filesystem::path
    GetPluginPath()
    {
        wchar_t path[
            MAX_PATH
        ]{};


        const DWORD length =
            GetModuleFileNameW(
                reinterpret_cast<
                    HMODULE
                >(
                    &__ImageBase
                ),
                path,
                MAX_PATH
            );


        if (
            length == 0 ||
            length >= MAX_PATH
        )
        {
            throw std::runtime_error(
                "Could not determine plugin DLL path."
            );
        }


        return
            std::filesystem::path(
                path
            );
    }


    std::filesystem::path
    GetPluginDirectory()
    {
        return
            GetPluginPath()
                .parent_path();
    }


    std::filesystem::path
    GetConfigPath()
    {
        return
            GetPluginDirectory() /
            "config.json";
    }


    std::string
    BytesToHex(
        const unsigned char* data,
        std::size_t length
    )
    {
        std::ostringstream stream;


        stream
            << std::hex
            << std::setfill(
                '0'
            );


        for (
            std::size_t i = 0;
            i < length;
            ++i
        )
        {
            stream
                << std::setw(
                    2
                )
                << static_cast<int>(
                    data[i]
                );
        }


        return
            stream.str();
    }


    void
    GenerateRandomBytes(
        unsigned char* output,
        std::size_t length
    )
    {
        const NTSTATUS status =
            BCryptGenRandom(
                nullptr,
                output,
                static_cast<ULONG>(
                    length
                ),
                BCRYPT_USE_SYSTEM_PREFERRED_RNG
            );


        if (
            status < 0
        )
        {
            throw std::runtime_error(
                "BCryptGenRandom failed."
            );
        }
    }


    std::string
    GenerateCompanionSecret()
    {
        std::array<
            unsigned char,
            32
        > bytes{};


        GenerateRandomBytes(
            bytes.data(),
            bytes.size()
        );


        return
            BytesToHex(
                bytes.data(),
                bytes.size()
            );
    }


    std::string
    GenerateCompanionGuid()
    {
        std::array<
            unsigned char,
            16
        > bytes{};


        GenerateRandomBytes(
            bytes.data(),
            bytes.size()
        );


        /*
         * RFC 4122 UUID version 4.
         */
        bytes[6] =
            static_cast<unsigned char>(
                (
                    bytes[6] &
                    0x0F
                ) |
                0x40
            );


        bytes[8] =
            static_cast<unsigned char>(
                (
                    bytes[8] &
                    0x3F
                ) |
                0x80
            );


        const std::string hex =
            BytesToHex(
                bytes.data(),
                bytes.size()
            );


        return
            hex.substr(
                0,
                8
            ) +
            "-" +
            hex.substr(
                8,
                4
            ) +
            "-" +
            hex.substr(
                12,
                4
            ) +
            "-" +
            hex.substr(
                16,
                4
            ) +
            "-" +
            hex.substr(
                20,
                12
            );
    }


    std::string
    GeneratePairingCode()
    {
        /*
         * Exclude visually confusing characters
         * such as I, O, 0 and 1.
         */
        static constexpr
            char alphabet[] =
                "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";


        constexpr std::size_t
            character_count =
                sizeof(
                    alphabet
                ) - 1;


        std::array<
            unsigned char,
            8
        > random{};


        GenerateRandomBytes(
            random.data(),
            random.size()
        );


        std::string result;


        result.reserve(
            9
        );


        for (
            std::size_t index = 0;
            index < random.size();
            ++index
        )
        {
            if (
                index ==
                4
            )
            {
                result.push_back(
                    '-'
                );
            }


            result.push_back(
                alphabet[
                    random[index] %
                    character_count
                ]
            );
        }


        return result;
    }


    void
    SaveConfig(
        const CompanionConfig& value
    )
    {
        const auto path =
            GetConfigPath();


        json data =
        {
            {
                "enabled",
                value.enabled
            },
            {
                "url",
                value.url
            },
            {
                "companionGuid",
                value.companion_guid
            },
            {
                "companionSecret",
                value.companion_secret
            },
            {
                "discoveryKey",
                value.discovery_key
            },
            {
                "paired",
                value.paired
            },
            {
                "autoUpdate",
                value.auto_update
            },
            {
                "updateChannel",
                value.update_channel
            }
        };


        std::ofstream file(
            path,
            std::ios::trunc
        );


        if (!file)
        {
            throw std::runtime_error(
                "Could not write companion config.json."
            );
        }


        file
            << data.dump(
                4
            )
            << std::endl;
    }


    CompanionConfig
    LoadConfig()
    {
        const auto path =
            GetConfigPath();


        std::ifstream file(
            path
        );


        if (!file)
        {
            throw std::runtime_error(
                "config.json was not found beside the plugin DLL."
            );
        }


        json data;

        file >>
            data;


        CompanionConfig result;


        result.enabled =
            data.value(
                "enabled",
                false
            );


        result.url =
            data.value(
                "url",
                ""
            );


        result.companion_guid =
            data.value(
                "companionGuid",
                ""
            );


        result.companion_secret =
            data.value(
                "companionSecret",
                ""
            );


        result.discovery_key =
            data.value(
                "discoveryKey",
                ""
            );


        result.paired =
            data.value(
                "paired",
                false
            );


        result.auto_update =
            data.value(
                "autoUpdate",
                true
            );


        result.update_channel =
            data.value(
                "updateChannel",
                "Production"
            );


        if (
            result.enabled &&
            result.url.empty()
        )
        {
            throw std::runtime_error(
                "Companion URL is missing."
            );
        }


        if (
            result.enabled &&
            result.url.rfind(
                "wss://",
                0
            ) != 0
        )
        {
            throw std::runtime_error(
                "Companion URL must use wss://."
            );
        }


        bool changed =
            false;


        std::string normalized_update_channel =
            result.update_channel;

        std::transform(
            normalized_update_channel.begin(),
            normalized_update_channel.end(),
            normalized_update_channel.begin(),
            [](
                unsigned char character
            ) {
                return static_cast<char>(
                    std::tolower(
                        character
                    )
                );
            }
        );


        if (
            normalized_update_channel ==
                "dev"
        )
        {
            if (
                result.update_channel !=
                    "Dev"
            )
            {
                result.update_channel =
                    "Dev";

                changed =
                    true;
            }

        }
        else if (
            normalized_update_channel ==
                "production" ||
            normalized_update_channel ==
                "prod"
        )
        {
            if (
                result.update_channel !=
                    "Production"
            )
            {
                result.update_channel =
                    "Production";

                changed =
                    true;
            }

        }
        else
        {
            Log::GetLog()->warn(
                "Invalid updateChannel '{}'; using Production",
                result.update_channel
            );

            result.update_channel =
                "Production";

            changed =
                true;
        }


        if (
            result.companion_guid.empty()
        )
        {
            result.companion_guid =
                GenerateCompanionGuid();

            changed =
                true;
        }


        if (
            result.companion_secret.empty()
        )
        {
            result.companion_secret =
                GenerateCompanionSecret();

            changed =
                true;
        }


        /*
         * Old configs had serverId/serverSecret.
         *
         * Saving here converts the file to the new
         * companion identity format and removes the
         * obsolete fields.
         */
        if (
            changed ||
            data.contains(
                "serverId"
            ) ||
            data.contains(
                "serverSecret"
            ) ||
            !data.contains(
                "paired"
            ) ||
            !data.contains(
                "autoUpdate"
            ) ||
            !data.contains(
                "updateChannel"
            ) ||
            !data.contains(
                "discoveryKey"
            )
        )
        {
            SaveConfig(
                result
            );
        }


        return result;
    }


    void
    CaptureServerMetadata()
    {
        metadata =
            CompanionMetadata{};


        auto* game_mode =
            AsaApi::GetApiUtils()
                .GetShooterGameMode();


        if (game_mode)
        {
            metadata.server_id =
                game_mode
                    ->MyServerIdField()
                    .ToString();
        }


        auto* game_state =
            AsaApi::GetApiUtils()
                .GetGameState();


        if (game_state)
        {
            metadata.cluster_id =
                game_state
                    ->ClusterIdField()
                    .ToString();


            metadata.session_name =
                game_state
                    ->ServerSessionNameField()
                    .ToString();
        }


        Log::GetLog()->info(
            "Companion server metadata: serverId='{}', clusterId='{}', session='{}'",
            metadata.server_id,
            metadata.cluster_id,
            metadata.session_name
        );
    }


    void
    PrintPairingInstructions()
    {
        const std::string banner =
            "\n"
            "============================================================\n"
            " PixelPurge Companion - PAIRING REQUIRED\n"
            "============================================================\n"
            " Pairing Code: " + pairing_code + "\n"
            "\n"
            " Run in Discord:\n"
            " /serverpair code:" + pairing_code + "\n"
            "\n"
            " Pairing code expires after 15 minutes.\n"
            "============================================================";

        // Persistent ASA API/plugin log.
        Log::GetLog()->warn("{}", banner);

        // Standard process stdout.
        //
        // Unlike ASA API's Windows color-console sink, this uses fwrite()
        // and fflush(stdout), so it works whether stdout is a normal console
        // or is redirected by a service/process manager.
        static auto console_logger =
            std::make_shared<spdlog::logger>(
                "PixelPurgeCompanionConsole",
                spdlog::sinks::stdout_sink_mt::instance()
            );

        console_logger->set_pattern("%v");
        console_logger->info("{}", banner);
        console_logger->flush();
    }


    void
    BecomeUnpaired()
    {
        authenticated.store(
            false
        );


        if (
            config.paired
        )
        {
            config.paired =
                false;


            try
            {
                SaveConfig(
                    config
                );
            }
            catch (
                const std::exception& error
            )
            {
                Log::GetLog()->error(
                    "Could not save unpaired companion state: {}",
                    error.what()
                );
            }
        }


        pairing_code =
            GeneratePairingCode();


        PrintPairingInstructions();
    }


    std::string
    HmacSha256(
        const std::string& key,
        const std::string& message
    )
    {
        BCRYPT_ALG_HANDLE
            algorithm =
                nullptr;


        BCRYPT_HASH_HANDLE
            hash =
                nullptr;


        DWORD object_length =
            0;


        DWORD result_length =
            0;


        DWORD hash_length =
            0;


        std::vector<unsigned char>
            hash_object;


        std::vector<unsigned char>
            digest;


        NTSTATUS status =
            BCryptOpenAlgorithmProvider(
                &algorithm,
                BCRYPT_SHA256_ALGORITHM,
                nullptr,
                BCRYPT_ALG_HANDLE_HMAC_FLAG
            );


        if (
            status < 0
        )
        {
            throw std::runtime_error(
                "BCryptOpenAlgorithmProvider failed."
            );
        }


        status =
            BCryptGetProperty(
                algorithm,
                BCRYPT_OBJECT_LENGTH,
                reinterpret_cast<
                    PUCHAR
                >(
                    &object_length
                ),
                sizeof(
                    object_length
                ),
                &result_length,
                0
            );


        if (
            status < 0
        )
        {
            BCryptCloseAlgorithmProvider(
                algorithm,
                0
            );

            throw std::runtime_error(
                "Could not get HMAC object length."
            );
        }


        status =
            BCryptGetProperty(
                algorithm,
                BCRYPT_HASH_LENGTH,
                reinterpret_cast<
                    PUCHAR
                >(
                    &hash_length
                ),
                sizeof(
                    hash_length
                ),
                &result_length,
                0
            );


        if (
            status < 0
        )
        {
            BCryptCloseAlgorithmProvider(
                algorithm,
                0
            );

            throw std::runtime_error(
                "Could not get SHA256 length."
            );
        }


        hash_object.resize(
            object_length
        );


        digest.resize(
            hash_length
        );


        status =
            BCryptCreateHash(
                algorithm,
                &hash,
                hash_object.data(),
                static_cast<ULONG>(
                    hash_object.size()
                ),
                reinterpret_cast<
                    PUCHAR
                >(
                    const_cast<char*>(
                        key.data()
                    )
                ),
                static_cast<ULONG>(
                    key.size()
                ),
                0
            );


        if (
            status < 0
        )
        {
            BCryptCloseAlgorithmProvider(
                algorithm,
                0
            );

            throw std::runtime_error(
                "BCryptCreateHash failed."
            );
        }


        status =
            BCryptHashData(
                hash,
                reinterpret_cast<
                    PUCHAR
                >(
                    const_cast<char*>(
                        message.data()
                    )
                ),
                static_cast<ULONG>(
                    message.size()
                ),
                0
            );


        if (
            status >= 0
        )
        {
            status =
                BCryptFinishHash(
                    hash,
                    digest.data(),
                    static_cast<ULONG>(
                        digest.size()
                    ),
                    0
                );
        }


        BCryptDestroyHash(
            hash
        );


        BCryptCloseAlgorithmProvider(
            algorithm,
            0
        );


        if (
            status < 0
        )
        {
            throw std::runtime_error(
                "HMAC-SHA256 calculation failed."
            );
        }


        return
            BytesToHex(
                digest.data(),
                digest.size()
            );
    }


    void
    SendJson(
        const json& message
    )
    {
        if (
            websocket.getReadyState() !=
            ix::ReadyState::Open
        )
        {
            return;
        }


        websocket.sendText(
            message.dump()
        );
    }


    json
    CollectOnlinePlayerTelemetry()
    {
        json players =
            json::array();


        auto* world =
            AsaApi::GetApiUtils()
                .GetWorld();


        if (!world)
        {
            return players;
        }


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


            const std::string eos_id =
                eos.ToString();


            if (eos_id.empty())
            {
                continue;
            }


            FString survivor_name;

            shooter
                ->GetPlayerCharacterName(
                    &survivor_name
                );


            json player =
            {
                {
                    "eosId",
                    eos_id
                },
                {
                    "survivorName",
                    survivor_name.ToString()
                },
                {
                    "tribeId",
                    nullptr
                },
                {
                    "tribeName",
                    nullptr
                },
                {
                    "isTribeAdmin",
                    false
                }
            };


            if (
                shooter->IsInTribe()
            )
            {
                auto* player_state =
                    static_cast<
                        AShooterPlayerState*
                    >(
                        shooter
                            ->PlayerStateField()
                            .Get()
                    );


                if (player_state)
                {
                    auto& tribe =
                        player_state
                            ->MyTribeDataField();


                    player[
                        "tribeId"
                    ] =
                        tribe.TribeIDField();


                    player[
                        "tribeName"
                    ] =
                        tribe
                            .TribeNameField()
                            .ToString();


                    player[
                        "isTribeAdmin"
                    ] =
                        shooter
                            ->IsTribeAdmin();
                }
            }


            players.push_back(
                std::move(
                    player
                )
            );
        }


        return players;
    }


    const char*
    ChatSendModeName(
        EChatSendMode::Type mode
    )
    {
        switch (
            mode
        )
        {
            case EChatSendMode::GlobalChat:
                return "GLOBAL";

            case EChatSendMode::LocalChat:
                return "LOCAL";


            case EChatSendMode::GlobalTribeChat:
                return "TRIBE";

            case EChatSendMode::AllianceChat:
                return "ALLIANCE";

            default:
                return "UNKNOWN";
        }
    }


    bool
    GetPlayerTribeContext(
        AShooterPlayerController* shooter,
        int& tribe_id,
        std::string& tribe_name,
        bool& is_tribe_admin
    )
    {
        tribe_id =
            0;

        tribe_name.clear();

        is_tribe_admin =
            false;


        if (
            !shooter ||
            !shooter->IsInTribe()
        )
        {
            return false;
        }


        auto* player_state =
            static_cast<
                AShooterPlayerState*
            >(
                shooter
                    ->PlayerStateField()
                    .Get()
            );


        if (!player_state)
        {
            return false;
        }


        auto& tribe =
            player_state
                ->MyTribeDataField();


        tribe_id =
            tribe.TribeIDField();


        tribe_name =
            tribe
                .TribeNameField()
                .ToStringUTF8();


        is_tribe_admin =
            shooter
                ->IsTribeAdmin();


        return true;
    }


    json
    DeliverChatMessage(
        const json& payload
    )
    {
        const std::string audience =
            payload.value(
                "audience",
                ""
            );


        const std::string message =
            payload.value(
                "message",
                ""
            );


        const std::string eos_id =
            payload.value(
                "eosId",
                ""
            );


        const int tribe_id =
            payload.value(
                "tribeId",
                0
            );


        const std::string sender_id =
            payload.value(
                "senderId",
                "Overseer"
            );


        const bool bold =
            payload.value(
                "bold",
                false
            );


        if (
            audience !=
                "GLOBAL" &&
            audience !=
                "TRIBE" &&
            audience !=
                "PLAYER"
        )
        {
            throw std::runtime_error(
                "SendChatMessage audience must be GLOBAL, TRIBE, or PLAYER."
            );
        }


        if (
            message.empty()
        )
        {
            throw std::runtime_error(
                "SendChatMessage message is empty."
            );
        }


        if (
            audience ==
                "TRIBE" &&
            tribe_id <=
                0
        )
        {
            throw std::runtime_error(
                "SendChatMessage TRIBE audience requires tribeId."
            );
        }


        if (
            audience ==
                "PLAYER" &&
            eos_id.empty()
        )
        {
            throw std::runtime_error(
                "SendChatMessage PLAYER audience requires eosId."
            );
        }


        auto* world =
            AsaApi::GetApiUtils()
                .GetWorld();


        if (!world)
        {
            throw std::runtime_error(
                "ASA world is not available."
            );
        }


        FLinearColor color(
            0.4f,
            1.0f,
            1.0f,
            1.0f
        );


        if (
            payload.contains(
                "color"
            ) &&
            payload[
                "color"
            ].is_object()
        )
        {
            const auto& requested =
                payload[
                    "color"
                ];


            color.R =
                requested.value(
                    "r",
                    color.R
                );

            color.G =
                requested.value(
                    "g",
                    color.G
                );

            color.B =
                requested.value(
                    "b",
                    color.B
                );

            color.A =
                requested.value(
                    "a",
                    color.A
                );
        }


        FString text =
            FString::FromStringUTF8(
                message
            );


        FString sender =
            FString::FromStringUTF8(
                sender_id
            );


        int delivered =
            0;


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


            bool should_deliver =
                false;


            if (
                audience ==
                "GLOBAL"
            )
            {
                should_deliver =
                    true;
            }


            if (
                audience ==
                "PLAYER"
            )
            {
                const FString player_eos =
                    AsaApi::IApiUtils::
                        GetEOSIDFromController(
                            shooter
                        );


                should_deliver =
                    player_eos
                        .ToString()
                    ==
                    eos_id;
            }


            if (
                audience ==
                "TRIBE"
            )
            {
                int player_tribe_id =
                    0;

                std::string player_tribe_name;

                bool player_is_admin =
                    false;


                if (
                    GetPlayerTribeContext(
                        shooter,
                        player_tribe_id,
                        player_tribe_name,
                        player_is_admin
                    )
                )
                {
                    should_deliver =
                        player_tribe_id ==
                        tribe_id;
                }
            }


            if (
                !should_deliver
            )
            {
                continue;
            }


            /*
             * Verified ASA client RPC wrapper.
             *
             * We deliberately target each matching controller.
             * That makes TRIBE and PLAYER audiences impossible
             * to leak to unrelated players.
             */
            shooter
                ->ClientServerChatDirectMessage(
                    &text,
                    color,
                    bold,
                    &sender
                );


            ++delivered;
        }


        return {
            {
                "delivered",
                delivered
            },
            {
                "audience",
                audience
            }
        };
    }


    void
    SendPresenceIfDue()
    {
        if (
            !authenticated.load() ||
            websocket.getReadyState() !=
                ix::ReadyState::Open
        )
        {
            return;
        }


        const auto now =
            std::chrono::steady_clock::now();


        const bool heartbeat_due =
            last_heartbeat_sent
                .time_since_epoch()
                .count() == 0 ||
            now - last_heartbeat_sent >=
                std::chrono::seconds(
                    20
                );


        const bool snapshot_due =
            last_player_snapshot_sent
                .time_since_epoch()
                .count() == 0 ||
            now - last_player_snapshot_sent >=
                std::chrono::seconds(
                    30
                );


        if (
            !heartbeat_due &&
            !snapshot_due
        )
        {
            return;
        }


        /*
         * All ASA player/controller access happens here,
         * from ProcessPendingRequests() on ARK's game thread.
         */
        const json players =
            CollectOnlinePlayerTelemetry();


        if (heartbeat_due)
        {
            SendJson({
                {
                    "type",
                    "heartbeat"
                },
                {
                    "playerCount",
                    players.size()
                }
            });


            last_heartbeat_sent =
                now;
        }


        if (snapshot_due)
        {
            SendJson({
                {
                    "type",
                    "player_snapshot"
                },
                {
                    "schemaVersion",
                    1
                },
                {
                    "players",
                    players
                }
            });


            last_player_snapshot_sent =
                now;
        }
    }


    void
    SendHello()
    {
        json hello =
        {
            {
                "type",
                "hello"
            },
            {
                "companionGuid",
                config.companion_guid
            },
            {
                "paired",
                config.paired
            },
            {
                "protocolVersion",
                2
            },
            {
                "pluginVersion",
                PLUGIN_VERSION
            },
            {
                "autoUpdate",
                config.auto_update
            },
            {
                "updateChannel",
                config.update_channel
            },
            {
                "metadata",
                {
                    {
                        "serverId",
                        metadata.server_id
                    },
                    {
                        "clusterId",
                        metadata.cluster_id
                    },
                    {
                        "sessionName",
                        metadata.session_name
                    }
                }
            }
        };


        /*
         * The permanent secret is only transmitted
         * during initial enrollment, over WSS.
         *
         * Once paired, only HMAC challenge responses
         * are sent.
         */
        if (
            !config.paired
        )
        {
            hello[
                "pairingCode"
            ] =
                pairing_code;


            hello[
                "companionSecret"
            ] =
                config.companion_secret;


            if (
                !config.discovery_key.empty()
            )
            {
                hello[
                    "discoveryKey"
                ] =
                    config.discovery_key;
            }
        }


        SendJson(
            hello
        );
    }


    void
    HandleChallenge(
        const json& message
    )
    {
        const std::string nonce =
            message.value(
                "nonce",
                ""
            );


        const std::string challenge_guid =
            message.value(
                "companionGuid",
                ""
            );


        if (
            nonce.empty() ||
            challenge_guid.empty() ||
            challenge_guid !=
                config.companion_guid
        )
        {
            Log::GetLog()->error(
                "Companion received an invalid authentication challenge"
            );

            return;
        }


        try
        {
            const std::string signature =
                HmacSha256(
                    config.companion_secret,
                    nonce
                );


            SendJson({
                {
                    "type",
                    "auth"
                },
                {
                    "companionGuid",
                    config.companion_guid
                },
                {
                    "signature",
                    signature
                }
            });
        }
        catch (
            const std::exception& error
        )
        {
            Log::GetLog()->error(
                "Companion authentication signing failed: {}",
                error.what()
            );
        }
    }


    void
    QueueRequest(
        const json& message
    )
    {
        if (
            !authenticated.load()
        )
        {
            Log::GetLog()->warn(
                "Companion rejected request before authentication"
            );

            return;
        }


        const std::string request_id =
            message.value(
                "requestId",
                ""
            );


        const std::string action =
            message.value(
                "action",
                ""
            );


        if (
            request_id.empty() ||
            action.empty()
        )
        {
            return;
        }


        PendingRequest request{
            request_id,
            action,
            message.value(
                "payload",
                json::object()
            )
        };


        std::lock_guard lock(
            queue_mutex
        );


        /*
         * Prevent an unhealthy backend from growing
         * an unlimited queue inside the game server.
         */
        if (
            pending_requests.size() >=
            100
        )
        {
            Log::GetLog()->error(
                "Companion request queue is full"
            );

            SendJson({
                {
                    "type",
                    "response"
                },
                {
                    "requestId",
                    request_id
                },
                {
                    "success",
                    false
                },
                {
                    "error",
                    "Server request queue is full."
                }
            });

            return;
        }


        pending_requests.push(
            std::move(
                request
            )
        );
    }


    void
    HandleMessage(
        const std::string& text
    )
    {
        try
        {
            const json message =
                json::parse(
                    text
                );


            const std::string type =
                message.value(
                    "type",
                    ""
                );


            if (
                type ==
                "challenge"
            )
            {
                HandleChallenge(
                    message
                );

                return;
            }


            if (
                type ==
                "pairing_pending"
            )
            {
                const bool verified =
                    message.value(
                        "verified",
                        false
                    );


                if (verified)
                {
                    Log::GetLog()->info(
                        "PixelPurge Companion pairing identity verified. Waiting for /serverpair."
                    );
                }


                return;
            }


            if (
                type ==
                "pairing_complete"
            )
            {
                config.paired =
                    true;


                SaveConfig(
                    config
                );


                Log::GetLog()->info(
                    "PixelPurge Companion pairing completed successfully"
                );


                return;
            }


            if (
                type ==
                "pairing_required"
            )
            {
                Log::GetLog()->warn(
                    "Backend no longer recognizes this companion pairing"
                );


                BecomeUnpaired();


                /*
                 * Re-announce immediately using the
                 * newly generated pairing code.
                 */
                SendHello();

                return;
            }


            if (
                type ==
                "unpaired"
            )
            {
                Log::GetLog()->warn(
                    "PixelPurge Companion was unpaired by the backend"
                );


                BecomeUnpaired();

                return;
            }


            if (
                type ==
                "authenticated"
            )
            {
                authenticated.store(
                    true
                );


                /*
                 * If the backend recognizes our GUID,
                 * it is authoritative. Repair local
                 * paired state if necessary.
                 */
                if (
                    !config.paired
                )
                {
                    config.paired =
                        true;


                    SaveConfig(
                        config
                    );
                }


                pairing_code.clear();


                /*
                 * Force the game-thread timer to publish fresh
                 * presence and player telemetry immediately
                 * after every successful authentication or
                 * reconnect.
                 */
                last_heartbeat_sent =
                    {};

                last_player_snapshot_sent =
                    {};


                Log::GetLog()->info(
                    "PixelPurge Companion authenticated successfully"
                );

                return;
            }


            if (
                type ==
                "request"
            )
            {
                QueueRequest(
                    message
                );

                return;
            }
        }
        catch (
            const std::exception& error
        )
        {
            Log::GetLog()->error(
                "Companion received invalid message: {}",
                error.what()
            );
        }
    }


    void
    SendResponse(
        const std::string& request_id,
        bool success,
        const std::string& error =
            "",
        const json& result =
            nullptr
    )
    {
        json response = {
            {
                "type",
                "response"
            },
            {
                "requestId",
                request_id
            },
            {
                "success",
                success
            }
        };


        if (
            !error.empty()
        )
        {
            response[
                "error"
            ] =
                error;
        }


        if (
            !result.is_null()
        )
        {
            response[
                "result"
            ] =
                result;
        }


        SendJson(
            response
        );
    }


    void
    ExecuteRequest(
        const PendingRequest& request
    )
    {
        /*
         * IMPORTANT:
         *
         * This function is called by AsaApi's timer
         * callback, so all Unreal/ASA interaction
         * happens on the game thread.
         */


        


if (
            request.action ==
            "SendChatMessage"
        )
        {
            try
            {
                const json result =
                    DeliverChatMessage(
                        request.payload
                    );


                SendResponse(
                    request.request_id,
                    true,
                    "",
                    result
                );


                Log::GetLog()->info(
                    "SendChatMessage delivered to {} recipient(s)",
                    result.value(
                        "delivered",
                        0
                    )
                );
            }
            catch (
                const std::exception& error
            )
            {
                SendResponse(
                    request.request_id,
                    false,
                    error.what()
                );


                Log::GetLog()->warn(
                    "SendChatMessage failed: {}",
                    error.what()
                );
            }


            return;
        }


        if (
            request.action ==
            "RunConsoleCommand"
        )
        {
            const std::string command =
                request.payload.value(
                    "command",
                    ""
                );


            const std::string request_id =
                request.request_id;


            /*
             * IMPORTANT:
             *
             * Do not execute localhost RCON here.
             * This dispatcher runs on ARK's game thread.
             *
             * The RCON worker must run independently so
             * ARK can continue ticking and process the
             * RCON packet we send to localhost.
             */
            Companion::ExecuteLocalRconAsync(
                command,
                [
                    request_id,
                    command
                ](
                    Companion::LocalRconResult result
                )
                {
                    json response_result =
                    {
                        {
                            "output",
                            result.output
                        }
                    };


                    SendResponse(
                        request_id,
                        result.success,
                        result.error,
                        response_result
                    );


                    if (
                        result.success
                    )
                    {
                        Log::GetLog()->info(
                            "RunConsoleCommand succeeded: {}",
                            command
                        );


                        if (
                            !result.output.empty()
                        )
                        {
                            Log::GetLog()->info(
                                "RunConsoleCommand output: {}",
                                result.output
                            );
                        }
                    }
                    else
                    {
                        Log::GetLog()->warn(
                            "RunConsoleCommand failed: {} - {}",
                            command,
                            result.error
                        );
                    }
                }
            );


            /*
             * Return immediately to ARK's game thread.
             */
            return;
        }


        if (
            request.action ==
            "GiveItemToEOSId"
        )
        {
            const std::string eos_id =
                request.payload.value(
                    "eosId",
                    ""
                );


            const std::string blueprint =
                request.payload.value(
                    "blueprint",
                    ""
                );


            const int quantity =
                request.payload.value(
                    "quantity",
                    1
                );


            const float quality =
                request.payload.value(
                    "quality",
                    0.0f
                );


            const bool force_blueprint =
                request.payload.value(
                    "forceBlueprint",
                    false
                );


            const auto result =
                Companion::GiveItemToEOSId(
                    eos_id,
                    blueprint,
                    quantity,
                    quality,
                    force_blueprint
                );


            SendResponse(
                request.request_id,
                result.success,
                result.error
            );


            if (
                result.success
            )
            {
                Log::GetLog()->info(
                    "GiveItemToEOSId succeeded for EOS {}",
                    eos_id
                );
            }
            else
            {
                Log::GetLog()->warn(
                    "GiveItemToEOSId failed for EOS {}: {}",
                    eos_id,
                    result.error
                );
            }


            return;
        }


        SendResponse(
            request.request_id,
            false,
            "Unknown companion action."
        );
    }
}


namespace Companion
{
    void PublishChatMessage(
        AShooterPlayerController* player,
        const FString* message,
        EChatSendMode::Type send_mode,
        int sender_platform
    )
    {
        if (
            !authenticated.load() ||
            websocket.getReadyState() !=
                ix::ReadyState::Open ||
            !player ||
            !message ||
            message->IsEmpty()
        )
        {
            return;
        }


        const FString eos =
            AsaApi::IApiUtils::
                GetEOSIDFromController(
                    player
                );


        const std::string eos_id =
            eos.ToString();


        if (
            eos_id.empty()
        )
        {
            return;
        }


        FString survivor_name;


        player
            ->GetPlayerCharacterName(
                &survivor_name
            );


        int tribe_id =
            0;

        std::string tribe_name;

        bool is_tribe_admin =
            false;


        const bool has_tribe =
            GetPlayerTribeContext(
                player,
                tribe_id,
                tribe_name,
                is_tribe_admin
            );


        /*
         * UUID-style event ID generated using the same cryptographic
         * RNG already used for companion identities.
         */
        const std::string message_id =
            GenerateCompanionGuid();


        json event =
        {
            {
                "type",
                "chat_message"
            },
            {
                "schemaVersion",
                1
            },
            {
                "messageId",
                message_id
            },
            {
                "origin",
                "GAME"
            },
            {
                "message",
                message
                    ->ToStringUTF8()
            },
            {
                "channel",
                ChatSendModeName(
                    send_mode
                )
            },
            {
                "sendMode",
                static_cast<int>(
                    send_mode
                )
            },
            {
                "senderPlatform",
                sender_platform
            },
            {
                "server",
                {
                    {
                        "serverId",
                        metadata.server_id
                    },
                    {
                        "clusterId",
                        metadata.cluster_id
                    },
                    {
                        "sessionName",
                        metadata.session_name
                    }
                }
            },
            {
                "player",
                {
                    {
                        "eosId",
                        eos_id
                    },
                    {
                        "survivorName",
                        survivor_name
                            .ToStringUTF8()
                    },
                    {
                        "tribeId",
                        has_tribe
                            ? json(
                                tribe_id
                            )
                            : json(
                                nullptr
                            )
                    },
                    {
                        "tribeName",
                        has_tribe
                            ? json(
                                tribe_name
                            )
                            : json(
                                nullptr
                            )
                    },
                    {
                        "isTribeAdmin",
                        is_tribe_admin
                    }
                }
            }
        };


        SendJson(
            event
        );


        Log::GetLog()->debug(
            "Published {} chat from EOS {}",
            ChatSendModeName(
                send_mode
            ),
            eos_id
        );
    }


    void Start()
    {
        if (
            started.exchange(
                true
            )
        )
        {
            return;
        }


        try
        {
            config =
                LoadConfig();


            StartPluginUpdateCheck(); // updater startup
        }
        catch (
            const std::exception& error
        )
        {
            started.store(
                false
            );


            Log::GetLog()->error(
                "PixelPurge Companion config error: {}",
                error.what()
            );


            return;
        }


        if (
            !config.enabled
        )
        {
            Log::GetLog()->info(
                "PixelPurge Companion is disabled in config.json"
            );

            return;
        }


        authenticated.store(
            false
        );


        /*
         * Start() is called from AShooterGameMode::BeginPlay
         * on ARK's game thread, so this is the safe place
         * to read Unreal server metadata.
         */
        CaptureServerMetadata();


        if (
            !config.paired
        )
        {
            pairing_code =
                GeneratePairingCode();


            PrintPairingInstructions();
        }


        websocket.setUrl(
            config.url
        );


        /*
         * Keep the connection alive through reverse
         * proxies and automatically reconnect if the
         * backend or network disappears.
         */
        websocket.setPingInterval(
            30
        );


        websocket.enableAutomaticReconnection();


        /*
         * SYSTEM uses the Windows/system trust roots.
         * Hostname validation remains enabled.
         */
        ix::SocketTLSOptions tls;

        tls.caFile =
            "SYSTEM";

        tls.disable_hostname_validation =
            false;


        websocket.setTLSOptions(
            tls
        );


        websocket.setOnMessageCallback(
            [](
                const ix::WebSocketMessagePtr& message
            )
            {
                if (
                    message->type ==
                    ix::WebSocketMessageType::Open
                )
                {
                    authenticated.store(
                        false
                    );


                    Log::GetLog()->info(
                        "PixelPurge Companion connected to backend"
                    );


                    SendHello();

                    return;
                }


                if (
                    message->type ==
                    ix::WebSocketMessageType::Message
                )
                {
                    HandleMessage(
                        message->str
                    );

                    return;
                }


                if (
                    message->type ==
                    ix::WebSocketMessageType::Close
                )
                {
                    authenticated.store(
                        false
                    );


                    Log::GetLog()->warn(
                        "PixelPurge Companion disconnected: {}",
                        message
                            ->closeInfo
                            .reason
                    );

                    return;
                }


                if (
                    message->type ==
                    ix::WebSocketMessageType::Error
                )
                {
                    authenticated.store(
                        false
                    );


                    Log::GetLog()->error(
                        "PixelPurge Companion WebSocket error: {}",
                        message
                            ->errorInfo
                            .reason
                    );

                    return;
                }
            }
        );


        websocket.start();


        Log::GetLog()->info(
            "PixelPurge Companion WebSocket client started"
        );
    }


    void ProcessPendingRequests()
    {
        SendPresenceIfDue();


        /*
         * Called once per second by AsaApi.
         *
         * Drain only a bounded number each tick so
         * remote requests cannot monopolize the
         * game thread.
         */
        for (
            int processed = 0;
            processed < 20;
            ++processed
        )
        {
            std::optional<
                PendingRequest
            > request;


            {
                std::lock_guard lock(
                    queue_mutex
                );


                if (
                    pending_requests.empty()
                )
                {
                    break;
                }


                request =
                    std::move(
                        pending_requests.front()
                    );


                pending_requests.pop();
            }


            ExecuteRequest(
                *request
            );
        }
    }


    void Stop()
    {
        if (
            !started.exchange(
                false
            )
        )
        {
            return;
        }


        authenticated.store(
            false
        );


        websocket.stop();


        {
            std::lock_guard lock(
                queue_mutex
            );


            while (
                !pending_requests.empty()
            )
            {
                pending_requests.pop();
            }
        }


        Log::GetLog()->info(
            "PixelPurge Companion WebSocket client stopped"
        );
    }
}


