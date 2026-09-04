#include "LocalRconClient.h"

#include "API/ARK/Ark.h"

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>

#include <condition_variable>
#include <deque>
#include <filesystem>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>


#pragma comment(lib, "Ws2_32.lib")


namespace
{
    SOCKET g_socket =
        INVALID_SOCKET;


    std::mutex g_mutex;


    bool g_winsock_started =
        false;


    int g_rcon_port =
        0;


    std::string g_rcon_password;


    std::filesystem::path g_ini_path;


    struct LocalRconWorkItem
    {
        std::string command;

        std::function<
            void(
                Companion::LocalRconResult
            )
        > callback;
    };


    std::mutex g_work_mutex;

    std::condition_variable g_work_cv;

    std::deque<
        LocalRconWorkItem
    > g_work_queue;

    std::thread g_worker_thread;

    bool g_worker_stopping =
        false;


    constexpr int SOCKET_TIMEOUT_MS =
        500;


    bool SendAll(
        SOCKET socket,
        const char* data,
        int length
    )
    {
        int sent =
            0;


        while (sent < length)
        {
            const int result =
                send(
                    socket,
                    data + sent,
                    length - sent,
                    0
                );


            if (
                result == SOCKET_ERROR ||
                result == 0
            )
            {
                return false;
            }


            sent +=
                result;
        }


        return true;
    }


    bool ReceiveAll(
        SOCKET socket,
        char* data,
        int length
    )
    {
        int received =
            0;


        while (received < length)
        {
            const int result =
                recv(
                    socket,
                    data + received,
                    length - received,
                    0
                );


            if (
                result == SOCKET_ERROR ||
                result == 0
            )
            {
                return false;
            }


            received +=
                result;
        }


        return true;
    }


    bool SendPacket(
        SOCKET socket,
        int id,
        int type,
        const std::string& body
    )
    {
        const int body_length =
            static_cast<int>(
                body.size()
            );


        const int packet_size =
            body_length + 10;


        const int total_size =
            packet_size + 4;


        std::vector<char>
            packet(
                total_size,
                0
            );


        int offset =
            0;


        memcpy(
            packet.data() + offset,
            &packet_size,
            4
        );

        offset +=
            4;


        memcpy(
            packet.data() + offset,
            &id,
            4
        );

        offset +=
            4;


        memcpy(
            packet.data() + offset,
            &type,
            4
        );

        offset +=
            4;


        if (body_length > 0)
        {
            memcpy(
                packet.data() + offset,
                body.data(),
                body_length
            );
        }


        return SendAll(
            socket,
            packet.data(),
            total_size
        );
    }


    struct RconPacket
    {
        bool valid =
            false;

        int id =
            0;

        int type =
            0;

        std::string body;
    };


    RconPacket ReceivePacket(
        SOCKET socket
    )
    {
        RconPacket result;


        int packet_size =
            0;


        if (
            !ReceiveAll(
                socket,
                reinterpret_cast<char*>(
                    &packet_size
                ),
                4
            )
        )
        {
            return result;
        }


        if (
            packet_size < 10 ||
            packet_size > 4 * 1024 * 1024
        )
        {
            return result;
        }


        std::vector<char>
            packet(
                packet_size
            );


        if (
            !ReceiveAll(
                socket,
                packet.data(),
                packet_size
            )
        )
        {
            return result;
        }


        memcpy(
            &result.id,
            packet.data(),
            4
        );


        memcpy(
            &result.type,
            packet.data() + 4,
            4
        );


        const int body_length =
            packet_size - 10;


        if (body_length > 0)
        {
            result.body.assign(
                packet.data() + 8,
                body_length
            );
        }


        result.valid =
            true;


        return result;
    }


    void Disconnect()
    {
        if (
            g_socket !=
            INVALID_SOCKET
        )
        {
            closesocket(
                g_socket
            );


            g_socket =
                INVALID_SOCKET;
        }
    }


    bool FileExists(
        const std::filesystem::path& path
    )
    {
        std::error_code error;


        return
            std::filesystem::exists(
                path,
                error
            );
    }


    bool FindGameUserSettings()
    {
        const auto current =
            std::filesystem::current_path();


        const std::vector<
            std::filesystem::path
        > candidates =
        {
            current /
                "ShooterGame/Saved/Config/WindowsServer/GameUserSettings.ini",

            current /
                "../../Saved/Config/WindowsServer/GameUserSettings.ini",

            current /
                "../../../Saved/Config/WindowsServer/GameUserSettings.ini",

            current /
                "../../../../ShooterGame/Saved/Config/WindowsServer/GameUserSettings.ini"
        };


        for (
            const auto& candidate :
            candidates
        )
        {
            if (
                FileExists(
                    candidate
                )
            )
            {
                std::error_code error;


                g_ini_path =
                    std::filesystem::weakly_canonical(
                        candidate,
                        error
                    );


                if (error)
                {
                    g_ini_path =
                        candidate;
                }


                return true;
            }
        }


        return false;
    }


    bool LoadRconSettings()
    {
        if (
            !FindGameUserSettings()
        )
        {
            Log::GetLog()->error(
                "Local RCON could not locate GameUserSettings.ini"
            );


            return false;
        }


        wchar_t password_buffer[1024]{};


        GetPrivateProfileStringW(
            L"ServerSettings",
            L"ServerAdminPassword",
            L"",
            password_buffer,
            static_cast<DWORD>(
                std::size(
                    password_buffer
                )
            ),
            g_ini_path.c_str()
        );


        const int port =
            GetPrivateProfileIntW(
                L"ServerSettings",
                L"RCONPort",
                0,
                g_ini_path.c_str()
            );


        if (
            password_buffer[0] ==
            L'\0'
        )
        {
            Log::GetLog()->error(
                "Local RCON could not read ServerAdminPassword"
            );


            return false;
        }


        if (
            port <= 0 ||
            port > 65535
        )
        {
            Log::GetLog()->error(
                "Local RCON could not read a valid RCONPort"
            );


            return false;
        }


        const int required =
            WideCharToMultiByte(
                CP_UTF8,
                0,
                password_buffer,
                -1,
                nullptr,
                0,
                nullptr,
                nullptr
            );


        if (required <= 1)
        {
            return false;
        }


        std::string password(
            required - 1,
            '\0'
        );


        WideCharToMultiByte(
            CP_UTF8,
            0,
            password_buffer,
            -1,
            password.data(),
            required,
            nullptr,
            nullptr
        );


        g_rcon_password =
            password;


        g_rcon_port =
            port;


        Log::GetLog()->info(
            "Local RCON configuration loaded. port={}, ini={}",
            g_rcon_port,
            g_ini_path.string()
        );


        return true;
    }


    bool ConnectAndAuthenticate()
    {
        Disconnect();


        if (
            g_rcon_password.empty() ||
            g_rcon_port <= 0
        )
        {
            if (
                !LoadRconSettings()
            )
            {
                return false;
            }
        }


        g_socket =
            socket(
                AF_INET,
                SOCK_STREAM,
                IPPROTO_TCP
            );


        if (
            g_socket ==
            INVALID_SOCKET
        )
        {
            Log::GetLog()->error(
                "Local RCON socket creation failed: {}",
                WSAGetLastError()
            );


            return false;
        }


        DWORD timeout =
            SOCKET_TIMEOUT_MS;


        setsockopt(
            g_socket,
            SOL_SOCKET,
            SO_RCVTIMEO,
            reinterpret_cast<const char*>(
                &timeout
            ),
            sizeof(
                timeout
            )
        );


        setsockopt(
            g_socket,
            SOL_SOCKET,
            SO_SNDTIMEO,
            reinterpret_cast<const char*>(
                &timeout
            ),
            sizeof(
                timeout
            )
        );


        sockaddr_in address{};


        address.sin_family =
            AF_INET;


        address.sin_port =
            htons(
                static_cast<u_short>(
                    g_rcon_port
                )
            );


        address.sin_addr.s_addr =
            htonl(
                INADDR_LOOPBACK
            );


        if (
            connect(
                g_socket,
                reinterpret_cast<
                    sockaddr*
                >(
                    &address
                ),
                sizeof(
                    address
                )
            ) ==
            SOCKET_ERROR
        )
        {
            const int error =
                WSAGetLastError();


            Log::GetLog()->error(
                "Local RCON connect failed: {}",
                error
            );


            Disconnect();


            return false;
        }


        Log::GetLog()->info(
            "Local RCON TCP connection established"
        );


        constexpr int auth_id =
            12345;


        constexpr int auth_type =
            3;


        if (
            !SendPacket(
                g_socket,
                auth_id,
                auth_type,
                g_rcon_password
            )
        )
        {
            Log::GetLog()->error(
                "Local RCON failed sending auth packet"
            );


            Disconnect();


            return false;
        }


        const auto response =
            ReceivePacket(
                g_socket
            );


        if (!response.valid)
        {
            Log::GetLog()->error(
                "Local RCON failed reading auth response"
            );


            Disconnect();


            return false;
        }


        Log::GetLog()->info(
            "Local RCON auth response: id={}, type={}, bodyLength={}",
            response.id,
            response.type,
            response.body.size()
        );


        /*
         * ASA auth behavior:
         *
         * Successful authentication returns:
         *   same request ID
         *   packet type 2
         *   usually empty body
         *
         * Failed authentication returns ID -1.
         */
        if (
            response.id ==
            -1
        )
        {
            Log::GetLog()->error(
                "Local RCON authentication rejected"
            );


            Disconnect();


            return false;
        }


        if (
            response.id !=
            auth_id
        )
        {
            Log::GetLog()->error(
                "Local RCON auth response had unexpected ID: {}",
                response.id
            );


            Disconnect();


            return false;
        }


        if (
            response.type !=
            2
        )
        {
            Log::GetLog()->error(
                "Local RCON auth response had unexpected type: {}",
                response.type
            );


            Disconnect();


            return false;
        }


        Log::GetLog()->info(
            "Local RCON authenticated successfully"
        );


        return true;
    }


    Companion::LocalRconResult
        ExecuteInternal(
            const std::string& command
        )
    {
        Companion::LocalRconResult result;


        if (
            g_socket ==
            INVALID_SOCKET
        )
        {
            if (
                !ConnectAndAuthenticate()
            )
            {
                result.error =
                    "Unable to connect or authenticate to localhost RCON.";


                return result;
            }
        }


        static int next_id =
            2000;


        ++next_id;


        if (
            next_id >
            1000000000
        )
        {
            next_id =
                2000;
        }


        constexpr int command_type =
            2;


        if (
            !SendPacket(
                g_socket,
                next_id,
                command_type,
                command
            )
        )
        {
            Disconnect();


            result.error =
                "Failed sending localhost RCON command.";


            return result;
        }


        std::string output;


        bool received_response =
            false;


        /*
         * Most ASA RCON commands return one packet.
         *
         * We allow several packets so larger responses
         * such as player lists can be assembled.
         */
        for (
            int attempt = 0;
            attempt < 16;
            ++attempt
        )
        {
            const auto packet =
                ReceivePacket(
                    g_socket
                );


            if (!packet.valid)
            {
                /*
                 * Once at least one matching response was
                 * received, a short timeout simply means
                 * the response is complete.
                 */
                if (
                    received_response
                )
                {
                    break;
                }


                Disconnect();


                result.error =
                    "Timed out waiting for localhost RCON response.";


                return result;
            }


            if (
                packet.id !=
                next_id
            )
            {
                continue;
            }


            received_response =
                true;


            if (
                !packet.body.empty()
            )
            {
                if (
                    !output.empty()
                )
                {
                    output +=
                        "\n";
                }


                output +=
                    packet.body;
            }


            /*
             * For normal ASA responses the complete
             * payload is usually returned immediately.
             *
             * Try one additional packet and let the
             * short socket timeout terminate collection.
             */
        }


        result.success =
            received_response;


        result.output =
            output;


        if (
            !result.success
        )
        {
            result.error =
                "No localhost RCON response was received.";
        }


        return result;
    }
}


    void LocalRconWorkerLoop()
    {
        Log::GetLog()->info(
            "Local RCON worker started"
        );


        while (true)
        {
            LocalRconWorkItem work;


            {
                std::unique_lock<
                    std::mutex
                > lock(
                    g_work_mutex
                );


                g_work_cv.wait(
                    lock,
                    []()
                    {
                        return
                            g_worker_stopping ||
                            !g_work_queue.empty();
                    }
                );


                if (
                    g_worker_stopping &&
                    g_work_queue.empty()
                )
                {
                    break;
                }


                work =
                    std::move(
                        g_work_queue.front()
                    );


                g_work_queue.pop_front();
            }


            Companion::LocalRconResult result;


            try
            {
                result =
                    Companion::ExecuteLocalRcon(
                        work.command
                    );
            }
            catch (
                const std::exception& error
            )
            {
                result.success =
                    false;


                result.error =
                    error.what();
            }
            catch (...)
            {
                result.success =
                    false;


                result.error =
                    "Unknown exception in Local RCON worker.";
            }


            if (
                work.callback
            )
            {
                try
                {
                    work.callback(
                        std::move(
                            result
                        )
                    );
                }
                catch (
                    const std::exception& error
                )
                {
                    Log::GetLog()->error(
                        "Local RCON callback exception: {}",
                        error.what()
                    );
                }
                catch (...)
                {
                    Log::GetLog()->error(
                        "Unknown Local RCON callback exception"
                    );
                }
            }
        }


        Log::GetLog()->info(
            "Local RCON worker stopped"
        );
    }



namespace Companion
{
    bool StartLocalRcon()
    {
        {
            std::lock_guard<
                std::mutex
            > lock(
                g_mutex
            );


            if (
                !g_winsock_started
            )
            {
                WSADATA data{};


                if (
                    WSAStartup(
                        MAKEWORD(
                            2,
                            2
                        ),
                        &data
                    ) != 0
                )
                {
                    Log::GetLog()->error(
                        "Local RCON failed to initialize Winsock"
                    );


                    return false;
                }


                g_winsock_started =
                    true;
            }


            /*
             * Read configuration now.
             * We deliberately do NOT connect yet because
             * ARK's RCON listener may not be ready.
             */
            LoadRconSettings();
        }


        {
            std::lock_guard<
                std::mutex
            > lock(
                g_work_mutex
            );


            g_worker_stopping =
                false;
        }


        if (
            !g_worker_thread.joinable()
        )
        {
            g_worker_thread =
                std::thread(
                    LocalRconWorkerLoop
                );
        }


        Log::GetLog()->info(
            "Local RCON client initialized"
        );


        return true;
    }


    void StopLocalRcon()
    {
        /*
         * Stop the worker BEFORE taking g_mutex.
         *
         * The worker may currently be inside
         * ExecuteLocalRcon(), which also needs g_mutex.
         */
        {
            std::lock_guard<
                std::mutex
            > lock(
                g_work_mutex
            );


            g_worker_stopping =
                true;
        }


        g_work_cv.notify_all();


        if (
            g_worker_thread.joinable()
        )
        {
            g_worker_thread.join();
        }


        {
            std::lock_guard<
                std::mutex
            > lock(
                g_work_mutex
            );


            g_work_queue.clear();
        }


        {
            std::lock_guard<
                std::mutex
            > lock(
                g_mutex
            );


            Disconnect();


            g_rcon_password.clear();


            g_rcon_port =
                0;


            if (
                g_winsock_started
            )
            {
                WSACleanup();


                g_winsock_started =
                    false;
            }
        }


        Log::GetLog()->info(
            "Local RCON client stopped"
        );
    }


    LocalRconResult ExecuteLocalRcon(
        const std::string& command
    )
    {
        std::lock_guard<
            std::mutex
        > lock(
            g_mutex
        );


        LocalRconResult result;


        if (
            command.empty()
        )
        {
            result.error =
                "Command cannot be empty.";


            return result;
        }


        Log::GetLog()->info(
            "Local RCON executing: {}",
            command
        );


        result =
            ExecuteInternal(
                command
            );


        /*
         * Retry once after reconnecting.
         */
        if (
            !result.success
        )
        {
            Disconnect();


            if (
                ConnectAndAuthenticate()
            )
            {
                result =
                    ExecuteInternal(
                        command
                    );
            }
        }


        if (
            result.success
        )
        {
            Log::GetLog()->info(
                "Local RCON command succeeded: {}",
                command
            );


            if (
                !result.output.empty()
            )
            {
                Log::GetLog()->info(
                    "Local RCON output: {}",
                    result.output
                );
            }
        }
        else
        {
            Log::GetLog()->warn(
                "Local RCON command failed: {} - {}",
                command,
                result.error
            );
        }


        return result;
    }


    void ExecuteLocalRconAsync(
        const std::string& command,
        std::function<
            void(
                LocalRconResult
            )
        > callback
    )
    {
        {
            std::lock_guard<
                std::mutex
            > lock(
                g_work_mutex
            );


            if (
                g_worker_stopping
            )
            {
                LocalRconResult result;


                result.success =
                    false;


                result.error =
                    "Local RCON worker is stopping.";


                if (
                    callback
                )
                {
                    callback(
                        std::move(
                            result
                        )
                    );
                }


                return;
            }


            g_work_queue.push_back(
                LocalRconWorkItem{
                    command,
                    std::move(
                        callback
                    )
                }
            );
        }


        g_work_cv.notify_one();
    }
}
