#pragma once

#include <exception>
#include <string>

#if USE_WINDNS
#include <dnssd/windns/Windns.h>
#elif USE_AVAHI
// No backend-specific header needed here
#else
#include <dnssd/bonjour/Bonjour.h>
#endif

namespace dnssd
{

/**
 * Class for indicating success or failure. It can hold a backend-specific error type and an error message.
 */
class Result
{
public:
    enum class Code {
        NoError = 0,
        UnknownError = -1,
    };

    Result() = default;
    Result (Code code) noexcept : mCode (code) {}
    Result (Code code, const std::string& errorMsg) noexcept : mCode (code), mErrorMsg (errorMsg) {}

#if !USE_WINDNS && !USE_AVAHI
    /**
     * Construct this Result with given DNSServiceErrorType.
     * @param error The DNSServiceErrorType to store.
     */
    explicit Result (DNSServiceErrorType error) noexcept;
#endif

#if USE_WINDNS && _WIN32
    explicit Result(DNS_STATUS  error) noexcept;
#endif

#if USE_AVAHI
    /**
     * Construct this Result with given Avahi error code.
     * @param error The Avahi error code (int) to store.
     */
    explicit Result (int error) noexcept;
#endif

    /**
     * Constructs this Result with an error message.
     * @param errorMsg The error message to store.
     */
    explicit Result (const std::string& errorMsg) noexcept;

    /**
     * @return Returns true if this result holds an error.
     */
    bool hasError() const;

    /**
     * @return Returns true if this result doesn't hold an error.
     */
    bool isOk() const;

    /**
     * @return Returns a description of this Result, which will either return the error message or a description of the stored
     * DNSServiceErrorType.
     */
    std::string description() const noexcept;

private:
#if USE_WINDNS
    DNS_STATUS mError = 0; // ERROR_SUCCESS
#elif USE_AVAHI
    int mError = 0; // AVAHI_OK
#else
    DNSServiceErrorType mError = kDNSServiceErr_NoError;
#endif

    Code mCode = Code::NoError;
    std::string mErrorMsg;

#if !USE_WINDNS && !USE_AVAHI
    static const char* DNSServiceErrorDescription (DNSServiceErrorType error) noexcept;
#endif
};

} // namespace dnssd
