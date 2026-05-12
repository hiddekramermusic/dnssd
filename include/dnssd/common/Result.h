#pragma once

#include <exception>
#include <string>

#if USE_WINDNS
#include <dnssd/windns/Windns.h>
#else
#include <dnssd/bonjour/Bonjour.h>
#endif

namespace dnssd
{

/**
 * Class for indicating success or failure. It can hold a DNSServiceErrorType and an error message where either will
 * make the Result indicate an error.
 */
class Result
{
public:
    Result() = default;

#if !USE_WINDNS
    /**
     * Construct this Result with given DNSServiceErrorType.
     * @param error The DNSServiceErrorType to store.
     */
    explicit Result (DNSServiceErrorType error) noexcept;
#endif

#if USE_WINDNS && _WIN32
    explicit Result(DNS_STATUS  error) noexcept;
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
    DNS_STATUS mError = ERROR_SUCCESS;
#else
    DNSServiceErrorType mError = kDNSServiceErr_NoError;
#endif

    std::string mErrorMsg;

#if !USE_WINDNS
    static const char* DNSServiceErrorDescription (DNSServiceErrorType error) noexcept;
#endif
};

} // namespace dnssd
