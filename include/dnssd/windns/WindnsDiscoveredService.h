#pragma once

#if !_WIN32 || !USE_WINDNS
#error This file should only be included on Windows builds and have the 'USE_WINDNS' compilation flag enabled.
#endif

#include "Windns.h"
#include "dnssd/ServiceDescription.h"

#include <chrono>
#include <memory>
#include <string>

namespace dnssd
{

class WindnsBrowser;

/**
 * One DnsServiceResolve call: the request state and its cancel handle.
 */
struct WindnsResolveRequest
{
    WindnsBrowser* owner = nullptr;
    std::string instanceName;
    DNS_SERVICE_CANCEL cancel {};
};

/**
 * One DnsQueryEx A or AAAA call: the request state, its result and its cancel handle.
 */
struct WindnsAddressQuery
{
    WindnsBrowser* owner = nullptr;
    std::string instanceName;
    bool isIpv6 = false;
    /// Result struct kept alive until the async callback fires (pQueryResults == &result).
    DNS_QUERY_RESULT result {};
    DNS_QUERY_CANCEL cancel {};
};

/**
 * Tracks all resolved state for a single discovered service instance.
 */
struct WindnsDiscoveredService
{
    /// The service description, filled incrementally as queries complete.
    ServiceDescription description;

    /// TTL in seconds from the most recent PTR record. A zero TTL (goodbye) removes the service; otherwise the service
    /// is pruned when it has not been seen for longer than this.
    DWORD ttl = 0;

    /// Last time the service was confirmed alive: a non-goodbye PTR record or a successful resolve.
    std::chrono::steady_clock::time_point lastSeen;

    /// When the current DnsServiceResolve call was issued; used for the resolve timeout.
    std::chrono::steady_clock::time_point resolveStartedAt;

    /// Resolves in a row that failed or timed out. Reset only by a successful resolve.
    int consecutiveResolveFailures = 0;

    /// True once onServiceResolved has fired for this service.
    bool resolved = false;

    /// The in-flight DnsServiceResolve call, or nullptr.
    std::shared_ptr<WindnsResolveRequest> resolve;

    /// The in-flight A record (IPv4) query, or nullptr.
    std::shared_ptr<WindnsAddressQuery> aQuery;

    /// The in-flight AAAA record (IPv6) query, or nullptr.
    std::shared_ptr<WindnsAddressQuery> aaaaQuery;
};

} // namespace dnssd
