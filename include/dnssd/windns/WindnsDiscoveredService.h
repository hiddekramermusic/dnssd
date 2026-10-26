#pragma once

#if !_WIN32 || !USE_WINDNS
#error This file should only be included on Windows builds and have the 'USE_WINDNS' compilation flag enabled.
#endif

#include "Windns.h"
#include "dnssd/ServiceDescription.h"

#include <chrono>
#include <cstdint>

namespace dnssd
{

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

    /// Id of the current DnsServiceResolve call. Callbacks carrying another id (e.g. the ERROR_CANCELLED callback of a
    /// resolve that timed out) do not change this service's state.
    uint64_t currentResolveId = 0;

    /// Cancel handle for the in-flight DnsServiceResolve call.
    DNS_SERVICE_CANCEL resolveCancel {};

    /// Cancel handle of the in-flight A record (IPv4) query. Points into the query's heap-allocated context, which
    /// lives until the query callback, as DnsCancelQuery requires. Valid only while aQueryInFlight.
    DNS_QUERY_CANCEL* aCancel = nullptr;

    /// Cancel handle of the in-flight AAAA record (IPv6) query. Same lifetime rules as aCancel.
    DNS_QUERY_CANCEL* aaaaCancel = nullptr;

    /// True while a DnsServiceResolve call is in-flight (cancel handle is live).
    bool resolveInFlight = false;

    /// True while a DnsQueryEx A (IPv4) call is in-flight (cancel handle is live).
    bool aQueryInFlight = false;

    /// True while a DnsQueryEx AAAA (IPv6) call is in-flight (cancel handle is live).
    bool aaaaQueryInFlight = false;
};

} // namespace dnssd
