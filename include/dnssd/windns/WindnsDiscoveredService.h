#pragma once

#if !_WIN32 || !USE_WINDNS
#error This file should only be included on Windows builds and have the 'USE_WINDNS' compilation flag enabled.
#endif

#include "Windns.h"
#include "dnssd/ServiceDescription.h"

namespace dnssd
{

/**
 * Tracks all resolved state for a single discovered service instance.
 */
struct WindnsDiscoveredService
{
    /// The service description, filled incrementally as queries complete.
    ServiceDescription description;

    /// TTL from the PTR record; used for goodbye packet detection (zero TTL = removal).
    DWORD ttl = 0;

    /// Cancel handle for the in-flight DnsServiceResolve call.
    DNS_SERVICE_CANCEL resolveCancel {};

    /// Cancel handle for the in-flight A record (IPv4) query.
    DNS_QUERY_CANCEL aCancel {};

    /// Cancel handle for the in-flight AAAA record (IPv6) query.
    DNS_QUERY_CANCEL aaaaCancel {};

    /// True once DnsServiceResolve has been called (cancel handle is live).
    bool resolveStarted = false;

    /// True once the DnsServiceResolve callback has fired (success or failure).
    /// Indicates the cancel handle is no longer live; hostTarget is populated only on success.
    bool resolveFinished = false;

    /// True while a DnsQueryEx A (IPv4) call is in-flight (cancel handle is live).
    bool aQueryInFlight = false;

    /// True while a DnsQueryEx AAAA (IPv6) call is in-flight (cancel handle is live).
    bool aaaaQueryInFlight = false;
};

} // namespace dnssd
