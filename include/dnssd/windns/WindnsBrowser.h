#pragma once

#if !_WIN32 || !USE_WINDNS
#error This file should only be included on Windows builds and have the 'USE_WINDNS' compilation flag enabled.
#endif

#include "Windns.h"
#include "WindnsDiscoveredService.h"
#include "dnssd/common/BrowserBase.h"
#include "dnssd/common/Log.h"
#include "dnssd/common/Result.h"

#include <map>
#include <mutex>
#include <string>

namespace dnssd
{

/**
 * Windows native DNS-SD implementation of BrowserBase using the WinDNS API (windns.h).
 * Only the .local mDNS domain is supported; custom domains are not available via this API.
 *
 * Discovery is performed in three async stages:
 *   1. DnsServiceBrowse     — finds PTR records, fires onServiceDiscovered / onServiceRemoved
 *   2. DnsServiceResolve    — resolves host, port, and TXT record, fires onServiceResolved
 *   3. DnsQueryEx (A/AAAA) — enumerates all addresses, fires onAddressAdded / onAddressRemoved
 *
 * All WinDNS callbacks arrive on thread-pool threads; mLock serialises access to mServices.
 */
class WindnsBrowser : public BrowserBase
{
public:
    explicit WindnsBrowser() = default;
    ~WindnsBrowser() override;

    /**
     * Starts browsing for a service type on the local mDNS domain.
     * Can be called multiple times with different service types.
     * @param serviceType The service type (e.g. "_http._tcp.").
     * @return A Result indicating success or failure.
     */
    Result browseFor (const std::string& serviceType) override;

private:
    /// One cancel handle per browsed service type, keyed by wide-string service type.
    std::map<std::wstring, DNS_SERVICE_CANCEL> mBrowseCancels;

    /// All currently known service instances, keyed by fully-qualified instance name (narrow, as received from browse).
    std::map<std::string, WindnsDiscoveredService> mServices;

    std::recursive_mutex mLock;

    // -- Context structs passed as pQueryContext to WinDNS async calls --
    // Browse passes 'this' directly; resolve and address queries need the instance name too.

    struct ResolveContext
    {
        WindnsBrowser* owner;
        std::string instanceName;
    };

    struct AddressQueryContext
    {
        WindnsBrowser* owner;
        std::string instanceName;
        /// Embedded result struct kept alive until the async callback fires (pQueryResults == &queryResult).
        DNS_QUERY_RESULT queryResult {};
    };

    // -- Static WINAPI callbacks (invoked on WinDNS thread-pool threads) --

    /**
     * Fired by DnsServiceBrowse when PTR records are discovered or removed.
     * @param Status        DNS status code (ERROR_SUCCESS on success).
     * @param pQueryContext Pointer to the WindnsBrowser instance (passed as 'this' in browseFor).
     * @param pDnsRecord    Chain of DNS_RECORD results (DNS_TYPE_PTR). Freed by WinDNS after callback returns.
     */
    static VOID WINAPI browseCallback (DWORD Status, PVOID pQueryContext, PDNS_RECORD pDnsRecord);

    /**
     * Fired by DnsServiceResolve when a service instance is resolved to its host, port, and TXT record.
     * Routes into onResolveResult() after casting pQueryContext to ResolveContext.
     * @param Status        DNS status code (ERROR_SUCCESS on success).
     * @param pQueryContext Pointer to a heap-allocated ResolveContext.
     * @param pInstance     Resolved service instance. Must be freed with DnsServiceFreeInstance.
     */
    static VOID WINAPI resolveCallback (DWORD Status, PVOID pQueryContext, PDNS_SERVICE_INSTANCE pInstance);

    /**
     * Fired by DnsQueryEx for A (IPv4) record queries.
     * Routes into onAddressResult() after casting pQueryContext to AddressQueryContext.
     * @param pQueryContext Pointer to a heap-allocated AddressQueryContext.
     * @param pQueryResults Query results; pQueryResults->pQueryRecords is the DNS_RECORD chain.
     */
    static VOID WINAPI aQueryCallback (PVOID pQueryContext, PDNS_QUERY_RESULT pQueryResults);

    /**
     * Fired by DnsQueryEx for AAAA (IPv6) record queries.
     * Routes into onAddressResult() after casting pQueryContext to AddressQueryContext.
     * @param pQueryContext Pointer to a heap-allocated AddressQueryContext.
     * @param pQueryResults Query results; pQueryResults->pQueryRecords is the DNS_RECORD chain.
     */
    static VOID WINAPI aaaaQueryCallback (PVOID pQueryContext, PDNS_QUERY_RESULT pQueryResults);

    // -- Instance methods (called from callbacks, mLock already held) --

    /**
     * Issues DnsServiceResolve for the given instance name.
     * Stores the cancel handle in mServices[instanceName].resolveCancel.
     * Must be called with mLock held.
     * @param instanceName Wide-string fully-qualified instance name (e.g. L"MyDevice._http._tcp.local").
     */
    void issueResolve (const std::string& instanceName);

    /**
     * Issues DnsQueryEx for A and AAAA records for the given host name,
     * cancelling any previously in-flight address queries for this service first.
     * Must be called with mLock held.
     * @param instanceName Instance name used to look up the service on callback.
     * @param hostName     Host to query (e.g. "MyDevice.local").
     */
    void issueAddressQueries (const std::string& instanceName, const std::string& hostName);

    /**
     * Processes a resolved DNS_SERVICE_INSTANCE, populating hostTarget, port, and txtRecord
     * on the matching service and firing onServiceResolvedCallback.
     * Then issues A/AAAA address queries.
     * Must be called with mLock held.
     * @param instanceName Instance name.
     * @param pInstance    Resolved instance data. Caller is responsible for calling DnsServiceFreeInstance.
     */
    void onResolveResult (const std::string& instanceName, PDNS_SERVICE_INSTANCE pInstance);

    /**
     * Processes a chain of A or AAAA DNS_RECORD results, inserting new addresses into
     * description.interfaces and firing onAddressAddedCallback for each new address.
     * Zero-TTL records trigger removal from the set and fire onAddressRemovedCallback.
     * Must be called with mLock held.
     * @param instanceName Instance name.
     * @param records      Chain of DNS_RECORD results (DNS_TYPE_A or DNS_TYPE_AAAA).
     */
    void onAddressResult (const std::string& instanceName, PDNS_RECORD records);

    /**
     * Reports an error via onBrowseErrorCallback if result.hasError().
     * @return true if there was an error, false otherwise.
     */
    bool reportIfError (const Result& result) const noexcept;
};

} // namespace dnssd
