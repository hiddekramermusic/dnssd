#pragma once

#if !_WIN32 || !USE_WINDNS
#error This file should only be included on Windows builds and have the 'USE_WINDNS' compilation flag enabled.
#endif

#include "Windns.h"
#include "WindnsDiscoveredService.h"
#include "dnssd/common/BrowserBase.h"
#include "dnssd/common/Log.h"
#include "dnssd/common/Result.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <map>
#include <mutex>
#include <string>
#include <thread>

namespace dnssd
{

/// Interval of the WinDNS browser liveness check, and the time after which an unanswered resolve counts as a failure.
constexpr std::chrono::milliseconds kLivenessInterval { 5000 };

/// Resolve failures in a row after which the WinDNS browser removes a service.
constexpr int kMaxResolveFailures = 3;

/**
 * Windows native DNS-SD implementation of BrowserBase using the WinDNS API (windns.h).
 * Only the .local mDNS domain is supported; custom domains are not available via this API.
 *
 * Discovery is performed in async stages:
 *   1. DnsServiceBrowse   — finds PTR records, fires onServiceDiscovered / onServiceRemoved
 *   2. DnsServiceResolve  — resolves host, port, TXT, and (if included) addresses via ip4Address /
 *                           ip6Address on DNS_SERVICE_INSTANCE; fires onServiceResolved and onAddressAdded
 *   3. DnsQueryEx (A/AAAA) — fallback address query when DnsServiceResolve does not include addresses
 *
 * Liveness: a background thread re-resolves every known service every kLivenessInterval. For a service that is gone,
 * DnsServiceResolve does not call back; a resolve still in flight after kLivenessInterval is cancelled and counted as a
 * failure. After kMaxResolveFailures failures in a row, or when the service has not been seen for longer than its PTR
 * TTL, the service is removed and onServiceRemoved fires. This covers services that disappear without a goodbye packet.
 *
 * All WinDNS callbacks arrive on thread-pool threads; mLock serialises access to mServices.
 */
class WindnsBrowser : public BrowserBase
{
public:
    explicit WindnsBrowser() = default;

    /**
    * Sets up the browser with a custom TXT polling interval. If the interval is 0, services are not re-resolved for
    * TXT updates; the background thread still runs the liveness check.
    *
    * @param txtPollIntervalMs - the interval in milliseconds between TXT polls.
    */
    explicit WindnsBrowser (uint32_t txtPollIntervalMs) : mTxtPollIntervalMs (txtPollIntervalMs) {};

    ~WindnsBrowser() override;

    /**
     * Starts browsing for a service type on the local mDNS domain.
     * Can be called multiple times with different service types.
     * @param serviceType The service type (e.g. "_http._tcp.").
     * @return A Result indicating success or failure.
     */
    Result browseFor (const std::string& serviceType) override;

    /**
     * Enables periodic re-resolution of discovered services to detect TXT record updates.
     * The WinDNS API has no record-change subscription, so polling is the only reliable way
     * to pick up TXT changes announced by remote peers (e.g. Bonjour on macOS).
     * Each poll re-issues DnsServiceResolve for every known service and fires
     * onServiceResolved if the TXT record has changed.
     *
     * Can be called at any time; the background thread picks up the new interval immediately.
     * The background thread keeps running with an interval of 0, because it also runs the liveness check.
     *
     * @param intervalMs Poll interval in milliseconds. Pass 0 to disable TXT polling.
     */
    void setTxtPollIntervalMs (uint32_t intervalMs);

private:
    std::thread mPollThread;
    std::condition_variable mPollCv;
    std::mutex mPollMutex; // used only to satisfy wait_until; does not guard any data
    std::atomic<uint32_t> mTxtPollIntervalMs { 1000 };
    std::atomic<bool> mStopPollThread { false };
    std::atomic<bool> mTxtPollIntervalChanged { false }; // wakes pollLoop to reschedule the TXT poll

    /// One cancel handle per browsed service type, keyed by wide-string service type.
    std::map<std::wstring, DNS_SERVICE_CANCEL> mBrowseCancels;

    /// All currently known service instances, keyed by fully-qualified instance name (narrow, as received from browse).
    std::map<std::string, WindnsDiscoveredService> mServices;

    std::recursive_mutex mLock;

    /// Source of ResolveContext::resolveId. Guarded by mLock.
    uint64_t mNextResolveId = 0;

    /// Set by the destructor; browse results arriving after that are ignored. Guarded by mLock.
    bool mShuttingDown = false;

    /// Synchronises the destructor with callbacks that are still to come: the final ERROR_CANCELLED browseCallback per
    /// active browse, and one callback per issued resolve and address query. Both counters are guarded by mCancelMutex.
    std::mutex mCancelMutex;
    std::condition_variable mCancelCv;
    int mPendingBrowseCancels = 0;
    int mOutstandingCallbacks = 0;

    // -- Context structs passed as pQueryContext to WinDNS async calls --
    // Browse passes 'this' directly; resolve and address queries need the instance name too.

    struct ResolveContext
    {
        WindnsBrowser* owner;
        std::string instanceName;
        /// Matched against WindnsDiscoveredService::currentResolveId; a mismatch means this resolve was superseded.
        uint64_t resolveId;
    };

    struct AddressQueryContext
    {
        WindnsBrowser* owner;
        std::string instanceName;
        /// Embedded result struct kept alive until the async callback fires (pQueryResults == &queryResult).
        DNS_QUERY_RESULT queryResult {};
        /// Cancel handle; must stay valid until the callback fires, so it lives here rather than in the service.
        DNS_QUERY_CANCEL cancel {};
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
     * Routes into handleResolveCallback() after casting pQueryContext to ResolveContext.
     * @param Status        DNS status code (ERROR_SUCCESS on success).
     * @param pQueryContext Pointer to a heap-allocated ResolveContext.
     * @param pInstance     Resolved service instance. Must be freed with DnsServiceFreeInstance.
     */
    static VOID WINAPI resolveCallback (DWORD Status, PVOID pQueryContext, PDNS_SERVICE_INSTANCE pInstance);

    /**
     * Fired by DnsQueryEx for A (IPv4) record queries.
     * Routes into handleAddressQueryCallback() after casting pQueryContext to AddressQueryContext.
     * @param pQueryContext Pointer to a heap-allocated AddressQueryContext.
     * @param pQueryResults Query results; pQueryResults->pQueryRecords is the DNS_RECORD chain.
     */
    static VOID WINAPI aQueryCallback (PVOID pQueryContext, PDNS_QUERY_RESULT pQueryResults);

    /**
     * Fired by DnsQueryEx for AAAA (IPv6) record queries.
     * Routes into handleAddressQueryCallback() after casting pQueryContext to AddressQueryContext.
     * @param pQueryContext Pointer to a heap-allocated AddressQueryContext.
     * @param pQueryResults Query results; pQueryResults->pQueryRecords is the DNS_RECORD chain.
     */
    static VOID WINAPI aaaaQueryCallback (PVOID pQueryContext, PDNS_QUERY_RESULT pQueryResults);

    // -- Instance methods --

    /**
     * Handles a DnsServiceResolve callback: updates resolve state and failure count, then processes the result.
     * Takes mLock.
     */
    void handleResolveCallback (const std::string& instanceName, uint64_t resolveId, DWORD status, PDNS_SERVICE_INSTANCE pInstance);

    /**
     * Handles a DnsQueryEx A or AAAA callback. Takes mLock.
     * @param isIpv6 true for the AAAA query, false for the A query.
     */
    void handleAddressQueryCallback (const std::string& instanceName, PDNS_QUERY_RESULT pQueryResults, bool isIpv6);

    /**
     * Registers that a WinDNS callback is expected (resolve or address query). Call before issuing the request.
     */
    void callbackExpected();

    /**
     * Registers that an expected callback has arrived, or that the request failed synchronously and none will come.
     * When called from a callback this must be the last access to this object: the destructor may complete after it.
     */
    void callbackFinished();

    /**
     * Issues DnsServiceResolve for the given instance name.
     * Stores the cancel handle in mServices[instanceName].resolveCancel and sets resolveInFlight on success.
     * Must be called with mLock held.
     * @param instanceName Fully-qualified instance name (e.g. "MyDevice._http._tcp.local").
     */
    void issueResolve (const std::string& instanceName);

    /**
     * Cancels the service's in-flight queries, fires onServiceRemovedCallback and erases it from mServices.
     * Must be called with mLock held.
     * @return The iterator following the erased element.
     */
    std::map<std::string, WindnsDiscoveredService>::iterator removeService (std::map<std::string, WindnsDiscoveredService>::iterator it);

    /**
     * Liveness tick: cancels resolves that have been in flight for kLivenessInterval and counts them as failures,
     * removes services with kMaxResolveFailures failures in a row or whose PTR TTL has expired, and issues a resolve
     * for every remaining service without one in flight. Must be called with mLock held.
     */
    void checkLiveness (std::chrono::steady_clock::time_point now);

    /**
     * TXT poll tick: issues a resolve for every service without one in flight. Must be called with mLock held.
     */
    void pollTxtRecords();

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

    /**
     * Background thread body. Runs checkLiveness every kLivenessInterval and, when mTxtPollIntervalMs is non-zero,
     * pollTxtRecords every mTxtPollIntervalMs. Wakes early when the TXT interval changes or mStopPollThread is set.
     */
    void pollLoop();
};

} // namespace dnssd
