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
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

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
 * Liveness: every known service is re-resolved every kLivenessInterval. A service is removed (onServiceRemoved fires)
 * after kMaxResolveFailures failed or unanswered resolves in a row, or when it has not been seen within its PTR TTL.
 *
 * All WinDNS callbacks arrive on thread-pool threads; mLock serialises access to mServices.
 */
class WindnsBrowser : public BrowserBase
{
public:
    explicit WindnsBrowser() = default;

    /**
    * Sets up the browser with a custom TXT polling interval. If the interval is 0, services are not re-resolved for
    * TXT updates; the liveness check keeps running.
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
     * Can be called at any time; the new interval takes effect immediately.
     *
     * @param intervalMs Poll interval in milliseconds. Pass 0 to disable TXT polling; the liveness check keeps running.
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

    /// Guards mServices and mShuttingDown.
    std::recursive_mutex mLock;

    /// Set by the destructor; browse results arriving after that are ignored. Guarded by mLock.
    bool mShuttingDown = false;

    /// Synchronises the destructor with callbacks that are still to come: the final ERROR_CANCELLED browseCallback per
    /// active browse, and one callback per issued resolve and address query. Both counters are guarded by mCancelMutex.
    std::mutex mCancelMutex;
    std::condition_variable mCancelCv;
    int mPendingBrowseCancels = 0;
    int mOutstandingCallbacks = 0;

    /**
     * Requests waiting to be cancelled by runCancels().
     */
    struct PendingCancels
    {
        std::vector<std::shared_ptr<WindnsResolveRequest>> resolves;
        std::vector<std::shared_ptr<WindnsAddressQuery>> addressQueries;
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
     * @param Status        DNS status code (ERROR_SUCCESS on success).
     * @param pQueryContext Heap-allocated std::shared_ptr<WindnsResolveRequest>.
     * @param pInstance     Resolved service instance. Must be freed with DnsServiceFreeInstance.
     */
    static VOID WINAPI resolveCallback (DWORD Status, PVOID pQueryContext, PDNS_SERVICE_INSTANCE pInstance);

    /**
     * Fired by DnsQueryEx for A (IPv4) and AAAA (IPv6) record queries.
     * @param pQueryContext Heap-allocated std::shared_ptr<WindnsAddressQuery>.
     * @param pQueryResults Query results (points into the WindnsAddressQuery); pQueryRecords is the DNS_RECORD chain.
     */
    static VOID WINAPI addressQueryCallback (PVOID pQueryContext, PDNS_QUERY_RESULT pQueryResults);

    // -- Instance methods --

    /**
     * Applies browse results: adds newly discovered services, refreshes known ones and removes services that sent a
     * goodbye. The in-flight requests of removed services are added to `pending`.
     */
    void handleBrowseResults (DWORD status, PDNS_RECORD pDnsRecord, PendingCancels& pending);

    /**
     * Applies the result of a DnsServiceResolve call to its service.
     */
    void handleResolveCallback (const std::shared_ptr<WindnsResolveRequest>& request, DWORD status, PDNS_SERVICE_INSTANCE pInstance);

    /**
     * Applies the result of a DnsQueryEx A or AAAA query to its service.
     */
    void handleAddressQueryCallback (const std::shared_ptr<WindnsAddressQuery>& query, PDNS_QUERY_RESULT pQueryResults);

    /**
     * Cancels every request in `pending`, then clears it.
     * Must not be called with mLock held.
     */
    void runCancels (PendingCancels& pending);

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
     * Issues DnsServiceResolve for the given instance name and stores the request in the service's `resolve`.
     * Must be called with mLock held.
     * @param instanceName Fully-qualified instance name (e.g. "MyDevice._http._tcp.local").
     */
    void issueResolve (const std::string& instanceName);

    /**
     * Removes a service: adds its in-flight requests to `pending`, fires onServiceRemovedCallback and erases it.
     * Must be called with mLock held.
     * @return The iterator following the erased element.
     */
    std::map<std::string, WindnsDiscoveredService>::iterator removeService (
        std::map<std::string, WindnsDiscoveredService>::iterator it,
        PendingCancels& pending);

    /**
     * Counts resolves that have been in flight for kLivenessInterval as failures and adds them to `pending`, then
     * removes services with kMaxResolveFailures failures in a row or an expired PTR TTL.
     * Must be called with mLock held.
     */
    void checkLiveness (std::chrono::steady_clock::time_point now, PendingCancels& pending);

    /**
     * Issues a resolve for every service without one in flight.
     * Must be called with mLock held.
     */
    void resolveIdleServices();

    /**
     * Issues DnsQueryEx for A and AAAA records for the given host name, unless that query is already in flight.
     * Must be called with mLock held.
     * @param instanceName Instance name used to look up the service on callback.
     * @param hostName     Host to query (e.g. "MyDevice.local").
     */
    void issueAddressQueries (const std::string& instanceName, const std::string& hostName);

    /**
     * Issues one DnsQueryEx (A or AAAA) for the service, unless that query is already in flight.
     * Must be called with mLock held.
     */
    void issueAddressQuery (
        WindnsDiscoveredService& service,
        const std::string& instanceName,
        const std::wstring& hostName,
        DWORD queryOptions,
        bool isIpv6);

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
     * Background thread body: runs the liveness check every kLivenessInterval and re-resolves services every
     * mTxtPollIntervalMs (when non-zero), until mStopPollThread is set.
     */
    void pollLoop();
};

} // namespace dnssd
