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
 *   1. DnsServiceBrowse   — PTR records fire onServiceDiscovered / onServiceRemoved; SRV, TXT, A and AAAA records in
 *                           the same result are applied to the matching services
 *   2. DnsServiceResolve  — resolves host, port, TXT, and (if included) one IPv4 and one IPv6 address;
 *                           fires onServiceResolved and onAddressAdded
 *   3. DnsQueryEx (A/AAAA) — queries all addresses of the host target; fires onAddressAdded / onAddressRemoved
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
     * onServiceResolved if the host target, port or TXT record has changed.
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
    std::atomic<bool> mBrowseCancelRequested { false }; // wakes pollLoop to cancel failed browses

    /// The active browse per service type, keyed by normalised query name. Guarded by mLock.
    std::map<std::wstring, std::shared_ptr<WindnsBrowseRequest>> mBrowses;

    /// Failed browses, removed from mBrowses and waiting to be cancelled by pollLoop. Guarded by mLock.
    std::vector<std::shared_ptr<WindnsBrowseRequest>> mFailedBrowses;

    /// All currently known service instances, keyed by instance name in ASCII lowercase without trailing dots.
    /// The name as received from browse is kept in ServiceDescription::fullname.
    std::map<std::string, WindnsDiscoveredService> mServices;

    /// Guards mServices and mShuttingDown.
    std::recursive_mutex mLock;

    /// Set by the destructor; browse results arriving after that are ignored. Guarded by mLock.
    bool mShuttingDown = false;

    /// Synchronises the destructor with callbacks that are still to come: the final ERROR_CANCELLED browseCallback per
    /// browse, and one callback per issued resolve and address query. Guarded by mCancelMutex.
    std::mutex mCancelMutex;
    std::condition_variable mCancelCv;
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
     * Fired by DnsServiceBrowse for each set of results, and once more with ERROR_CANCELLED after the browse is
     * cancelled.
     * @param Status        DNS status code (ERROR_SUCCESS on success).
     * @param pQueryContext Heap-allocated std::shared_ptr<WindnsBrowseRequest>.
     * @param pDnsRecord    Chain of DNS_RECORD results. Freed by this callback.
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
     * On an error status the browse is moved from mBrowses to mFailedBrowses, so that browseFor accepts its service
     * type again.
     */
    void handleBrowseResults (
        const std::shared_ptr<WindnsBrowseRequest>& request,
        DWORD status,
        PDNS_RECORD pDnsRecord,
        PendingCancels& pending);

    /**
     * Cancels a browse that is no longer in mBrowses. If no final ERROR_CANCELLED callback will come, releases the
     * callback context and its callbackExpected() registration.
     * Must not be called with mLock held, nor from a callback of the same browse.
     */
    void cancelBrowse (const std::shared_ptr<WindnsBrowseRequest>& request);

    /**
     * Cancels every browse in mFailedBrowses.
     * Must not be called with mLock held.
     */
    void cancelFailedBrowses();

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
     * Registers that a WinDNS callback is expected: the final callback of a browse, or the callback of a resolve or
     * address query. Call before issuing the request.
     */
    void callbackExpected();

    /**
     * Registers that an expected callback has arrived, or that the request failed synchronously and none will come.
     * When called from a callback this must be the last access to this object: the destructor may complete after it.
     */
    void callbackFinished();

    /**
     * Issues DnsServiceResolve for the service and stores the request in the service's `resolve`.
     * Must be called with mLock held.
     * @param serviceKey Key of the service in mServices.
     */
    void issueResolve (const std::string& serviceKey);

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
     * @param serviceKey Key of the service in mServices.
     * @param hostName   Host to query (e.g. "MyDevice.local").
     */
    void issueAddressQueries (const std::string& serviceKey, const std::string& hostName);

    /**
     * Issues one DnsQueryEx (A or AAAA) for the service, unless that query is already in flight.
     * Must be called with mLock held.
     */
    void issueAddressQuery (
        WindnsDiscoveredService& service,
        const std::string& serviceKey,
        const std::wstring& hostName,
        DWORD queryOptions,
        bool isIpv6);

    /**
     * Applies the SRV, TXT, A and AAAA records of a browse result to the services they belong to. SRV and TXT records
     * are matched on instance name, A and AAAA records on the host target of each service.
     * Must be called with mLock held.
     */
    void applyBrowseServiceRecords (PDNS_RECORD pDnsRecord);

    /**
     * Applies a host target, port and/or TXT record to a service. Once host target and port are both known, fires
     * onServiceResolvedCallback the first time and whenever one of the three changes. Issues A/AAAA address queries
     * when the host target changes, and otherwise at most once every kLivenessInterval.
     * Must be called with mLock held.
     * @param serviceKey     Key of the service in mServices.
     * @param hostTarget     New host target, or nullptr to leave it unchanged.
     * @param port           New port, or nullptr to leave it unchanged.
     * @param txtRecord      New TXT record, or nullptr to leave it unchanged.
     * @param interfaceIndex Interface index passed to onServiceResolvedCallback.
     */
    void updateService (
        const std::string& serviceKey,
        const std::string* hostTarget,
        const uint16_t* port,
        const TxtRecord* txtRecord,
        uint32_t interfaceIndex);

    /**
     * Processes a resolved DNS_SERVICE_INSTANCE: applies its host target, port and TXT record through updateService
     * and adds its IPv4 and IPv6 address.
     * Must be called with mLock held.
     * @param serviceKey Key of the service in mServices.
     * @param pInstance  Resolved instance data. Caller is responsible for calling DnsServiceFreeInstance.
     */
    void onResolveResult (const std::string& serviceKey, PDNS_SERVICE_INSTANCE pInstance);

    /**
     * Processes a chain of A or AAAA DNS_RECORD results through applyAddressRecord.
     * Must be called with mLock held.
     * @param serviceKey Key of the service in mServices.
     * @param records    Chain of DNS_RECORD results (DNS_TYPE_A or DNS_TYPE_AAAA).
     */
    void onAddressResult (const std::string& serviceKey, PDNS_RECORD records);

    /**
     * Adds the address of an A or AAAA record to the service under interface index 0 and fires onAddressAddedCallback
     * if it is new. A zero-TTL record removes the address and fires onAddressRemovedCallback. Other record types are
     * ignored.
     * Must be called with mLock held.
     */
    void applyAddressRecord (const std::string& serviceKey, const DNS_RECORD& record);

    /**
     * Adds an address to the service and fires onAddressAddedCallback if it is new.
     * Must be called with mLock held.
     */
    void addAddress (const std::string& serviceKey, uint32_t interfaceIndex, const std::string& address);

    /**
     * Reports an error via onBrowseErrorCallback if result.hasError().
     * @return true if there was an error, false otherwise.
     */
    bool reportIfError (const Result& result) const noexcept;

    /**
     * Background thread body: runs the liveness check every kLivenessInterval, re-resolves services every
     * mTxtPollIntervalMs (when non-zero) and cancels failed browses, until mStopPollThread is set.
     */
    void pollLoop();
};

} // namespace dnssd
