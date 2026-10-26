#include "dnssd/windns/WindnsBrowser.h"
#include "dnssd/windns/WindnsUtil.h"

namespace
{

/**
 * Splits a fully-qualified service instance name into its components.
 *
 * Expects the form "<name>.<type>.<domain>" where <type> has exactly two DNS labels
 * (e.g. "_http._tcp") and <domain> is "local". Works backwards from ".local" so that
 * service names containing "._" are handled correctly.
 *
 * @param instanceName  Instance name as received from DnsServiceBrowse (e.g. "My Device._http._tcp.local").
 * @param name          Receives the service instance name (e.g. "My Device").
 * @param type          Receives the service type with trailing dot (e.g. "_http._tcp.").
 * @param domain        Receives the domain with trailing dot (e.g. "local.").
 * @return true on success, false if the name cannot be parsed.
 */
bool parseInstanceName (
    const std::string& instanceName,
    std::string& name,
    std::string& type,
    std::string& domain)
{
    const std::string localSuffix = ".local";
    const auto localPos = instanceName.rfind (localSuffix);
    if (localPos == std::string::npos || localPos == 0)
    {
        DNSSD_LOG_DEBUG ("instance name does not end in .local: " << instanceName << std::endl);
        return false;
    }

    // Everything before ".local": "<name>._type._proto"
    const std::string nameAndType = instanceName.substr (0, localPos);

    // Find the 2nd dot from the right — that is where the name ends and the type begins.
    // Using rfind twice handles service names that themselves contain "._".
    auto dotPos = nameAndType.rfind ('.');
    if (dotPos == std::string::npos || dotPos == 0)
        return false;
    dotPos = nameAndType.rfind ('.', dotPos - 1);
    if (dotPos == std::string::npos)
        return false;

    name = nameAndType.substr (0, dotPos);
    type = nameAndType.substr (dotPos + 1) + "."; // e.g. "_http._tcp."
    domain = "local.";
    return true;
}

} // namespace

namespace dnssd
{

void WindnsBrowser::setTxtPollIntervalMs (uint32_t intervalMs)
{
    mTxtPollIntervalMs.store (intervalMs, std::memory_order_release);
    {
        std::lock_guard<std::mutex> lk (mPollMutex);
        mTxtPollIntervalChanged.store (true, std::memory_order_release);
    }
    mPollCv.notify_one();
}

void WindnsBrowser::pollLoop()
{
    using Clock = std::chrono::steady_clock;

    auto nextLiveness = Clock::now() + kLivenessInterval;
    auto nextTxtPoll = Clock::now() + std::chrono::milliseconds (mTxtPollIntervalMs.load (std::memory_order_acquire));

    while (true)
    {
        const uint32_t txtIntervalMs = mTxtPollIntervalMs.load (std::memory_order_acquire);
        const auto wakeAt = (txtIntervalMs > 0 && nextTxtPoll < nextLiveness) ? nextTxtPoll : nextLiveness;

        {
            std::unique_lock<std::mutex> lk (mPollMutex);
            mPollCv.wait_until (lk, wakeAt, [this]() {
                return mStopPollThread.load (std::memory_order_acquire)
                       || mTxtPollIntervalChanged.load (std::memory_order_acquire);
            });
        }

        if (mStopPollThread.load (std::memory_order_acquire))
            break;

        const auto now = Clock::now();

        if (mTxtPollIntervalChanged.exchange (false, std::memory_order_acq_rel))
        {
            nextTxtPoll = now + std::chrono::milliseconds (mTxtPollIntervalMs.load (std::memory_order_acquire));
            continue;
        }

        std::lock_guard<std::recursive_mutex> lg (mLock);

        if (now >= nextLiveness)
        {
            checkLiveness (now);
            nextLiveness = now + kLivenessInterval;
        }

        if (txtIntervalMs > 0 && now >= nextTxtPoll)
        {
            pollTxtRecords();
            nextTxtPoll = now + std::chrono::milliseconds (txtIntervalMs);
        }
    }
}

void WindnsBrowser::checkLiveness (std::chrono::steady_clock::time_point now)
{
    for (auto it = mServices.begin(); it != mServices.end();)
    {
        WindnsDiscoveredService& service = it->second;

        // A service that is gone does not answer, and DnsServiceResolve then never calls back.
        if (service.resolveInFlight && now - service.resolveStartedAt >= kLivenessInterval)
        {
            DWORD res = DnsServiceResolveCancel (&service.resolveCancel);
            if (res != ERROR_SUCCESS && res != ERROR_CANCELLED)
                DNSSD_LOG_DEBUG ("- checkLiveness: DnsServiceResolveCancel failed for " << it->first << ": "
                                 << Result (static_cast<DNS_STATUS> (res)).description() << std::endl)

            service.resolveInFlight = false;
            ++service.consecutiveResolveFailures;
            DNSSD_LOG_DEBUG ("- checkLiveness: resolve timed out for " << it->first << " ("
                             << service.consecutiveResolveFailures << " in a row)" << std::endl)
        }

        const bool tooManyFailures = service.consecutiveResolveFailures >= kMaxResolveFailures;
        const bool ttlExpired = service.ttl > 0 && now - service.lastSeen > std::chrono::seconds (service.ttl);

        if (tooManyFailures || ttlExpired)
        {
            DNSSD_LOG_DEBUG ("- checkLiveness: pruning " << it->first << ": "
                             << (tooManyFailures ? "too many resolve failures" : "not seen within PTR TTL") << std::endl)
            it = removeService (it);
            continue;
        }

        if (!service.resolveInFlight)
            issueResolve (it->first);

        ++it;
    }
}

void WindnsBrowser::pollTxtRecords()
{
    for (auto& entry : mServices)
    {
        if (!entry.second.resolveInFlight)
            issueResolve (entry.first);
    }
}

std::map<std::string, WindnsDiscoveredService>::iterator WindnsBrowser::removeService (
    std::map<std::string, WindnsDiscoveredService>::iterator it)
{
    WindnsDiscoveredService& service = it->second;

    // Cancelled requests still call back; those callbacks find the service gone and only clean up.
    if (service.resolveInFlight)
        DnsServiceResolveCancel (&service.resolveCancel);
    if (service.aQueryInFlight && service.aCancel != nullptr)
        DnsCancelQuery (service.aCancel);
    if (service.aaaaQueryInFlight && service.aaaaCancel != nullptr)
        DnsCancelQuery (service.aaaaCancel);

    DNSSD_LOG_DEBUG ("- removeService: removed " << service.description.fullname << std::endl)

    if (onServiceRemovedCallback)
        onServiceRemovedCallback (service.description);

    return mServices.erase (it);
}

void WindnsBrowser::callbackExpected()
{
    std::lock_guard<std::mutex> lk (mCancelMutex);
    ++mOutstandingCallbacks;
}

void WindnsBrowser::callbackFinished()
{
    std::lock_guard<std::mutex> lk (mCancelMutex);
    --mOutstandingCallbacks;
    mCancelCv.notify_all();
}

WindnsBrowser::~WindnsBrowser()
{
    {
        std::lock_guard<std::mutex> lk (mPollMutex);
        mStopPollThread.store (true, std::memory_order_release);
    }
    mPollCv.notify_one();
    if (mPollThread.joinable())
        mPollThread.join();

    {
        std::lock_guard<std::recursive_mutex> lg (mLock);
        mShuttingDown = true;

        // Cancel resolve and address queries. Cancelled requests still call back (ERROR_CANCELLED);
        // mOutstandingCallbacks counts them, and we wait for them below.
        for (auto& entry : mServices)
        {
            WindnsDiscoveredService& service = entry.second;
            if (service.resolveInFlight)
            {
                DWORD res = DnsServiceResolveCancel (&service.resolveCancel);
                if (res != ERROR_SUCCESS && res != ERROR_CANCELLED)
                    DNSSD_LOG_DEBUG ("WindnsBrowser::~WindnsBrowser: DnsServiceResolveCancel failed: "
                                     << Result (static_cast<DNS_STATUS> (res)).description() << std::endl)
            }
            if (service.aQueryInFlight && service.aCancel != nullptr)
            {
                DWORD res = DnsCancelQuery (service.aCancel);
                if (res != ERROR_SUCCESS && res != ERROR_CANCELLED)
                    DNSSD_LOG_DEBUG ("WindnsBrowser::~WindnsBrowser: DnsCancelQuery (A) failed: "
                                     << Result (static_cast<DNS_STATUS> (res)).description() << std::endl)
            }
            if (service.aaaaQueryInFlight && service.aaaaCancel != nullptr)
            {
                DWORD res = DnsCancelQuery (service.aaaaCancel);
                if (res != ERROR_SUCCESS && res != ERROR_CANCELLED)
                    DNSSD_LOG_DEBUG ("WindnsBrowser::~WindnsBrowser: DnsCancelQuery (AAAA) failed: "
                                     << Result (static_cast<DNS_STATUS> (res)).description() << std::endl)
            }
        }
        mServices.clear();

        // DnsServiceBrowseCancel results in one final browseCallback with ERROR_CANCELLED per browse,
        // which we also wait for below.
        {
            std::lock_guard<std::mutex> lk (mCancelMutex);
            mPendingBrowseCancels = static_cast<int> (mBrowseCancels.size());
        }
        for (auto& entry : mBrowseCancels)
        {
            DWORD res = DnsServiceBrowseCancel (&entry.second);
            if (res != ERROR_SUCCESS && res != ERROR_CANCELLED)
                DNSSD_LOG_DEBUG ("WindnsBrowser::~WindnsBrowser: DnsServiceBrowseCancel failed: "
                                 << Result (static_cast<DNS_STATUS> (res)).description() << std::endl)
        }
        mBrowseCancels.clear();
    }

    std::unique_lock<std::mutex> lk (mCancelMutex);
    bool completed = mCancelCv.wait_for (lk, kWindnsCallbackTimeout, [this]() {
        return mPendingBrowseCancels == 0 && mOutstandingCallbacks == 0;
    });
    if (!completed)
        DNSSD_LOG_DEBUG ("WindnsBrowser::~WindnsBrowser: timed out waiting for callbacks (browse cancels: "
                         << mPendingBrowseCancels << ", resolve/address queries: " << mOutstandingCallbacks << ")"
                         << std::endl)
}

Result WindnsBrowser::browseFor (const std::string& serviceType)
{
    std::wstring queryName;
    auto r = toWideString (serviceType, queryName);
    if (r.hasError())
        return r;

    // Normalize to the form "_type._proto.local" expected by DnsServiceBrowse:
    // strip any trailing dots, then append .local if not already present.
    while (!queryName.empty() && queryName.back() == L'.')
        queryName.pop_back();

    if (queryName.rfind (L".local") == std::wstring::npos)
        queryName += L".local";

    std::lock_guard<std::recursive_mutex> lg (mLock);

    if (mBrowseCancels.count (queryName) > 0)
        return Result ("already browsing for service \"" + serviceType + "\"");


    DNS_SERVICE_BROWSE_REQUEST req {};
    req.Version = DNS_QUERY_REQUEST_VERSION1;
    req.InterfaceIndex = 0; // all interfaces
    req.QueryName = queryName.c_str();
    req.pBrowseCallback = &WindnsBrowser::browseCallback;
    req.pQueryContext = this;

    auto& it = mBrowseCancels.emplace (queryName, DNS_SERVICE_CANCEL {}).first;

    DWORD status = DnsServiceBrowse (&req, &it->second);

    if (status != DNS_REQUEST_PENDING && status != ERROR_SUCCESS)
    {
        mBrowseCancels.erase (it);
        return Result (static_cast<DNS_STATUS> (status));
    }

    if (!mPollThread.joinable()) {
        mPollThread = std::thread (&WindnsBrowser::pollLoop, this);
    }

    return {};
}

VOID WINAPI WindnsBrowser::browseCallback (DWORD Status, PVOID pQueryContext, PDNS_RECORD pDnsRecord)
{
    auto* self = static_cast<WindnsBrowser*> (pQueryContext);

    // Cancelling the browse request calls this callback one more time for cleanup.
    if (static_cast<DNS_STATUS> (Status) == ERROR_CANCELLED)
    {
        std::lock_guard<std::mutex> lk (self->mCancelMutex);
        --self->mPendingBrowseCancels;
        self->mCancelCv.notify_all();
        return;
    }

    std::lock_guard<std::recursive_mutex> lg (self->mLock);

    if (self->mShuttingDown)
        return;

    DNSSD_LOG_DEBUG ("> browseCallback enter" << std::endl)

    const auto now = std::chrono::steady_clock::now();

    if (self->reportIfError (Result (static_cast<DNS_STATUS> (Status))))
        return;

    for (PDNS_RECORD record = pDnsRecord; record != nullptr; record = record->pNext)
    {
        if (record->wType != DNS_TYPE_PTR)
            continue;

        if (record->Data.PTR.pNameHost == nullptr)
        {
            DNSSD_LOG_DEBUG ("- browseCallback: host name string was nullptr" << std::endl);
            continue;
        }

        std::string instanceName;
        if (toNarrowString (record->Data.PTR.pNameHost, instanceName).hasError())
        {
            DNSSD_LOG_DEBUG ("- browseCallback: failed to convert instance name" << std::endl);
            continue;
        }

        if (record->dwTtl == 0)
        {
            // Goodbye packet — the service is being removed
            auto it = self->mServices.find (instanceName);
            if (it == self->mServices.end())
                continue;

            DNSSD_LOG_DEBUG ("- browseCallback: goodbye for " << instanceName << std::endl)
            self->removeService (it);
        }
        else
        {
            auto it = self->mServices.find (instanceName);

            if (it == self->mServices.end())
            {
                // First sighting — parse the instance name and create a new entry
                std::string name, type, domain;
                if (!parseInstanceName (instanceName, name, type, domain))
                {
                    DNSSD_LOG_DEBUG ("- browseCallback: failed to parse instance name, skipping" << std::endl)
                    continue;
                }

                WindnsDiscoveredService service;
                service.ttl = record->dwTtl;
                service.lastSeen = now;
                service.description.fullname = instanceName;
                service.description.name = name;
                service.description.type = type;
                service.description.domain = domain;

                it = self->mServices.emplace (instanceName, std::move (service)).first;

                DNSSD_LOG_DEBUG ("- browseCallback: discovered " << instanceName << std::endl)

                if (self->onServiceDiscoveredCallback)
                    self->onServiceDiscoveredCallback (it->second.description);

                self->issueResolve (instanceName);
            }
            else
            {
                // Subsequent sighting — re-resolve to pick up TXT record updates.
                // Skip if a resolve is already in flight.
                it->second.ttl = record->dwTtl;
                it->second.lastSeen = now;

                if (!it->second.resolveInFlight)
                    self->issueResolve (instanceName);
            }
        }
    }

    DNSSD_LOG_DEBUG ("< browseCallback exit" << std::endl)
}

VOID WINAPI WindnsBrowser::resolveCallback (DWORD Status, PVOID pQueryContext, PDNS_SERVICE_INSTANCE pInstance)
{
    auto* ctx = static_cast<ResolveContext*> (pQueryContext);
    auto* self = ctx->owner;
    const std::string instanceName = ctx->instanceName;
    const uint64_t resolveId = ctx->resolveId;
    delete ctx;

    self->handleResolveCallback (instanceName, resolveId, Status, pInstance);
    self->callbackFinished(); // last access to self
}

void WindnsBrowser::handleResolveCallback (
    const std::string& instanceName,
    uint64_t resolveId,
    DWORD status,
    PDNS_SERVICE_INSTANCE pInstance)
{
    std::lock_guard<std::recursive_mutex> lg (mLock);

    DNSSD_LOG_DEBUG ("> resolveCallback enter: " << instanceName << std::endl)

    auto it = mServices.find (instanceName);
    if (it == mServices.end() || it->second.currentResolveId != resolveId)
    {
        DNSSD_LOG_DEBUG ("- resolveCallback: service removed or resolve superseded, discarding result" << std::endl)
        if (pInstance != nullptr)
            DnsServiceFreeInstance (pInstance);
        return;
    }

    WindnsDiscoveredService& service = it->second;
    service.resolveInFlight = false;

    // Cancelled by checkLiveness (already counted as a failure there) or by removeService.
    if (static_cast<DNS_STATUS> (status) == ERROR_CANCELLED)
    {
        if (pInstance != nullptr)
            DnsServiceFreeInstance (pInstance);
        return;
    }

    if (status != ERROR_SUCCESS)
    {
        ++service.consecutiveResolveFailures;
        DNSSD_LOG_DEBUG ("- resolveCallback: resolve failed for " << instanceName << " ("
                         << service.consecutiveResolveFailures << " in a row)" << std::endl)
        reportIfError (Result ("Resolving " + instanceName + " failed: "
                               + Result (static_cast<DNS_STATUS> (status)).description()));
        if (pInstance != nullptr)
            DnsServiceFreeInstance (pInstance);
        return;
    }

    if (pInstance == nullptr)
    {
        DNSSD_LOG_DEBUG ("- resolveCallback: pInstance is null" << std::endl)
        return;
    }

    service.consecutiveResolveFailures = 0;
    service.lastSeen = std::chrono::steady_clock::now();

    onResolveResult (instanceName, pInstance);
    DnsServiceFreeInstance (pInstance);

    DNSSD_LOG_DEBUG ("< resolveCallback exit: " << instanceName << std::endl)
}

VOID WINAPI WindnsBrowser::aQueryCallback (PVOID pQueryContext, PDNS_QUERY_RESULT pQueryResults)
{
    auto* ctx = static_cast<AddressQueryContext*> (pQueryContext);
    auto* self = ctx->owner;

    self->handleAddressQueryCallback (ctx->instanceName, pQueryResults, false);
    delete ctx; // pQueryResults points into ctx
    self->callbackFinished(); // last access to self
}

VOID WINAPI WindnsBrowser::aaaaQueryCallback (PVOID pQueryContext, PDNS_QUERY_RESULT pQueryResults)
{
    auto* ctx = static_cast<AddressQueryContext*> (pQueryContext);
    auto* self = ctx->owner;

    self->handleAddressQueryCallback (ctx->instanceName, pQueryResults, true);
    delete ctx; // pQueryResults points into ctx
    self->callbackFinished(); // last access to self
}

void WindnsBrowser::handleAddressQueryCallback (const std::string& instanceName, PDNS_QUERY_RESULT pQueryResults, bool isIpv6)
{
    std::lock_guard<std::recursive_mutex> lg (mLock);

    const char* queryType = isIpv6 ? "AAAA" : "A";
    DNSSD_LOG_DEBUG ("> addressQueryCallback (" << queryType << ") enter: " << instanceName << std::endl)

    auto it = mServices.find (instanceName);
    if (it != mServices.end())
    {
        if (isIpv6)
        {
            it->second.aaaaQueryInFlight = false;
            it->second.aaaaCancel = nullptr;
        }
        else
        {
            it->second.aQueryInFlight = false;
            it->second.aCancel = nullptr;
        }
    }

    if (pQueryResults == nullptr)
        return;

    if (pQueryResults->QueryStatus != ERROR_SUCCESS)
    {
        if (it != mServices.end() && static_cast<DNS_STATUS> (pQueryResults->QueryStatus) != ERROR_CANCELLED)
            reportIfError (Result (std::string (queryType) + " query for " + instanceName + " failed: "
                                   + Result (static_cast<DNS_STATUS> (pQueryResults->QueryStatus)).description()));
        if (pQueryResults->pQueryRecords != nullptr)
            DnsRecordListFree (pQueryResults->pQueryRecords, DnsFreeRecordList);
        return;
    }

    if (it == mServices.end())
    {
        DNSSD_LOG_DEBUG ("- addressQueryCallback: service already removed, discarding" << std::endl)
        DnsRecordListFree (pQueryResults->pQueryRecords, DnsFreeRecordList);
        return;
    }

    onAddressResult (instanceName, pQueryResults->pQueryRecords);
    DnsRecordListFree (pQueryResults->pQueryRecords, DnsFreeRecordList);

    DNSSD_LOG_DEBUG ("< addressQueryCallback (" << queryType << ") exit: " << instanceName << std::endl)
}

void WindnsBrowser::issueResolve (const std::string& instanceName)
{
    auto it = mServices.find (instanceName);
    if (it == mServices.end())
        return;

    std::wstring instanceNameW;
    auto r = toWideString (instanceName, instanceNameW);
    if (reportIfError (r))
        return;

    WindnsDiscoveredService& service = it->second;
    const uint64_t resolveId = ++mNextResolveId;
    auto* ctx = new ResolveContext { this, instanceName, resolveId };

    DNS_SERVICE_RESOLVE_REQUEST req {};
    req.Version = DNS_QUERY_REQUEST_VERSION1;
    req.InterfaceIndex = 0;
    req.QueryName = const_cast<PWSTR> (instanceNameW.c_str());
    req.pResolveCompletionCallback = &WindnsBrowser::resolveCallback;
    req.pQueryContext = ctx;

    // Set before the call: if the callback runs synchronously on this thread (mLock is recursive), it must see this
    // resolve as current and in flight.
    service.currentResolveId = resolveId;
    service.resolveStartedAt = std::chrono::steady_clock::now();
    service.resolveInFlight = true;
    callbackExpected();

    DWORD status = DnsServiceResolve (&req, &service.resolveCancel);

    if (status != DNS_REQUEST_PENDING && status != ERROR_SUCCESS)
    {
        delete ctx;
        callbackFinished();
        service.resolveInFlight = false;
        ++service.consecutiveResolveFailures;
        reportIfError (Result ("Resolving " + instanceName + " failed: "
                               + Result (static_cast<DNS_STATUS> (status)).description()));
    }
}

void WindnsBrowser::issueAddressQueries (const std::string& instanceName, const std::string& hostName)
{
    auto it = mServices.find (instanceName);
    if (it == mServices.end())
        return;

    WindnsDiscoveredService& service = it->second;

    std::wstring hostNameW;
    auto r = toWideString (hostName, hostNameW);
    if (reportIfError (r))
        return;

    // .local hostnames must be resolved via multicast DNS; standard unicast DNS has no record of them.
    const DWORD queryOptions = (hostName.size() >= 6 && hostName.compare (hostName.size() - 6, 6, ".local") == 0)
                                   ? DNS_QUERY_MULTICAST_ONLY
                                   : DNS_QUERY_STANDARD;

    // A record (IPv4) query
    if (!service.aQueryInFlight)
    {
        auto* ctx = new AddressQueryContext { this, instanceName };
        ctx->queryResult.Version = DNS_QUERY_REQUEST_VERSION1;

        DNS_QUERY_REQUEST req {};
        req.Version = DNS_QUERY_REQUEST_VERSION1;
        req.QueryName = hostNameW.c_str();
        req.QueryType = DNS_TYPE_A;
        req.QueryOptions = queryOptions;
        req.InterfaceIndex = 0;
        req.pQueryCompletionCallback = &WindnsBrowser::aQueryCallback;
        req.pQueryContext = ctx;

        // Set before the call, in case the callback runs synchronously on this thread.
        service.aQueryInFlight = true;
        service.aCancel = &ctx->cancel;
        callbackExpected();

        DWORD status = DnsQueryEx (&req, &ctx->queryResult, &ctx->cancel);

        if (status != DNS_REQUEST_PENDING)
        {
            // Completed synchronously or failed: no callback will come.
            service.aQueryInFlight = false;
            service.aCancel = nullptr;
            callbackFinished();

            if (status == ERROR_SUCCESS)
            {
                onAddressResult (instanceName, ctx->queryResult.pQueryRecords);
                DnsRecordListFree (ctx->queryResult.pQueryRecords, DnsFreeRecordList);
            }
            else
            {
                reportIfError (Result ("A query for " + instanceName + " failed: "
                                       + Result (static_cast<DNS_STATUS> (status)).description()));
            }
            delete ctx;
        }
    }

    // AAAA record (IPv6) query
    if (!service.aaaaQueryInFlight)
    {
        auto* ctx = new AddressQueryContext { this, instanceName };
        ctx->queryResult.Version = DNS_QUERY_REQUEST_VERSION1;

        DNS_QUERY_REQUEST req {};
        req.Version = DNS_QUERY_REQUEST_VERSION1;
        req.QueryName = hostNameW.c_str();
        req.QueryType = DNS_TYPE_AAAA;
        req.QueryOptions = queryOptions;
        req.InterfaceIndex = 0;
        req.pQueryCompletionCallback = &WindnsBrowser::aaaaQueryCallback;
        req.pQueryContext = ctx;

        // Set before the call, in case the callback runs synchronously on this thread.
        service.aaaaQueryInFlight = true;
        service.aaaaCancel = &ctx->cancel;
        callbackExpected();

        DWORD status = DnsQueryEx (&req, &ctx->queryResult, &ctx->cancel);

        if (status != DNS_REQUEST_PENDING)
        {
            // Completed synchronously or failed: no callback will come.
            service.aaaaQueryInFlight = false;
            service.aaaaCancel = nullptr;
            callbackFinished();

            if (status == ERROR_SUCCESS)
            {
                onAddressResult (instanceName, ctx->queryResult.pQueryRecords);
                DnsRecordListFree (ctx->queryResult.pQueryRecords, DnsFreeRecordList);
            }
            else
            {
                reportIfError (Result ("AAAA query for " + instanceName + " failed: "
                                       + Result (static_cast<DNS_STATUS> (status)).description()));
            }
            delete ctx;
        }
    }
}

void WindnsBrowser::onResolveResult (const std::string& instanceName, PDNS_SERVICE_INSTANCE pInstance)
{
    auto it = mServices.find (instanceName);
    if (it == mServices.end())
        return;

    ServiceDescription& desc = it->second.description;

    if (pInstance->pszHostName != nullptr)
    {
        auto r = toNarrowString (pInstance->pszHostName, desc.hostTarget);
        if (reportIfError (r))
            return;
    }

    desc.port = pInstance->wPort;

    desc.txtRecord.clear();
    for (DWORD i = 0; i < pInstance->dwPropertyCount; ++i)
    {
        if (pInstance->keys == nullptr || pInstance->keys[i] == nullptr)
            continue;

        std::string key, value;
        auto rKey = toNarrowString (pInstance->keys[i], key);
        if (rKey.hasError())
        {
            DNSSD_LOG_DEBUG ("- onResolveResult: failed to convert TXT key at index " << i << std::endl)
            continue;
        }

        if (pInstance->values != nullptr && pInstance->values[i] != nullptr)
        {
            auto rVal = toNarrowString (pInstance->values[i], value);
            if (rVal.hasError())
            {
                DNSSD_LOG_DEBUG ("- onResolveResult: failed to convert TXT value for key \"" << key << "\"" << std::endl)
                continue;
            }
        }

        desc.txtRecord[key] = value;
    }

    DNSSD_LOG_DEBUG ("- onResolveResult: " << instanceName << " host=" << desc.hostTarget << " port=" << desc.port << std::endl)

    if (onServiceResolvedCallback)
        onServiceResolvedCallback (desc, pInstance->dwInterfaceIndex);

    // Bonjour includes A/AAAA records as additional records in the mDNS SRV response, which
    // DnsServiceResolve populates into ip4Address/ip6Address. Use them directly to avoid a
    // separate DnsQueryEx round-trip, which does not reliably resolve .local names via mDNS.
    bool hasAddresses = false;
    const uint32_t ifIndex = pInstance->dwInterfaceIndex;

    if (pInstance->ip4Address != nullptr)
    {
        char buf[INET_ADDRSTRLEN];
        if (inet_ntop (AF_INET, pInstance->ip4Address, buf, sizeof (buf)) != nullptr)
        {
            std::string address = buf;
            if (desc.interfaces[ifIndex].insert (address).second)
            {
                DNSSD_LOG_DEBUG ("- onResolveResult: added IPv4 " << address << " for " << instanceName << std::endl)
                if (onAddressAddedCallback)
                    onAddressAddedCallback (desc, address, ifIndex);
            }
            hasAddresses = true;
        }
    }

    if (pInstance->ip6Address != nullptr)
    {
        char buf[INET6_ADDRSTRLEN];
        if (inet_ntop (AF_INET6, pInstance->ip6Address, buf, sizeof (buf)) != nullptr)
        {
            std::string address = buf;
            if (desc.interfaces[ifIndex].insert (address).second)
            {
                DNSSD_LOG_DEBUG ("- onResolveResult: added IPv6 " << address << " for " << instanceName << std::endl)
                if (onAddressAddedCallback)
                    onAddressAddedCallback (desc, address, ifIndex);
            }
            hasAddresses = true;
        }
    }

    if (!hasAddresses && !desc.hostTarget.empty())
        issueAddressQueries (instanceName, desc.hostTarget);
}

void WindnsBrowser::onAddressResult (const std::string& instanceName, PDNS_RECORD records)
{
    auto it = mServices.find (instanceName);
    if (it == mServices.end())
        return;

    ServiceDescription& desc = it->second.description;
    const uint32_t ifIndex = 0;

    for (PDNS_RECORD record = records; record != nullptr; record = record->pNext)
    {
        std::string address;

        if (record->wType == DNS_TYPE_A)
        {
            char buf[INET_ADDRSTRLEN];
            DWORD ipAddr = record->Data.A.IpAddress;
            if (inet_ntop (AF_INET, &ipAddr, buf, sizeof (buf)) == nullptr)
                continue;
            address = buf;
        }
        else if (record->wType == DNS_TYPE_AAAA)
        {
            char buf[INET6_ADDRSTRLEN];
            if (inet_ntop (AF_INET6, &record->Data.AAAA.Ip6Address, buf, sizeof (buf)) == nullptr)
                continue;
            address = buf;
        }
        else
        {
            continue;
        }

        // Goodbye message for a specific interface
        if (record->dwTtl == 0)
        {
            auto ifIt = desc.interfaces.find (ifIndex);
            if (ifIt != desc.interfaces.end() && ifIt->second.erase (address) > 0)
            {
                if (ifIt->second.empty())
                    desc.interfaces.erase (ifIt);

                DNSSD_LOG_DEBUG ("- onAddressResult: removed " << address << " for " << instanceName << std::endl)

                if (onAddressRemovedCallback)
                    onAddressRemovedCallback (desc, address, ifIndex);
            }
        }
        else
        {
            bool inserted = desc.interfaces[ifIndex].insert (address).second;
            if (inserted)
            {
                DNSSD_LOG_DEBUG ("- onAddressResult: added " << address << " for " << instanceName << std::endl)

                if (onAddressAddedCallback)
                    onAddressAddedCallback (desc, address, ifIndex);
            }
        }
    }
}

bool WindnsBrowser::reportIfError (const Result& result) const noexcept
{
    if (result.hasError())
    {
        if (onBrowseErrorCallback)
            onBrowseErrorCallback (result);
        return true;
    }
    return false;
}

} // namespace dnssd
