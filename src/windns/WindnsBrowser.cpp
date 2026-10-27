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

/**
 * Returns the key under which a service instance is stored: the instance name in ASCII lowercase, without trailing
 * dots. DNS names compare case-insensitively, and a trailing dot only marks a name as fully qualified.
 *
 * @param instanceName  Instance name as received from DnsServiceBrowse (e.g. "My Device._http._tcp.local").
 */
std::string makeServiceKey (const std::string& instanceName)
{
    std::string key = instanceName;
    while (!key.empty() && key.back() == '.')
        key.pop_back();
    for (char& c : key)
    {
        if (c >= 'A' && c <= 'Z')
            c = static_cast<char> (c - 'A' + 'a');
    }
    return key;
}

/**
 * Parses the strings of a TXT record into key/value pairs. A string without '=' is a key with an empty value. Empty
 * strings are skipped, and when a key appears more than once the first occurrence is kept.
 */
dnssd::TxtRecord parseTxtStrings (const DNS_TXT_DATAW& txt)
{
    dnssd::TxtRecord txtRecord;
    for (DWORD i = 0; i < txt.dwStringCount; ++i)
    {
        if (txt.pStringArray[i] == nullptr)
            continue;

        std::string entry;
        if (dnssd::toNarrowString (txt.pStringArray[i], entry).hasError() || entry.empty())
            continue;

        const auto separator = entry.find ('=');
        if (separator == std::string::npos)
            txtRecord.emplace (entry, std::string());
        else
            txtRecord.emplace (entry.substr (0, separator), entry.substr (separator + 1));
    }
    return txtRecord;
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
                       || mTxtPollIntervalChanged.load (std::memory_order_acquire)
                       || mBrowseCancelRequested.load (std::memory_order_acquire);
            });
        }

        if (mStopPollThread.load (std::memory_order_acquire))
            break;

        if (mBrowseCancelRequested.exchange (false, std::memory_order_acq_rel))
            cancelFailedBrowses();

        const auto now = Clock::now();

        if (mTxtPollIntervalChanged.exchange (false, std::memory_order_acq_rel))
        {
            nextTxtPoll = now + std::chrono::milliseconds (mTxtPollIntervalMs.load (std::memory_order_acquire));
            continue;
        }

        const bool livenessDue = now >= nextLiveness;
        const bool txtPollDue = txtIntervalMs > 0 && now >= nextTxtPoll;

        if (!livenessDue && !txtPollDue)
            continue;

        if (livenessDue)
        {
            PendingCancels pending;
            {
                std::lock_guard<std::recursive_mutex> lg (mLock);
                checkLiveness (now, pending);
            }
            runCancels (pending);
        }

        if (txtPollDue)
            nextTxtPoll = now + std::chrono::milliseconds (txtIntervalMs);

        {
            std::lock_guard<std::recursive_mutex> lg (mLock);
            resolveIdleServices();
        }

        // Scheduled after the resolves are issued, so that each of them has been in flight for at least
        // kLivenessInterval when the next liveness check runs.
        if (livenessDue)
            nextLiveness = Clock::now() + kLivenessInterval;
    }
}

void WindnsBrowser::checkLiveness (std::chrono::steady_clock::time_point now, PendingCancels& pending)
{
    for (auto it = mServices.begin(); it != mServices.end();)
    {
        WindnsDiscoveredService& service = it->second;

        // A service that is gone does not answer, and DnsServiceResolve then never calls back.
        if (service.resolve != nullptr && now - service.resolveStartedAt >= kLivenessInterval)
        {
            pending.resolves.push_back (std::move (service.resolve));
            service.resolve.reset();
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
            it = removeService (it, pending);
            continue;
        }

        ++it;
    }
}

void WindnsBrowser::resolveIdleServices()
{
    for (auto& entry : mServices)
    {
        if (entry.second.resolve == nullptr)
            issueResolve (entry.first);
    }
}

std::map<std::string, WindnsDiscoveredService>::iterator WindnsBrowser::removeService (
    std::map<std::string, WindnsDiscoveredService>::iterator it,
    PendingCancels& pending)
{
    WindnsDiscoveredService& service = it->second;

    // Cancelled after mLock is released. Their callbacks then find the service gone and only clean up.
    if (service.resolve != nullptr)
        pending.resolves.push_back (std::move (service.resolve));
    if (service.aQuery != nullptr)
        pending.addressQueries.push_back (std::move (service.aQuery));
    if (service.aaaaQuery != nullptr)
        pending.addressQueries.push_back (std::move (service.aaaaQuery));

    DNSSD_LOG_DEBUG ("- removeService: removed " << service.description.fullname << std::endl)

    if (onServiceRemovedCallback)
        onServiceRemovedCallback (service.description);

    return mServices.erase (it);
}

void WindnsBrowser::runCancels (PendingCancels& pending)
{
    for (auto& request : pending.resolves)
    {
        DWORD res = DnsServiceResolveCancel (&request->cancel);
        if (res != ERROR_SUCCESS && res != ERROR_CANCELLED)
            DNSSD_LOG_DEBUG ("- runCancels: DnsServiceResolveCancel failed for " << request->serviceKey << ": "
                             << Result (static_cast<DNS_STATUS> (res)).description() << std::endl)
    }

    for (auto& query : pending.addressQueries)
    {
        DWORD res = DnsCancelQuery (&query->cancel);
        if (res != ERROR_SUCCESS && res != ERROR_CANCELLED)
            DNSSD_LOG_DEBUG ("- runCancels: DnsCancelQuery (" << (query->isIpv6 ? "AAAA" : "A") << ") failed for "
                             << query->serviceKey << ": "
                             << Result (static_cast<DNS_STATUS> (res)).description() << std::endl)
    }

    pending.resolves.clear();
    pending.addressQueries.clear();
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

    // Take everything out under mLock, then cancel without it.
    PendingCancels pending;
    std::vector<std::shared_ptr<WindnsBrowseRequest>> browses;
    {
        std::lock_guard<std::recursive_mutex> lg (mLock);
        mShuttingDown = true;

        for (auto& entry : mServices)
        {
            WindnsDiscoveredService& service = entry.second;
            if (service.resolve != nullptr)
                pending.resolves.push_back (std::move (service.resolve));
            if (service.aQuery != nullptr)
                pending.addressQueries.push_back (std::move (service.aQuery));
            if (service.aaaaQuery != nullptr)
                pending.addressQueries.push_back (std::move (service.aaaaQuery));
        }
        mServices.clear();

        for (auto& entry : mBrowses)
            browses.push_back (std::move (entry.second));
        mBrowses.clear();

        browses.insert (browses.end(), mFailedBrowses.begin(), mFailedBrowses.end());
        mFailedBrowses.clear();
    }

    // Cancelled resolves and address queries still call back (ERROR_CANCELLED);
    // mOutstandingCallbacks counts them, and we wait for them below.
    runCancels (pending);

    // A cancelled browse calls back once more with ERROR_CANCELLED; mOutstandingCallbacks counts that callback too.
    for (auto& browse : browses)
        cancelBrowse (browse);
    browses.clear();

    std::unique_lock<std::mutex> lk (mCancelMutex);
    bool completed = mCancelCv.wait_for (lk, kWindnsCallbackTimeout, [this]() { return mOutstandingCallbacks == 0; });
    if (!completed)
        DNSSD_LOG_DEBUG ("WindnsBrowser::~WindnsBrowser: timed out waiting for " << mOutstandingCallbacks
                         << " callbacks" << std::endl)
}

void WindnsBrowser::cancelBrowse (const std::shared_ptr<WindnsBrowseRequest>& request)
{
    DWORD res = DnsServiceBrowseCancel (&request->cancel);
    if (res == ERROR_SUCCESS)
        return; // the final ERROR_CANCELLED callback releases the context

    DNSSD_LOG_DEBUG ("WindnsBrowser::cancelBrowse: DnsServiceBrowseCancel for " << request->serviceType << " returned "
                     << Result (static_cast<DNS_STATUS> (res)).description() << ", no final callback expected"
                     << std::endl)

    delete request->context;
    request->context = nullptr;
    callbackFinished();
}

void WindnsBrowser::cancelFailedBrowses()
{
    std::vector<std::shared_ptr<WindnsBrowseRequest>> failed;
    {
        std::lock_guard<std::recursive_mutex> lg (mLock);
        failed.swap (mFailedBrowses);
    }

    for (auto& request : failed)
        cancelBrowse (request);
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

    if (mBrowses.count (queryName) > 0)
        return Result ("already browsing for service \"" + serviceType + "\"");

    auto request = std::make_shared<WindnsBrowseRequest>();
    request->owner = this;
    request->serviceType = serviceType;
    request->queryName = queryName;
    request->context = new std::shared_ptr<WindnsBrowseRequest> (request);

    DNS_SERVICE_BROWSE_REQUEST req {};
    req.Version = DNS_QUERY_REQUEST_VERSION1;
    req.InterfaceIndex = 0; // all interfaces
    req.QueryName = request->queryName.c_str();
    req.pBrowseCallback = &WindnsBrowser::browseCallback;
    req.pQueryContext = request->context;

    // Set before the call: a callback can arrive before DnsServiceBrowse returns.
    mBrowses.emplace (queryName, request);
    callbackExpected();

    DWORD status = DnsServiceBrowse (&req, &request->cancel);

    if (status != DNS_REQUEST_PENDING && status != ERROR_SUCCESS)
    {
        mBrowses.erase (queryName);
        delete request->context;
        request->context = nullptr;
        callbackFinished();
        return Result (static_cast<DNS_STATUS> (status));
    }

    if (!mPollThread.joinable()) {
        mPollThread = std::thread (&WindnsBrowser::pollLoop, this);
    }

    return {};
}

VOID WINAPI WindnsBrowser::browseCallback (DWORD Status, PVOID pQueryContext, PDNS_RECORD pDnsRecord)
{
    auto* holder = static_cast<std::shared_ptr<WindnsBrowseRequest>*> (pQueryContext);

    // Cancelling the browse request calls this callback one more time for cleanup.
    if (static_cast<DNS_STATUS> (Status) == ERROR_CANCELLED)
    {
        if (pDnsRecord != nullptr)
            DnsRecordListFree (pDnsRecord, DnsFreeRecordList);

        std::shared_ptr<WindnsBrowseRequest> request = std::move (*holder);
        delete holder;
        auto* self = request->owner;
        request.reset();
        self->callbackFinished(); // last access to self
        return;
    }

    std::shared_ptr<WindnsBrowseRequest> request = *holder;
    auto* self = request->owner;

    PendingCancels pending;
    self->handleBrowseResults (request, Status, pDnsRecord, pending);

    if (pDnsRecord != nullptr)
        DnsRecordListFree (pDnsRecord, DnsFreeRecordList);

    self->runCancels (pending); // after mLock is released
}

void WindnsBrowser::handleBrowseResults (
    const std::shared_ptr<WindnsBrowseRequest>& request,
    DWORD status,
    PDNS_RECORD pDnsRecord,
    PendingCancels& pending)
{
    std::lock_guard<std::recursive_mutex> lg (mLock);

    if (mShuttingDown)
        return;

    DNSSD_LOG_DEBUG ("> browseCallback enter" << std::endl)

    const auto now = std::chrono::steady_clock::now();

    if (status != ERROR_SUCCESS)
    {
        reportIfError (Result ("Browsing for " + request->serviceType + " failed: "
                               + Result (static_cast<DNS_STATUS> (status)).description()));

        auto it = mBrowses.find (request->queryName);
        if (it != mBrowses.end() && it->second == request)
        {
            mBrowses.erase (it);
            mFailedBrowses.push_back (request);
            {
                std::lock_guard<std::mutex> lk (mPollMutex);
                mBrowseCancelRequested.store (true, std::memory_order_release);
            }
            mPollCv.notify_one();
        }
        return;
    }

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

        const std::string serviceKey = makeServiceKey (instanceName);

        if (record->dwTtl == 0)
        {
            // Goodbye packet — the service is being removed
            auto it = mServices.find (serviceKey);
            if (it == mServices.end())
            {
                DNSSD_LOG_DEBUG ("- browseCallback: goodbye for unknown instance " << instanceName << ", ignored" << std::endl)
                continue;
            }

            DNSSD_LOG_DEBUG ("- browseCallback: goodbye for " << instanceName << std::endl)
            removeService (it, pending);
        }
        else
        {
            auto it = mServices.find (serviceKey);

            if (it == mServices.end())
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

                it = mServices.emplace (serviceKey, std::move (service)).first;

                DNSSD_LOG_DEBUG ("- browseCallback: discovered " << instanceName << std::endl)

                if (onServiceDiscoveredCallback)
                    onServiceDiscoveredCallback (it->second.description);

                issueResolve (serviceKey);
            }
            else
            {
                // Subsequent sighting — re-resolve to pick up TXT record updates.
                // Skip if a resolve is already in flight.
                it->second.ttl = record->dwTtl;
                it->second.lastSeen = now;

                if (it->second.resolve == nullptr)
                    issueResolve (serviceKey);
            }
        }
    }

    applyBrowseServiceRecords (pDnsRecord);

    DNSSD_LOG_DEBUG ("< browseCallback exit" << std::endl)
}

void WindnsBrowser::applyBrowseServiceRecords (PDNS_RECORD pDnsRecord)
{
    // SRV records first, so that A and AAAA records in the same result can be matched on the host target.
    for (PDNS_RECORD record = pDnsRecord; record != nullptr; record = record->pNext)
    {
        if ((record->wType != DNS_TYPE_SRV && record->wType != DNS_TYPE_TEXT) || record->pName == nullptr
            || record->dwTtl == 0)
            continue;

        std::string instanceName;
        if (toNarrowString (record->pName, instanceName).hasError())
        {
            DNSSD_LOG_DEBUG ("- applyBrowseServiceRecords: failed to convert record name" << std::endl)
            continue;
        }

        const std::string serviceKey = makeServiceKey (instanceName);
        if (mServices.find (serviceKey) == mServices.end())
            continue;

        if (record->wType == DNS_TYPE_SRV)
        {
            std::string hostTarget;
            if (record->Data.SRV.pNameTarget == nullptr
                || toNarrowString (record->Data.SRV.pNameTarget, hostTarget).hasError())
            {
                DNSSD_LOG_DEBUG ("- applyBrowseServiceRecords: failed to read SRV target of " << instanceName << std::endl)
                continue;
            }

            const uint16_t port = record->Data.SRV.wPort;
            DNSSD_LOG_DEBUG ("- applyBrowseServiceRecords: SRV " << instanceName << " host=" << hostTarget
                             << " port=" << port << std::endl)
            updateService (serviceKey, &hostTarget, &port, nullptr, 0);
        }
        else
        {
            const TxtRecord txtRecord = parseTxtStrings (record->Data.TXT);
            DNSSD_LOG_DEBUG ("- applyBrowseServiceRecords: TXT " << instanceName << " (" << txtRecord.size()
                             << " entries)" << std::endl)
            updateService (serviceKey, nullptr, nullptr, &txtRecord, 0);
        }
    }

    for (PDNS_RECORD record = pDnsRecord; record != nullptr; record = record->pNext)
    {
        if ((record->wType != DNS_TYPE_A && record->wType != DNS_TYPE_AAAA) || record->pName == nullptr)
            continue;

        std::string hostName;
        if (toNarrowString (record->pName, hostName).hasError())
        {
            DNSSD_LOG_DEBUG ("- applyBrowseServiceRecords: failed to convert record name" << std::endl)
            continue;
        }

        const std::string hostKey = makeServiceKey (hostName);
        for (auto& entry : mServices)
        {
            const std::string& hostTarget = entry.second.description.hostTarget;
            if (!hostTarget.empty() && makeServiceKey (hostTarget) == hostKey)
                applyAddressRecord (entry.first, *record);
        }
    }
}

void WindnsBrowser::updateService (
    const std::string& serviceKey,
    const std::string* hostTarget,
    const uint16_t* port,
    const TxtRecord* txtRecord,
    uint32_t interfaceIndex)
{
    auto it = mServices.find (serviceKey);
    if (it == mServices.end())
        return;

    WindnsDiscoveredService& service = it->second;
    ServiceDescription& desc = service.description;

    const bool hostTargetChanged = hostTarget != nullptr && makeServiceKey (*hostTarget) != makeServiceKey (desc.hostTarget);
    const bool portChanged = port != nullptr && *port != desc.port;
    const bool txtRecordChanged = txtRecord != nullptr && *txtRecord != desc.txtRecord;

    if (hostTargetChanged)
        desc.hostTarget = *hostTarget;
    if (portChanged)
        desc.port = *port;
    if (txtRecordChanged)
        desc.txtRecord = *txtRecord;

    if (!desc.hostTarget.empty() && desc.port != 0
        && (!service.resolved || hostTargetChanged || portChanged || txtRecordChanged))
    {
        service.resolved = true;
        if (onServiceResolvedCallback)
            onServiceResolvedCallback (desc, interfaceIndex);
    }

    if (desc.hostTarget.empty())
        return;

    const auto now = std::chrono::steady_clock::now();
    const bool neverQueried = service.lastAddressQueryAt == std::chrono::steady_clock::time_point();
    if (hostTargetChanged || neverQueried || now - service.lastAddressQueryAt >= kLivenessInterval)
    {
        service.lastAddressQueryAt = now;
        issueAddressQueries (serviceKey, desc.hostTarget);
    }
}

VOID WINAPI WindnsBrowser::resolveCallback (DWORD Status, PVOID pQueryContext, PDNS_SERVICE_INSTANCE pInstance)
{
    std::shared_ptr<WindnsResolveRequest> request;
    {
        auto* holder = static_cast<std::shared_ptr<WindnsResolveRequest>*> (pQueryContext);
        request = std::move (*holder);
        delete holder;
    }
    auto* self = request->owner;

    self->handleResolveCallback (request, Status, pInstance);
    request.reset();
    self->callbackFinished(); // last access to self
}

void WindnsBrowser::handleResolveCallback (
    const std::shared_ptr<WindnsResolveRequest>& request,
    DWORD status,
    PDNS_SERVICE_INSTANCE pInstance)
{
    std::lock_guard<std::recursive_mutex> lg (mLock);

    const std::string& serviceKey = request->serviceKey;
    DNSSD_LOG_DEBUG ("> resolveCallback enter: " << serviceKey << std::endl)

    auto it = mServices.find (serviceKey);
    if (it == mServices.end() || it->second.resolve != request)
    {
        DNSSD_LOG_DEBUG ("- resolveCallback: service removed or resolve superseded, discarding result" << std::endl)
        if (pInstance != nullptr)
            DnsServiceFreeInstance (pInstance);
        return;
    }

    WindnsDiscoveredService& service = it->second;
    service.resolve.reset();

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
        DNSSD_LOG_DEBUG ("- resolveCallback: resolve failed for " << serviceKey << " ("
                         << service.consecutiveResolveFailures << " in a row)" << std::endl)
        reportIfError (Result ("Resolving " + service.description.fullname + " failed: "
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

    onResolveResult (serviceKey, pInstance);
    DnsServiceFreeInstance (pInstance);

    DNSSD_LOG_DEBUG ("< resolveCallback exit: " << serviceKey << std::endl)
}

VOID WINAPI WindnsBrowser::addressQueryCallback (PVOID pQueryContext, PDNS_QUERY_RESULT pQueryResults)
{
    std::shared_ptr<WindnsAddressQuery> query;
    {
        auto* holder = static_cast<std::shared_ptr<WindnsAddressQuery>*> (pQueryContext);
        query = std::move (*holder);
        delete holder;
    }
    auto* self = query->owner;

    self->handleAddressQueryCallback (query, pQueryResults);
    query.reset(); // pQueryResults points into the query
    self->callbackFinished(); // last access to self
}

void WindnsBrowser::handleAddressQueryCallback (const std::shared_ptr<WindnsAddressQuery>& query, PDNS_QUERY_RESULT pQueryResults)
{
    std::lock_guard<std::recursive_mutex> lg (mLock);

    const std::string& serviceKey = query->serviceKey;
    const char* queryType = query->isIpv6 ? "AAAA" : "A";
    DNSSD_LOG_DEBUG ("> addressQueryCallback (" << queryType << ") enter: " << serviceKey << std::endl)

    // Current only if the service still exists and this is its in-flight query (not cancelled by removeService).
    bool current = false;
    auto it = mServices.find (serviceKey);
    if (it != mServices.end())
    {
        std::shared_ptr<WindnsAddressQuery>& slot = query->isIpv6 ? it->second.aaaaQuery : it->second.aQuery;
        if (slot == query)
        {
            slot.reset();
            current = true;
        }
    }

    if (pQueryResults == nullptr)
        return;

    if (pQueryResults->QueryStatus != ERROR_SUCCESS)
    {
        if (current && static_cast<DNS_STATUS> (pQueryResults->QueryStatus) != ERROR_CANCELLED)
            reportIfError (Result (std::string (queryType) + " query for " + it->second.description.fullname + " failed: "
                                   + Result (static_cast<DNS_STATUS> (pQueryResults->QueryStatus)).description()));
        if (pQueryResults->pQueryRecords != nullptr)
            DnsRecordListFree (pQueryResults->pQueryRecords, DnsFreeRecordList);
        return;
    }

    if (!current)
    {
        DNSSD_LOG_DEBUG ("- addressQueryCallback: service already removed, discarding" << std::endl)
        DnsRecordListFree (pQueryResults->pQueryRecords, DnsFreeRecordList);
        return;
    }

    onAddressResult (serviceKey, pQueryResults->pQueryRecords);
    DnsRecordListFree (pQueryResults->pQueryRecords, DnsFreeRecordList);

    DNSSD_LOG_DEBUG ("< addressQueryCallback (" << queryType << ") exit: " << serviceKey << std::endl)
}

void WindnsBrowser::issueResolve (const std::string& serviceKey)
{
    auto it = mServices.find (serviceKey);
    if (it == mServices.end())
        return;

    WindnsDiscoveredService& service = it->second;
    const std::string& instanceName = service.description.fullname;

    std::wstring instanceNameW;
    auto r = toWideString (instanceName, instanceNameW);
    if (r.hasError())
    {
        reportIfError (Result ("Resolving " + instanceName + " failed: " + r.description()));
        return;
    }

    auto request = std::make_shared<WindnsResolveRequest>();
    request->owner = this;
    request->serviceKey = serviceKey;
    auto* holder = new std::shared_ptr<WindnsResolveRequest> (request); // callback context, deleted in the callback

    DNS_SERVICE_RESOLVE_REQUEST req {};
    req.Version = DNS_QUERY_REQUEST_VERSION1;
    req.InterfaceIndex = 0;
    req.QueryName = const_cast<PWSTR> (instanceNameW.c_str());
    req.pResolveCompletionCallback = &WindnsBrowser::resolveCallback;
    req.pQueryContext = holder;

    // Set before the call: if the callback runs synchronously on this thread (mLock is recursive), it must see this
    // resolve as the current, in-flight one.
    service.resolve = request;
    service.resolveStartedAt = std::chrono::steady_clock::now();
    callbackExpected();

    DWORD status = DnsServiceResolve (&req, &request->cancel);

    if (status != DNS_REQUEST_PENDING && status != ERROR_SUCCESS)
    {
        delete holder;
        callbackFinished();
        if (service.resolve == request)
            service.resolve.reset();
        ++service.consecutiveResolveFailures;
        reportIfError (Result ("Resolving " + instanceName + " failed: "
                               + Result (static_cast<DNS_STATUS> (status)).description()));
    }
}

void WindnsBrowser::issueAddressQueries (const std::string& serviceKey, const std::string& hostName)
{
    auto it = mServices.find (serviceKey);
    if (it == mServices.end())
        return;

    WindnsDiscoveredService& service = it->second;

    std::wstring hostNameW;
    auto r = toWideString (hostName, hostNameW);
    if (r.hasError())
    {
        reportIfError (Result ("Address query for " + service.description.fullname + " (host " + hostName + ") failed: "
                               + r.description()));
        return;
    }

    // .local hostnames must be resolved via multicast DNS; standard unicast DNS has no record of them.
    const DWORD queryOptions = (hostName.size() >= 6 && hostName.compare (hostName.size() - 6, 6, ".local") == 0)
                                   ? DNS_QUERY_MULTICAST_ONLY
                                   : DNS_QUERY_STANDARD;

    issueAddressQuery (service, serviceKey, hostNameW, queryOptions, false); // A record (IPv4)
    issueAddressQuery (service, serviceKey, hostNameW, queryOptions, true); // AAAA record (IPv6)
}

void WindnsBrowser::issueAddressQuery (
    WindnsDiscoveredService& service,
    const std::string& serviceKey,
    const std::wstring& hostName,
    DWORD queryOptions,
    bool isIpv6)
{
    std::shared_ptr<WindnsAddressQuery>& slot = isIpv6 ? service.aaaaQuery : service.aQuery;
    if (slot != nullptr)
        return; // already in flight

    auto query = std::make_shared<WindnsAddressQuery>();
    query->owner = this;
    query->serviceKey = serviceKey;
    query->isIpv6 = isIpv6;
    query->result.Version = DNS_QUERY_REQUEST_VERSION1;
    auto* holder = new std::shared_ptr<WindnsAddressQuery> (query); // callback context, deleted in the callback

    DNS_QUERY_REQUEST req {};
    req.Version = DNS_QUERY_REQUEST_VERSION1;
    req.QueryName = hostName.c_str();
    req.QueryType = isIpv6 ? DNS_TYPE_AAAA : DNS_TYPE_A;
    req.QueryOptions = queryOptions;
    req.InterfaceIndex = 0;
    req.pQueryCompletionCallback = &WindnsBrowser::addressQueryCallback;
    req.pQueryContext = holder;

    // Set before the call, in case the callback runs synchronously on this thread.
    slot = query;
    callbackExpected();

    DWORD status = DnsQueryEx (&req, &query->result, &query->cancel);

    if (status == DNS_REQUEST_PENDING)
        return;

    // Completed synchronously or failed: no callback will come.
    delete holder;
    callbackFinished();
    if (slot == query)
        slot.reset();

    if (status == ERROR_SUCCESS)
    {
        onAddressResult (serviceKey, query->result.pQueryRecords);
        DnsRecordListFree (query->result.pQueryRecords, DnsFreeRecordList);
    }
    else
    {
        reportIfError (Result (std::string (isIpv6 ? "AAAA" : "A") + " query for " + service.description.fullname + " failed: "
                               + Result (static_cast<DNS_STATUS> (status)).description()));
    }
}

void WindnsBrowser::onResolveResult (const std::string& serviceKey, PDNS_SERVICE_INSTANCE pInstance)
{
    auto it = mServices.find (serviceKey);
    if (it == mServices.end())
        return;

    std::string hostTarget;
    const std::string* newHostTarget = nullptr;
    if (pInstance->pszHostName != nullptr)
    {
        auto r = toNarrowString (pInstance->pszHostName, hostTarget);
        if (r.hasError())
        {
            reportIfError (Result ("Reading the host name of " + it->second.description.fullname + " failed: "
                                   + r.description()));
            return;
        }
        newHostTarget = &hostTarget;
    }

    const uint16_t port = pInstance->wPort;
    const uint32_t ifIndex = pInstance->dwInterfaceIndex;

    TxtRecord txtRecord;
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

        txtRecord.emplace (key, value);
    }

    DNSSD_LOG_DEBUG ("- onResolveResult: " << serviceKey << " host=" << hostTarget << " port=" << port << std::endl)

    updateService (serviceKey, newHostTarget, &port, &txtRecord, ifIndex);

    if (pInstance->ip4Address != nullptr)
    {
        char buf[INET_ADDRSTRLEN];
        if (inet_ntop (AF_INET, pInstance->ip4Address, buf, sizeof (buf)) != nullptr)
            addAddress (serviceKey, ifIndex, buf);
    }

    if (pInstance->ip6Address != nullptr)
    {
        char buf[INET6_ADDRSTRLEN];
        if (inet_ntop (AF_INET6, pInstance->ip6Address, buf, sizeof (buf)) != nullptr)
            addAddress (serviceKey, ifIndex, buf);
    }
}

void WindnsBrowser::onAddressResult (const std::string& serviceKey, PDNS_RECORD records)
{
    for (PDNS_RECORD record = records; record != nullptr; record = record->pNext)
        applyAddressRecord (serviceKey, *record);
}

void WindnsBrowser::applyAddressRecord (const std::string& serviceKey, const DNS_RECORD& record)
{
    auto it = mServices.find (serviceKey);
    if (it == mServices.end())
        return;

    std::string address;

    if (record.wType == DNS_TYPE_A)
    {
        char buf[INET_ADDRSTRLEN];
        DWORD ipAddr = record.Data.A.IpAddress;
        if (inet_ntop (AF_INET, &ipAddr, buf, sizeof (buf)) == nullptr)
            return;
        address = buf;
    }
    else if (record.wType == DNS_TYPE_AAAA)
    {
        char buf[INET6_ADDRSTRLEN];
        if (inet_ntop (AF_INET6, &record.Data.AAAA.Ip6Address, buf, sizeof (buf)) == nullptr)
            return;
        address = buf;
    }
    else
    {
        return;
    }

    const uint32_t ifIndex = 0;

    if (record.dwTtl != 0)
    {
        addAddress (serviceKey, ifIndex, address);
        return;
    }

    ServiceDescription& desc = it->second.description;
    auto ifIt = desc.interfaces.find (ifIndex);
    if (ifIt != desc.interfaces.end() && ifIt->second.erase (address) > 0)
    {
        if (ifIt->second.empty())
            desc.interfaces.erase (ifIt);

        DNSSD_LOG_DEBUG ("- applyAddressRecord: removed " << address << " for " << serviceKey << std::endl)

        if (onAddressRemovedCallback)
            onAddressRemovedCallback (desc, address, ifIndex);
    }
}

void WindnsBrowser::addAddress (const std::string& serviceKey, uint32_t interfaceIndex, const std::string& address)
{
    auto it = mServices.find (serviceKey);
    if (it == mServices.end())
        return;

    ServiceDescription& desc = it->second.description;
    if (!desc.interfaces[interfaceIndex].insert (address).second)
        return;

    DNSSD_LOG_DEBUG ("- addAddress: added " << address << " for " << serviceKey << " on interface " << interfaceIndex
                     << std::endl)

    if (onAddressAddedCallback)
        onAddressAddedCallback (desc, address, interfaceIndex);
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
